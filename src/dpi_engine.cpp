#include "dpi_engine.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>

namespace DPI {

// ============================================================================
// DPIEngine Implementation
// ============================================================================

DPIEngine::DPIEngine(const Config& config)
    : config_(config), output_queue_(10000) {
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    DPI ENGINE v1.0                            ║\n";
    std::cout << "║               Deep Packet Inspection System                   ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Configuration:                                                ║\n";
    std::cout << "║   Load Balancers:    " << std::setw(3) << config.num_load_balancers << "                                       ║\n";
    std::cout << "║   FPs per LB:        " << std::setw(3) << config.fps_per_lb << "                                       ║\n";
    std::cout << "║   Total FP threads:  " << std::setw(3) << (config.num_load_balancers * config.fps_per_lb) << "                                       ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

DPIEngine::~DPIEngine() {
    stop();
}

bool DPIEngine::initialize() {
    if (config_.num_load_balancers < 1 || config_.num_load_balancers > 64 ||
        config_.fps_per_lb < 1 || config_.fps_per_lb > 64 ||
        config_.num_load_balancers * config_.fps_per_lb > 256) {
        std::cerr << "[DPIEngine] Invalid worker configuration (limits: 1-64 per stage, 256 fast paths total)\n";
        return false;
    }

    // Create rule manager
    rule_manager_ = std::make_unique<RuleManager>();
    
    // Load rules if specified
    if (!config_.rules_file.empty()) {
        if (!rule_manager_->loadRules(config_.rules_file)) {
            std::cerr << "[DPIEngine] Could not load rules file: " << config_.rules_file << "\n";
            return false;
        }
    }
    
    // Create output callback
    auto output_cb = [this](const PacketJob& job, PacketAction action) {
        handleOutput(job, action);
    };
    
    // Create FP manager (creates FP threads and their queues)
    int total_fps = config_.num_load_balancers * config_.fps_per_lb;
    fp_manager_ = std::make_unique<FPManager>(total_fps, rule_manager_.get(), output_cb);
    
    // Create LB manager (creates LB threads, connects to FP queues)
    lb_manager_ = std::make_unique<LBManager>(
        config_.num_load_balancers,
        config_.fps_per_lb,
        fp_manager_->getQueuePtrs()
    );
    
    // Create global connection table
    global_conn_table_ = std::make_unique<GlobalConnectionTable>(total_fps);
    for (int i = 0; i < total_fps; i++) {
        global_conn_table_->registerTracker(i, &fp_manager_->getFP(i).getConnectionTracker());
    }
    
    std::cout << "[DPIEngine] Initialized successfully\n";
    return true;
}

void DPIEngine::start() {
    if (running_) return;
    
    running_ = true;
    processing_complete_ = false;
    
    // Start output thread
    output_thread_ = std::thread(&DPIEngine::outputThreadFunc, this);
    
    // Start FP threads
    fp_manager_->startAll();
    
    // Start LB threads
    lb_manager_->startAll();
    
    std::cout << "[DPIEngine] All threads started\n";
}

void DPIEngine::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // Stop LB threads first (they feed FPs)
    if (lb_manager_) {
        lb_manager_->stopAll();
    }
    
    // Stop FP threads
    if (fp_manager_) {
        fp_manager_->stopAll();
    }
    
    // Stop output thread
    output_queue_.shutdown();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    
    std::cout << "[DPIEngine] All threads stopped\n";
}

void DPIEngine::waitForCompletion() {
    // Wait for reader to finish
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    
    // Signal completion
    processing_complete_ = true;
}

bool DPIEngine::processFile(const std::string& input_file,
                            const std::string& output_file) {
    
    std::cout << "\n[DPIEngine] Processing: " << input_file << "\n";
    std::cout << "[DPIEngine] Output to:  " << output_file << "\n\n";
    
    // Initialize if not already done
    if (!rule_manager_) {
        if (!initialize()) {
            return false;
        }
    }

    std::error_code path_error;
    if (std::filesystem::equivalent(input_file, output_file, path_error) && !path_error) {
        std::cerr << "[DPIEngine] Error: Input and output refer to the same file\n";
        return false;
    }
    
    // Open output file
    output_file_.open(output_file, std::ios::binary);
    if (!output_file_.is_open()) {
        std::cerr << "[DPIEngine] Error: Cannot open output file\n";
        return false;
    }
    output_succeeded_ = true;
    
    // Start processing threads
    processing_succeeded_ = false;
    start();
    
    // Start reader thread
    reader_thread_ = std::thread(&DPIEngine::readerThreadFunc, this, input_file);
    
    // Wait for completion
    waitForCompletion();
    
    // Stop all threads
    stop();
    
    // Close output file
    if (output_file_.is_open()) {
        output_file_.flush();
        if (!output_file_.good()) output_succeeded_ = false;
        output_file_.close();
        if (output_file_.fail()) output_succeeded_ = false;
    }
    
    // Print final report
    std::cout << generateReport();
    std::cout << fp_manager_->generateClassificationReport();
    
    return processing_succeeded_ && output_succeeded_;
}

void DPIEngine::readerThreadFunc(const std::string& input_file) {
    PacketAnalyzer::PcapReader reader;
    
    if (!reader.open(input_file)) {
        std::cerr << "[Reader] Error: Cannot open input file\n";
        return;
    }

    if (reader.getGlobalHeader().network != 1) {
        std::cerr << "[Reader] Error: Only Ethernet PCAP captures are supported\n";
        reader.close();
        return;
    }
    
    // Write PCAP header to output
    if (!writeOutputHeader(reader.getGlobalHeader())) {
        std::cerr << "[Writer] Error: Cannot write output PCAP header\n";
        reader.close();
        return;
    }
    processing_succeeded_ = true;
    
    PacketAnalyzer::RawPacket raw;
    PacketAnalyzer::ParsedPacket parsed;
    uint64_t packet_id = 0;
    
    std::cout << "[Reader] Starting packet processing...\n";
    
    while (reader.readNextPacket(raw)) {
        const uint64_t current_packet_id = packet_id++;
        stats_.total_packets++;
        stats_.total_bytes += raw.data.size();

        // Parse the packet
        if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
            // Fail open for packets this parser cannot inspect.
            PacketJob passthrough{};
            passthrough.packet_id = current_packet_id;
            passthrough.original_length = raw.header.orig_len;
            passthrough.ts_sec = raw.header.ts_sec;
            passthrough.ts_usec = raw.header.ts_usec;
            passthrough.data = raw.data;
            stats_.other_packets++;
            stats_.forwarded_packets++;
            output_queue_.push(std::move(passthrough));
            continue;
        }
        
        // Only process IP packets with TCP/UDP
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
            // Preserve Ethernet traffic outside this engine's TCP/UDP scope.
            PacketJob passthrough{};
            passthrough.packet_id = current_packet_id;
            passthrough.original_length = raw.header.orig_len;
            passthrough.ts_sec = raw.header.ts_sec;
            passthrough.ts_usec = raw.header.ts_usec;
            passthrough.data = raw.data;
            stats_.other_packets++;
            stats_.forwarded_packets++;
            output_queue_.push(std::move(passthrough));
            continue;
        }
        
        // Create packet job
        PacketJob job = createPacketJob(raw, parsed, current_packet_id);
        
        if (parsed.has_tcp) {
            stats_.tcp_packets++;
        } else if (parsed.has_udp) {
            stats_.udp_packets++;
        }
        
        // Send to appropriate LB based on hash
        LoadBalancer& lb = lb_manager_->getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }

    if (reader.hasError()) {
        std::cerr << "[Reader] Error: Input PCAP is truncated or contains an invalid record\n";
        processing_succeeded_ = false;
    }
    
    std::cout << "[Reader] Finished reading " << packet_id << " packets\n";
    reader.close();
}

PacketJob DPIEngine::createPacketJob(const PacketAnalyzer::RawPacket& raw,
                                      const PacketAnalyzer::ParsedPacket& parsed,
                                      uint64_t packet_id) {
    PacketJob job;
    job.packet_id = packet_id;
    job.original_length = raw.header.orig_len;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    
    // Set five-tuple - parse IP addresses from string back to uint32
    auto parseIP = [](const std::string& ip) -> uint32_t {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (char c : ip) {
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    };
    
    job.tuple.src_ip = parseIP(parsed.src_ip);
    job.tuple.dst_ip = parseIP(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;
    
    // TCP flags
    job.tcp_flags = parsed.tcp_flags;
    job.tcp_sequence = parsed.seq_number;
    
    // Copy packet data
    job.data = raw.data;
    
    // Reuse validated offsets from the parser (including VLAN tags).
    job.eth_offset = 0;
    job.ip_offset = parsed.ip_header_offset;
    job.transport_offset = parsed.transport_header_offset;
    job.payload_offset = parsed.payload_offset;
    job.payload_length = parsed.payload_length;
    if (job.payload_offset <= job.data.size() && job.payload_length > 0) {
        job.payload_data = job.data.data() + job.payload_offset;
    }
    
    return job;
}

void DPIEngine::outputThreadFunc() {
    std::map<uint64_t, PacketJob> pending;
    uint64_t next_packet_id = 0;

    for (;;) {
        auto job_opt = output_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (job_opt) {
            auto inserted = pending.emplace(job_opt->packet_id, std::move(*job_opt));
            if (!inserted.second) {
                std::cerr << "[Writer] Error: Duplicate packet result ID\n";
                processing_succeeded_ = false;
            }

            auto next = pending.find(next_packet_id);
            while (next != pending.end()) {
                if (next->second.write_to_output) {
                    writeOutputPacket(next->second);
                }
                pending.erase(next);
                ++next_packet_id;
                next = pending.find(next_packet_id);
            }
        } else if (output_queue_.isShutdown()) {
            if (next_packet_id != stats_.total_packets.load() || !pending.empty()) {
                std::cerr << "[Writer] Error: Missing packet results while ordering output\n";
                processing_succeeded_ = false;
            }
            break;
        }
    }
}

void DPIEngine::handleOutput(const PacketJob& job, PacketAction action) {
    PacketJob result = job;
    if (action == PacketAction::DROP) {
        stats_.dropped_packets++;
        result.write_to_output = false;
    } else {
        stats_.forwarded_packets++;
        result.write_to_output = true;
    }
    output_queue_.push(std::move(result));
}

bool DPIEngine::writeOutputHeader(const PacketAnalyzer::PcapGlobalHeader& header) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) {
        output_succeeded_ = false;
        return false;
    }
    
    output_file_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!output_file_.good()) output_succeeded_ = false;
    return output_file_.good();
}

void DPIEngine::writeOutputPacket(const PacketJob& job) {
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    if (!output_file_.is_open()) {
        output_succeeded_ = false;
        return;
    }
    
    // Write packet header
    PacketAnalyzer::PcapPacketHeader pkt_header;
    pkt_header.ts_sec = job.ts_sec;
    pkt_header.ts_usec = job.ts_usec;
    pkt_header.incl_len = job.data.size();
    pkt_header.orig_len = job.original_length;
    
    output_file_.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
    output_file_.write(reinterpret_cast<const char*>(job.data.data()), job.data.size());
    if (!output_file_.good()) output_succeeded_ = false;
}

// ============================================================================
// Rule Management API
// ============================================================================

void DPIEngine::blockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->blockIP(ip);
    }
}

void DPIEngine::unblockIP(const std::string& ip) {
    if (rule_manager_) {
        rule_manager_->unblockIP(ip);
    }
}

void DPIEngine::blockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->blockApp(app);
    }
}

void DPIEngine::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            blockApp(static_cast<AppType>(i));
            return;
        }
    }
    std::cerr << "[DPIEngine] Unknown app: " << app_name << "\n";
}

void DPIEngine::unblockApp(AppType app) {
    if (rule_manager_) {
        rule_manager_->unblockApp(app);
    }
}

void DPIEngine::unblockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        if (appTypeToString(static_cast<AppType>(i)) == app_name) {
            unblockApp(static_cast<AppType>(i));
            return;
        }
    }
}

void DPIEngine::blockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->blockDomain(domain);
    }
}

void DPIEngine::unblockDomain(const std::string& domain) {
    if (rule_manager_) {
        rule_manager_->unblockDomain(domain);
    }
}

void DPIEngine::blockPort(uint16_t port) {
    if (rule_manager_) {
        rule_manager_->blockPort(port);
    }
}

bool DPIEngine::loadRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->loadRules(filename);
    }
    return false;
}

bool DPIEngine::saveRules(const std::string& filename) {
    if (rule_manager_) {
        return rule_manager_->saveRules(filename);
    }
    return false;
}

// ============================================================================
// Reporting
// ============================================================================

std::string DPIEngine::generateReport() const {
    std::ostringstream ss;
    
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                    DPI ENGINE STATISTICS                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ PACKET STATISTICS                                             ║\n";
    ss << "║   Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                        ║\n";
    ss << "║   Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                        ║\n";
    ss << "║   TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                        ║\n";
    ss << "║   UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                        ║\n";
    ss << "║   Other/Uninspected:  " << std::setw(12) << stats_.other_packets.load() << "                        ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ FILTERING STATISTICS                                          ║\n";
    ss << "║   Forwarded:          " << std::setw(12) << stats_.forwarded_packets.load() << "                        ║\n";
    ss << "║   Dropped/Blocked:    " << std::setw(12) << stats_.dropped_packets.load() << "                        ║\n";
    
    if (stats_.total_packets > 0) {
        double drop_rate = 100.0 * stats_.dropped_packets.load() / stats_.total_packets.load();
        ss << "║   Drop Rate:          " << std::setw(11) << std::fixed << std::setprecision(2) << drop_rate << "%                        ║\n";
    }
    
    if (lb_manager_) {
        auto lb_stats = lb_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ LOAD BALANCER STATISTICS                                      ║\n";
        ss << "║   LB Received:        " << std::setw(12) << lb_stats.total_received << "                        ║\n";
        ss << "║   LB Dispatched:      " << std::setw(12) << lb_stats.total_dispatched << "                        ║\n";
    }
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ FAST PATH STATISTICS                                          ║\n";
        ss << "║   FP Processed:       " << std::setw(12) << fp_stats.total_processed << "                        ║\n";
        ss << "║   FP Forwarded:       " << std::setw(12) << fp_stats.total_forwarded << "                        ║\n";
        ss << "║   FP Dropped:         " << std::setw(12) << fp_stats.total_dropped << "                        ║\n";
        ss << "║   Active Connections: " << std::setw(12) << fp_stats.total_connections << "                        ║\n";
    }
    
    if (rule_manager_) {
        auto rule_stats = rule_manager_->getStats();
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║ BLOCKING RULES                                                ║\n";
        ss << "║   Blocked IPs:        " << std::setw(12) << rule_stats.blocked_ips << "                        ║\n";
        ss << "║   Blocked Apps:       " << std::setw(12) << rule_stats.blocked_apps << "                        ║\n";
        ss << "║   Blocked Domains:    " << std::setw(12) << rule_stats.blocked_domains << "                        ║\n";
        ss << "║   Blocked Ports:      " << std::setw(12) << rule_stats.blocked_ports << "                        ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

std::string DPIEngine::generateClassificationReport() const {
    if (fp_manager_) {
        return fp_manager_->generateClassificationReport();
    }
    return "";
}

const DPIStats& DPIEngine::getStats() const {
    return stats_;
}

void DPIEngine::printStatus() const {
    std::cout << "\n--- Live Status ---\n";
    std::cout << "Packets: " << stats_.total_packets.load()
              << " | Forwarded: " << stats_.forwarded_packets.load()
              << " | Dropped: " << stats_.dropped_packets.load() << "\n";
    
    if (fp_manager_) {
        auto fp_stats = fp_manager_->getAggregatedStats();
        std::cout << "Connections: " << fp_stats.total_connections << "\n";
    }
}

} // namespace DPI
