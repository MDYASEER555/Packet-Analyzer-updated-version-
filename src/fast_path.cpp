#include "fast_path.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id,
                                     RuleManager* rule_manager,
                                     PacketOutputCallback output_callback)
    : fp_id_(fp_id),
      input_queue_(10000),
      conn_tracker_(fp_id),
      rule_manager_(rule_manager),
      output_callback_(std::move(output_callback)) {
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[FP" << fp_id_ << "] Stopped (processed " 
              << packets_processed_ << " packets)\n";
}

void FastPathProcessor::run() {
    for (;;) {
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            if (input_queue_.isShutdown()) break;
            // Periodically cleanup stale connections
            conn_tracker_.cleanupStale(std::chrono::seconds(300));
            continue;
        }
        
        packets_processed_++;
        
        // Process the packet
        PacketAction action = processPacket(*job_opt);
        
        // Call output callback
        if (output_callback_) {
            output_callback_(*job_opt, action);
        }
        
        // Update stats
        if (action == PacketAction::DROP) {
            packets_dropped_++;
        } else {
            packets_forwarded_++;
        }
    }
}

PacketAction FastPathProcessor::processPacket(PacketJob& job) {
    // Get or create connection
    Connection* conn = conn_tracker_.getOrCreateConnection(job.tuple);
    if (!conn) {
        // Should not happen, but handle gracefully
        return PacketAction::FORWARD;
    }
    
    // Update connection stats
    const bool is_outbound = conn->tuple == job.tuple;
    conn_tracker_.updateConnection(conn, job.data.size(), is_outbound);
    
    // Update TCP state if applicable
    if (job.tuple.protocol == 6) {  // TCP
        updateTCPState(conn, job.tcp_flags, !is_outbound);
    }
    
    // If connection is already blocked, drop immediately
    if (conn->state == ConnectionState::BLOCKED) {
        return PacketAction::DROP;
    }
    
    // Keep inspecting generic HTTPS flows until a split ClientHello yields SNI.
    const bool awaiting_sni = conn->app_type == AppType::HTTPS && conn->sni.empty();
    if ((conn->state != ConnectionState::CLASSIFIED || awaiting_sni) && job.payload_length > 0) {
        inspectPayload(job, conn);
    }
    
    // Check rules (even for classified connections, as rules might change)
    return checkRules(job, conn);
}

void FastPathProcessor::inspectPayload(PacketJob& job, Connection* conn) {
    if (job.payload_length == 0 || job.payload_offset >= job.data.size()) {
        return;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    
    // Try TLS SNI extraction first (most common for HTTPS)
    if (tryExtractSNI(job, conn)) {
        return;
    }
    
    // Try HTTP Host header extraction
    if (tryExtractHTTPHost(job, conn)) {
        return;
    }
    
    // Check for DNS (port 53)
    if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
        auto domain = DNSExtractor::extractQuery(payload, job.payload_length);
        if (domain) {
            conn_tracker_.classifyConnection(conn, AppType::DNS, *domain);
            return;
        }
    }
    
    // Basic port-based classification as fallback
    if (job.tuple.dst_port == 80) {
        conn_tracker_.classifyConnection(conn, AppType::HTTP, "");
    } else if (job.tuple.dst_port == 443) {
        conn_tracker_.classifyConnection(conn, AppType::HTTPS, "");
    }
}

bool FastPathProcessor::tryExtractSNI(const PacketJob& job, Connection* conn) {
    // ClientHello inspection is currently limited to the usual HTTPS port.
    if (job.tuple.dst_port != 443 || job.payload_offset >= job.data.size() ||
        job.payload_length == 0 || job.payload_length > job.data.size() - job.payload_offset) {
        return false;
    }

    const uint8_t* payload = job.data.data() + job.payload_offset;
    constexpr size_t MAX_TLS_INSPECTION_BYTES = 32768;

    if (!conn->tls_buffer_initialized) {
        conn->tls_buffer_base_sequence = job.tcp_sequence;
        conn->tls_buffer_initialized = true;
    }

    auto& buffer = conn->tls_client_hello_buffer;
    auto& received = conn->tls_client_hello_received;
    const uint32_t raw_delta = job.tcp_sequence - conn->tls_buffer_base_sequence;
    const int64_t relative = raw_delta >= 0x80000000u
        ? static_cast<int64_t>(raw_delta) - 0x100000000LL
        : static_cast<int64_t>(raw_delta);

    size_t offset = 0;
    if (relative < 0) {
        const size_t prepend = static_cast<size_t>(-relative);
        if (prepend > MAX_TLS_INSPECTION_BYTES ||
            buffer.size() > MAX_TLS_INSPECTION_BYTES - prepend) {
            return false;
        }
        buffer.insert(buffer.begin(), prepend, 0);
        received.insert(received.begin(), prepend, 0);
        conn->tls_buffer_base_sequence = job.tcp_sequence;
        offset = 0;
    } else {
        offset = static_cast<size_t>(relative);
    }

    if (offset > MAX_TLS_INSPECTION_BYTES ||
        job.payload_length > MAX_TLS_INSPECTION_BYTES - offset) {
        return false;
    }
    const size_t end = offset + job.payload_length;
    if (buffer.size() < end) {
        buffer.resize(end, 0);
        received.resize(end, 0);
    }

    std::copy(payload, payload + job.payload_length, buffer.begin() + offset);
    std::fill(received.begin() + offset, received.begin() + end, 1);

    size_t contiguous_size = 0;
    while (contiguous_size < received.size() && received[contiguous_size] != 0) {
        ++contiguous_size;
    }
    if (contiguous_size == 0) return false;

    auto sni = SNIExtractor::extract(buffer.data(), contiguous_size);
    if (sni) {
        sni_extractions_++;
        
        // Map SNI to app type
        AppType app = sniToAppType(*sni);
        conn_tracker_.classifyConnection(conn, app, *sni);
        
        if (app != AppType::UNKNOWN && app != AppType::HTTPS) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

bool FastPathProcessor::tryExtractHTTPHost(const PacketJob& job, Connection* conn) {
    // Only for port 80 (HTTP)
    if (job.tuple.dst_port != 80) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto host = HTTPHostExtractor::extract(payload, job.payload_length);
    if (host) {
        AppType app = sniToAppType(*host);
        conn_tracker_.classifyConnection(conn, app, *host);
        
        if (app != AppType::UNKNOWN && app != AppType::HTTP) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

PacketAction FastPathProcessor::checkRules(const PacketJob& job, Connection* conn) {
    if (!rule_manager_) {
        return PacketAction::FORWARD;
    }
    
    // Evaluate address and port rules in the stable flow direction so the
    // reverse half of a connection sees the same client and server fields.
    auto block_reason = rule_manager_->shouldBlock(
        conn->tuple.src_ip,
        conn->tuple.dst_port,
        conn->app_type,
        conn->sni
    );
    
    if (block_reason) {
        // Log the block
        std::ostringstream ss;
        ss << "[FP" << fp_id_ << "] BLOCKED packet: ";
        
        switch (block_reason->type) {
            case RuleManager::BlockReason::IP:
                ss << "IP " << block_reason->detail;
                break;
            case RuleManager::BlockReason::APP:
                ss << "App " << block_reason->detail;
                break;
            case RuleManager::BlockReason::DOMAIN:
                ss << "Domain " << block_reason->detail;
                break;
            case RuleManager::BlockReason::PORT:
                ss << "Port " << block_reason->detail;
                break;
        }
        
        std::cout << ss.str() << std::endl;
        
        // Mark connection as blocked
        conn_tracker_.blockConnection(conn);
        
        return PacketAction::DROP;
    }
    
    return PacketAction::FORWARD;
}

void FastPathProcessor::updateTCPState(Connection* conn, uint8_t tcp_flags, bool reverse_direction) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;
    
    if (tcp_flags & SYN) {
        if (tcp_flags & ACK) {
            conn->syn_ack_seen = true;
        } else {
            conn->syn_seen = true;
        }
    }
    
    if (conn->syn_seen && conn->syn_ack_seen && (tcp_flags & ACK)) {
        if (conn->state == ConnectionState::NEW) {
            conn->state = ConnectionState::ESTABLISHED;
        }
    }
    
    if (tcp_flags & RST) {
        conn->state = ConnectionState::CLOSED;
        return;
    }
    
    if (tcp_flags & FIN) {
        if (reverse_direction) {
            conn->fin_seen_reverse = true;
        } else {
            conn->fin_seen_forward = true;
        }
    }

    if (conn->fin_seen_forward && conn->fin_seen_reverse) {
        conn->state = ConnectionState::CLOSED;
    }
}

FastPathProcessor::FPStats FastPathProcessor::getStats() const {
    FPStats stats;
    stats.packets_processed = packets_processed_.load();
    stats.packets_forwarded = packets_forwarded_.load();
    stats.packets_dropped = packets_dropped_.load();
    stats.connections_tracked = conn_tracker_.getActiveCount();
    stats.sni_extractions = sni_extractions_.load();
    stats.classification_hits = classification_hits_.load();
    return stats;
}

// ============================================================================
// FPManager Implementation
// ============================================================================

FPManager::FPManager(int num_fps,
                     RuleManager* rule_manager,
                     PacketOutputCallback output_callback) {
    
    // Create FP processors (each has its own input queue)
    for (int i = 0; i < num_fps; i++) {
        auto fp = std::make_unique<FastPathProcessor>(i, rule_manager, output_callback);
        fps_.push_back(std::move(fp));
    }
    
    std::cout << "[FPManager] Created " << num_fps << " fast path processors\n";
}

FPManager::~FPManager() {
    stopAll();
}

void FPManager::startAll() {
    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {
    // Stop all FPs (they'll shutdown their own queues)
    for (auto& fp : fps_) {
        fp->stop();
    }
}

FPManager::AggregatedStats FPManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0, 0, 0};
    
    for (const auto& fp : fps_) {
        auto fp_stats = fp->getStats();
        stats.total_processed += fp_stats.packets_processed;
        stats.total_forwarded += fp_stats.packets_forwarded;
        stats.total_dropped += fp_stats.packets_dropped;
        stats.total_connections += fp_stats.connections_tracked;
    }
    
    return stats;
}

std::string FPManager::generateClassificationReport() const {
    // Aggregate app distribution across all FPs
    std::unordered_map<AppType, size_t> app_counts;
    std::unordered_map<std::string, size_t> domain_counts;
    size_t total_classified = 0;
    size_t total_unknown = 0;
    
    for (const auto& fp : fps_) {
        fp->getConnectionTracker().forEach([&](const Connection& conn) {
            app_counts[conn.app_type]++;
            
            if (conn.app_type == AppType::UNKNOWN) {
                total_unknown++;
            } else {
                total_classified++;
            }
            
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                 APPLICATION CLASSIFICATION REPORT             ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    size_t total = total_classified + total_unknown;
    double classified_pct = total > 0 ? (100.0 * total_classified / total) : 0;
    double unknown_pct = total > 0 ? (100.0 * total_unknown / total) : 0;
    
    ss << "║ Total Connections:    " << std::setw(10) << total << "                           ║\n";
    ss << "║ Classified:           " << std::setw(10) << total_classified 
       << " (" << std::fixed << std::setprecision(1) << classified_pct << "%)                  ║\n";
    ss << "║ Unidentified:         " << std::setw(10) << total_unknown
       << " (" << std::fixed << std::setprecision(1) << unknown_pct << "%)                  ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION DISTRIBUTION                   ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Sort apps by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        
        // Create a simple bar graph
        int bar_len = static_cast<int>(pct / 5);  // 20 chars max
        std::string bar(bar_len, '#');
        
        ss << "║ " << std::setw(15) << std::left << appTypeToString(pair.first)
           << std::setw(8) << std::right << pair.second
           << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
           << std::setw(20) << std::left << bar << "   ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

} // namespace DPI
