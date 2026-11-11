#include "connection_tracker.h"
#include "dpi_engine.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include "types.h"

#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void append16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void append24(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

std::vector<uint8_t> makeClientHello(const std::string& hostname) {
    std::vector<uint8_t> sni_list;
    sni_list.push_back(0); // host_name
    append16(sni_list, static_cast<uint16_t>(hostname.size()));
    sni_list.insert(sni_list.end(), hostname.begin(), hostname.end());

    std::vector<uint8_t> sni_data;
    append16(sni_data, static_cast<uint16_t>(sni_list.size()));
    sni_data.insert(sni_data.end(), sni_list.begin(), sni_list.end());

    std::vector<uint8_t> extensions;
    append16(extensions, 0); // server_name extension
    append16(extensions, static_cast<uint16_t>(sni_data.size()));
    extensions.insert(extensions.end(), sni_data.begin(), sni_data.end());

    std::vector<uint8_t> body{0x03, 0x03}; // ClientHello version
    body.insert(body.end(), 32, 0);         // random
    body.push_back(0);                      // session id length
    append16(body, 2);                      // cipher suite length
    append16(body, 0x1301);
    body.push_back(1);                      // compression list length
    body.push_back(0);
    append16(body, static_cast<uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake{1};
    append24(handshake, static_cast<uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record{0x16, 0x03, 0x01};
    append16(record, static_cast<uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<uint8_t> makeTcpFrame(uint16_t source_port) {
    std::vector<uint8_t> frame(14 + 20 + 20, 0);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[16] = 0;
    frame[17] = 40; // IPv4 total length: header plus TCP header
    frame[23] = 6;
    frame[26] = 192;
    frame[27] = 168;
    frame[28] = 1;
    frame[29] = 10;
    frame[30] = 93;
    frame[31] = 184;
    frame[32] = 216;
    frame[33] = 34;
    frame[34] = static_cast<uint8_t>(source_port >> 8);
    frame[35] = static_cast<uint8_t>(source_port);
    frame[36] = 0x01;
    frame[37] = 0xbb;
    frame[46] = 0x50;
    return frame;
}

std::vector<uint8_t> makeReverseTcpFrame(uint16_t client_port) {
    auto frame = makeTcpFrame(client_port);
    for (size_t i = 0; i < 4; ++i) std::swap(frame[26 + i], frame[30 + i]);
    std::swap(frame[34], frame[36]);
    std::swap(frame[35], frame[37]);
    return frame;
}

std::vector<uint8_t> makeTcpPayloadFrame(uint16_t source_port, uint32_t sequence,
                                         const std::vector<uint8_t>& payload) {
    auto frame = makeTcpFrame(source_port);
    frame[38] = static_cast<uint8_t>(sequence >> 24);
    frame[39] = static_cast<uint8_t>(sequence >> 16);
    frame[40] = static_cast<uint8_t>(sequence >> 8);
    frame[41] = static_cast<uint8_t>(sequence);
    frame[47] = 0x18; // PSH, ACK
    frame.insert(frame.end(), payload.begin(), payload.end());
    const uint16_t ip_length = static_cast<uint16_t>(40 + payload.size());
    frame[16] = static_cast<uint8_t>(ip_length >> 8);
    frame[17] = static_cast<uint8_t>(ip_length);
    return frame;
}

void testDomainClassification() {
    using DPI::AppType;
    require(DPI::sniToAppType("www.netflix.com") == AppType::NETFLIX,
            "Netflix hostname classified incorrectly");
    require(DPI::sniToAppType("www.microsoft.com") == AppType::MICROSOFT,
            "Microsoft hostname classified incorrectly");
    require(DPI::sniToAppType("twitter.com") == AppType::TWITTER,
            "Twitter hostname classified incorrectly");
    require(DPI::sniToAppType("example-t.co.attacker.test") == AppType::HTTPS,
            "Substring false positive in hostname classification");
}

void testBidirectionalFlow() {
    DPI::FiveTuple forward{0x0100007f, 0x0200007f, 50000, 443, 6};
    const DPI::FiveTuple reverse = forward.reverse();
    require(DPI::FiveTupleHash{}(forward) == DPI::FiveTupleHash{}(reverse),
            "Reverse flow hashes to a different worker");

    DPI::ConnectionTracker tracker(0);
    auto* first = tracker.getOrCreateConnection(forward);
    auto* second = tracker.getOrCreateConnection(reverse);
    require(first == second, "Reverse packet did not reuse the connection state");
    require(tracker.getActiveCount() == 1, "Reverse flow created a duplicate connection");
    tracker.blockConnection(first);
    require(tracker.getOrCreateConnection(reverse)->state == DPI::ConnectionState::BLOCKED,
            "Block state was not retained for the reverse direction");
    tracker.closeConnection(forward);
    auto* reused = tracker.getOrCreateConnection(forward);
    require(reused->state == DPI::ConnectionState::NEW && reused->app_type == DPI::AppType::UNKNOWN,
            "Closed flow tuple reuse retained stale classification state");
}

void testPacketParserBounds() {
    PacketAnalyzer::RawPacket raw{};
    const auto tls_hello = makeClientHello("www.youtube.com");
    raw.data.resize(14 + 20 + 20, 0);
    raw.data[12] = 0x08;
    raw.data[13] = 0x00; // IPv4 EtherType
    raw.data[14] = 0x45; // IPv4, 20-byte header
    raw.data[23] = 6;    // TCP
    raw.data[26] = 192;
    raw.data[27] = 168;
    raw.data[28] = 1;
    raw.data[29] = 10;
    raw.data[30] = 93;
    raw.data[31] = 184;
    raw.data[32] = 216;
    raw.data[33] = 34;
    raw.data[34] = 0xc3;
    raw.data[35] = 0x50; // source port 50000
    raw.data[36] = 0x01;
    raw.data[37] = 0xbb; // destination port 443
    raw.data[46] = 0x50; // TCP data offset 5
    raw.data.insert(raw.data.end(), tls_hello.begin(), tls_hello.end());
    const uint16_t ip_length = static_cast<uint16_t>(40 + tls_hello.size());
    raw.data[16] = static_cast<uint8_t>(ip_length >> 8);
    raw.data[17] = static_cast<uint8_t>(ip_length);

    PacketAnalyzer::ParsedPacket parsed{};
    require(PacketAnalyzer::PacketParser::parse(raw, parsed), "Valid Ethernet/IPv4/TCP frame rejected");
    require(parsed.has_ip && parsed.has_tcp && parsed.dest_port == 443,
            "Parsed packet fields are incorrect");

    auto padded = raw;
    padded.data.insert(padded.data.end(), 12, 0);
    require(PacketAnalyzer::PacketParser::parse(padded, parsed) &&
            parsed.payload_length == tls_hello.size(),
            "Ethernet padding was included in the IPv4 payload");

    auto fragmented = raw;
    fragmented.data[20] = 0x20; // IPv4 More Fragments flag
    fragmented.data[21] = 0;
    require(PacketAnalyzer::PacketParser::parse(fragmented, parsed) && parsed.is_fragmented &&
            !parsed.has_tcp && !parsed.has_udp,
            "IPv4 fragment was incorrectly treated as a complete transport packet");

    auto invalid_ip_length = raw;
    invalid_ip_length.data[16] = 0;
    invalid_ip_length.data[17] = 19;
    require(!PacketAnalyzer::PacketParser::parse(invalid_ip_length, parsed),
            "IPv4 total length shorter than its header was accepted");

    PacketAnalyzer::RawPacket tagged{};
    tagged.data.resize(raw.data.size() + 4);
    std::copy(raw.data.begin(), raw.data.begin() + 12, tagged.data.begin());
    tagged.data[12] = 0x81;
    tagged.data[13] = 0x00;
    tagged.data[14] = 0;
    tagged.data[15] = 100;
    tagged.data[16] = 0x08;
    tagged.data[17] = 0x00;
    std::copy(raw.data.begin() + 14, raw.data.end(), tagged.data.begin() + 18);
    require(PacketAnalyzer::PacketParser::parse(tagged, parsed), "802.1Q-tagged IPv4 frame rejected");
    require(parsed.has_tcp && parsed.ip_header_offset == 18 && parsed.transport_header_offset == 38,
            "802.1Q header offsets are incorrect");
    auto tagged_sni = DPI::SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
    require(tagged_sni && *tagged_sni == "www.youtube.com",
            "TLS SNI was not available through VLAN parser offsets");

    PacketAnalyzer::RawPacket qinq{};
    qinq.data.resize(raw.data.size() + 8);
    std::copy(raw.data.begin(), raw.data.begin() + 12, qinq.data.begin());
    qinq.data[12] = 0x88;
    qinq.data[13] = 0xa8;
    qinq.data[16] = 0x81;
    qinq.data[17] = 0x00;
    qinq.data[20] = 0x08;
    qinq.data[21] = 0x00;
    std::copy(raw.data.begin() + 14, raw.data.end(), qinq.data.begin() + 22);
    require(PacketAnalyzer::PacketParser::parse(qinq, parsed), "QinQ-tagged IPv4 frame rejected");
    require(parsed.has_tcp && parsed.ip_header_offset == 22 && parsed.transport_header_offset == 42,
            "QinQ header offsets are incorrect");
    auto qinq_sni = DPI::SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
    require(qinq_sni && *qinq_sni == "www.youtube.com",
            "TLS SNI was not available through QinQ parser offsets");

    PacketAnalyzer::RawPacket truncated_vlan{};
    truncated_vlan.data.resize(16, 0);
    truncated_vlan.data[12] = 0x81;
    truncated_vlan.data[13] = 0x00;
    require(!PacketAnalyzer::PacketParser::parse(truncated_vlan, parsed),
            "Truncated VLAN header was accepted");

    raw.data.resize(14 + 20 + 12);
    require(!PacketAnalyzer::PacketParser::parse(raw, parsed),
            "Truncated TCP header was accepted");
}

void testTlsSniBounds() {
    auto hello = makeClientHello("www.example.com");
    auto extracted = DPI::SNIExtractor::extract(hello.data(), hello.size());
    require(extracted && *extracted == "www.example.com", "Valid TLS SNI was not extracted");

    hello.pop_back();
    require(!DPI::SNIExtractor::extract(hello.data(), hello.size()),
            "Truncated TLS ClientHello was accepted");
}

void testDomainRulesCaseInsensitive() {
    DPI::RuleManager rules;
    rules.blockDomain("Example.COM");
    require(rules.isDomainBlocked("example.com"), "Exact domain rule is case-sensitive");
    require(!rules.isDomainBlocked("notexample.com"), "Exact domain rule matched a substring");

    rules.blockDomain("*.example.net");
    require(rules.isDomainBlocked("api.EXAMPLE.net"), "Wildcard domain rule missed a subdomain");
}

void testIPAndRulesFileValidation() {
    DPI::RuleManager rules;
    rules.blockIP("0.0.0.0");
    rules.blockIP("999.1.2.3");
    rules.blockIP("1.2.3");
    require(rules.isIPBlocked(0), "Valid zero IPv4 address was rejected");
    require(rules.getStats().blocked_ips == 1, "Malformed IPv4 rule was accepted");

    const auto path = std::filesystem::temp_directory_path() / "packet_analyzer_rules_validation.txt";
    rules.blockPort(1234);
    {
        std::ofstream file(path);
        file << "[BLOCKED_IPS]\n192.168.1.10\n[BLOCKED_PORTS]\n70000\n";
    }
    require(!rules.loadRules(path.string()), "Malformed rules file was accepted");
    require(rules.isIPBlocked(0) && !rules.isIPBlocked(0x0a01a8c0u) && rules.isPortBlocked(1234),
            "Failed rules load partially changed the active rules");

    {
        std::ofstream file(path);
        file << "# valid replacement rules\n[BLOCKED_IPS]\n192.168.1.10\n"
                "[BLOCKED_DOMAINS]\n*.example.org\n[BLOCKED_PORTS]\n443\n";
    }
    require(rules.loadRules(path.string()), "Valid rules file was rejected");
    require(!rules.isIPBlocked(0) && rules.isIPBlocked(0x0a01a8c0u) &&
            !rules.isPortBlocked(1234) && rules.isPortBlocked(443) &&
            rules.isDomainBlocked("api.example.org"),
            "Valid rules file did not replace active rules correctly");
    std::filesystem::remove(path);
}

void testTruncatedPcap() {
    static_assert(sizeof(PacketAnalyzer::PcapGlobalHeader) == 24);
    static_assert(sizeof(PacketAnalyzer::PcapPacketHeader) == 16);

    const auto path = std::filesystem::temp_directory_path() / "packet_analyzer_truncated_test.pcap";
    PacketAnalyzer::PcapGlobalHeader global{};
    global.magic_number = 0xa1b2c3d4;
    global.version_major = 2;
    global.version_minor = 4;
    global.snaplen = 65535;
    global.network = 1;
    PacketAnalyzer::PcapPacketHeader packet{1, 0, 4, 4};
    const char short_data[2] = {0, 1};

    {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(&global), sizeof(global));
        file.write(reinterpret_cast<const char*>(&packet), sizeof(packet));
        file.write(short_data, sizeof(short_data));
    }

    PacketAnalyzer::PcapReader reader;
    require(reader.open(path.string()), "Could not open generated PCAP test file");
    PacketAnalyzer::RawPacket raw;
    require(!reader.readNextPacket(raw), "Truncated packet data was accepted");
    require(reader.hasError(), "Truncated PCAP was not reported as an error");
    reader.close();
    std::filesystem::remove(path);
}

void testUnhandledEthernetPassThroughAndSameFileGuard() {
    const auto base = std::filesystem::temp_directory_path();
    const auto input_path = base / "packet_analyzer_passthrough_input.pcap";
    const auto output_path = base / "packet_analyzer_passthrough_output.pcap";

    PacketAnalyzer::PcapGlobalHeader global{};
    global.magic_number = 0xa1b2c3d4;
    global.version_major = 2;
    global.version_minor = 4;
    global.snaplen = 65535;
    global.network = 1;

    const std::vector<std::vector<uint8_t>> frames = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x06, 1, 2, 3},
        makeTcpFrame(50001),
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xb5, 4, 5, 6},
        makeTcpFrame(50002)
    };
    {
        std::ofstream file(input_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(&global), sizeof(global));
        for (const auto& frame : frames) {
            PacketAnalyzer::PcapPacketHeader packet{1, 0,
                static_cast<uint32_t>(frame.size()), static_cast<uint32_t>(frame.size())};
            file.write(reinterpret_cast<const char*>(&packet), sizeof(packet));
            file.write(reinterpret_cast<const char*>(frame.data()), frame.size());
        }
    }

    DPI::DPIEngine::Config config;
    config.num_load_balancers = 1;
    config.fps_per_lb = 1;
    DPI::DPIEngine engine(config);
    require(engine.initialize(), "Could not initialize engine for ordering test");
    engine.blockPort(443);
    require(engine.processFile(input_path.string(), output_path.string()),
            "Engine failed processing Ethernet frames outside its DPI scope");
    require(engine.getStats().total_packets == 4 && engine.getStats().forwarded_packets == 2 &&
            engine.getStats().dropped_packets == 2,
            "Filtered and pass-through packet counts are incorrect");

    std::ifstream output(output_path, std::ios::binary);
    PacketAnalyzer::PcapGlobalHeader output_global{};
    output.read(reinterpret_cast<char*>(&output_global), sizeof(output_global));
    require(output_global.magic_number == global.magic_number, "Output PCAP header is invalid");
    for (size_t index : {size_t{0}, size_t{2}}) {
        const auto& frame = frames[index];
        PacketAnalyzer::PcapPacketHeader packet{};
        output.read(reinterpret_cast<char*>(&packet), sizeof(packet));
        require(output.good() && packet.incl_len == frame.size(), "Pass-through packet header mismatch");
        std::vector<uint8_t> bytes(packet.incl_len);
        output.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        require(bytes == frame, "Pass-through packet bytes changed");
    }
    output.close();

    const auto input_size = std::filesystem::file_size(input_path);
    DPI::DPIEngine same_file_engine(config);
    require(!same_file_engine.processFile(input_path.string(), input_path.string()),
            "Engine accepted the same path as input and output");
    require(std::filesystem::file_size(input_path) == input_size,
            "Same-file guard modified the source capture");

    const auto bad_output_path = base / "packet_analyzer_output_directory.pcap";
    std::filesystem::create_directory(bad_output_path);
    DPI::DPIEngine failed_output_engine(config);
    require(!failed_output_engine.processFile(input_path.string(), bad_output_path.string()),
            "Engine reported success when the output target could not be opened");
    std::filesystem::remove(bad_output_path);

    std::filesystem::remove(input_path);
    std::filesystem::remove(output_path);
}

void testBidirectionalIPBlocking() {
    const auto base = std::filesystem::temp_directory_path();
    const auto input_path = base / "packet_analyzer_reverse_rule_input.pcap";
    const auto output_path = base / "packet_analyzer_reverse_rule_output.pcap";
    const auto forward = makeTcpFrame(50004);
    const auto reverse = makeReverseTcpFrame(50004);
    PacketAnalyzer::PcapGlobalHeader global{};
    global.magic_number = 0xa1b2c3d4;
    global.version_major = 2;
    global.version_minor = 4;
    global.snaplen = 65535;
    global.network = 1;
    {
        std::ofstream file(input_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(&global), sizeof(global));
        for (const auto* frame : {&forward, &reverse}) {
            PacketAnalyzer::PcapPacketHeader packet{1, 0,
                static_cast<uint32_t>(frame->size()), static_cast<uint32_t>(frame->size())};
            file.write(reinterpret_cast<const char*>(&packet), sizeof(packet));
            file.write(reinterpret_cast<const char*>(frame->data()), frame->size());
        }
    }

    DPI::DPIEngine::Config config;
    config.num_load_balancers = 1;
    config.fps_per_lb = 1;
    DPI::DPIEngine engine(config);
    require(engine.initialize(), "Could not initialize bidirectional IP rule test");
    engine.blockIP("192.168.1.10");
    require(engine.processFile(input_path.string(), output_path.string()),
            "Engine failed processing bidirectional IP rule traffic");
    require(engine.getStats().total_packets == 2 && engine.getStats().dropped_packets == 2 &&
            engine.getStats().forwarded_packets == 0,
            "Reverse flow packet did not use the tracked client's IP rule");

    PacketAnalyzer::PcapReader output;
    require(output.open(output_path.string()), "Could not open bidirectional rule output PCAP");
    PacketAnalyzer::RawPacket raw;
    require(!output.readNextPacket(raw) && !output.hasError(),
            "A packet from the blocked bidirectional flow was forwarded");
    output.close();
    std::filesystem::remove(input_path);
    std::filesystem::remove(output_path);
}

void testSplitClientHelloBlocking() {
    const auto base = std::filesystem::temp_directory_path();
    const auto input_path = base / "packet_analyzer_split_tls_input.pcap";
    const auto output_path = base / "packet_analyzer_split_tls_output.pcap";
    const auto hello = makeClientHello("www.youtube.com");
    const size_t first_size = 11;
    const size_t second_size = 17;
    // Force the segmented ClientHello across TCP's 32-bit sequence wrap point.
    const uint32_t initial_sequence = 0xfffffff0u;
    const auto sequence_at = [initial_sequence](size_t offset) {
        return initial_sequence + static_cast<uint32_t>(offset);
    };
    const std::vector<uint8_t> first_part(hello.begin(), hello.begin() + first_size);
    const std::vector<uint8_t> second_part(hello.begin() + first_size,
                                           hello.begin() + first_size + second_size);
    const std::vector<uint8_t> third_part(hello.begin() + first_size + second_size, hello.end());
    const auto frame1 = makeTcpPayloadFrame(50003, initial_sequence, first_part);
    const auto frame2 = makeTcpPayloadFrame(50003, sequence_at(first_size), second_part);
    const auto frame3 = makeTcpPayloadFrame(50003, sequence_at(first_size + second_size), third_part);
    const auto frame4 = makeTcpPayloadFrame(50003, sequence_at(hello.size()),
                                             {0x17, 0x03, 0x03, 0, 1, 0});

    PacketAnalyzer::PcapGlobalHeader global{};
    global.magic_number = 0xa1b2c3d4;
    global.version_major = 2;
    global.version_minor = 4;
    global.snaplen = 65535;
    global.network = 1;
    {
        std::ofstream file(input_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(&global), sizeof(global));
        // Deliberately deliver the final ClientHello bytes before the middle range.
        for (const auto* frame : {&frame1, &frame3, &frame2, &frame4}) {
            PacketAnalyzer::PcapPacketHeader packet{1, 0,
                static_cast<uint32_t>(frame->size()), static_cast<uint32_t>(frame->size())};
            file.write(reinterpret_cast<const char*>(&packet), sizeof(packet));
            file.write(reinterpret_cast<const char*>(frame->data()), frame->size());
        }
    }

    DPI::DPIEngine::Config config;
    config.num_load_balancers = 1;
    config.fps_per_lb = 1;
    DPI::DPIEngine engine(config);
    require(engine.initialize(), "Could not initialize split-TLS blocking test");
    engine.blockApp("YouTube");
    require(engine.processFile(input_path.string(), output_path.string()),
            "Engine failed processing segmented ClientHello traffic");
    require(engine.getStats().total_packets == 4 && engine.getStats().dropped_packets == 2 &&
            engine.getStats().forwarded_packets == 2,
            "Split ClientHello did not trigger SNI-based flow blocking");

    PacketAnalyzer::PcapReader output;
    require(output.open(output_path.string()), "Could not open split-TLS output PCAP");
    PacketAnalyzer::RawPacket raw;
    require(output.readNextPacket(raw) && raw.data == frame1, "First pre-classification packet missing");
    require(output.readNextPacket(raw) && raw.data == frame3, "Out-of-order pre-classification packet missing");
    require(!output.readNextPacket(raw), "Blocked ClientHello or later flow packet was forwarded");
    require(!output.hasError(), "Split-TLS output PCAP is malformed");
    output.close();

    std::filesystem::remove(input_path);
    std::filesystem::remove(output_path);
}

} // namespace

int main() {
    try {
        testDomainClassification();
        testBidirectionalFlow();
        testPacketParserBounds();
        testTlsSniBounds();
        testDomainRulesCaseInsensitive();
        testIPAndRulesFileValidation();
        testTruncatedPcap();
        testUnhandledEthernetPassThroughAndSameFileGuard();
        testBidirectionalIPBlocking();
        testSplitClientHelloBlocking();
        std::cout << "All engine regression checks passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Engine regression check failed: " << error.what() << '\n';
        return 1;
    }
}
