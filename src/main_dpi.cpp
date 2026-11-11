#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <charconv>
#include "dpi_engine.h"

using namespace DPI;

void printUsage(const char* program) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: )" << program << R"( <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --block-port <port>    Block packets by destination port (0-65535)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  )" << program << R"( capture.pcap filtered.pcap
  )" << program << R"( capture.pcap filtered.pcap --block-app YouTube
  )" << program << R"( capture.pcap filtered.pcap --block-port 443
  )" << program << R"( capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  )" << program << R"( capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  2 LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  4 FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘

)";
}

std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

bool parseThreadCount(const std::string& text, int& value) {
    int parsed = 0;
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last || parsed < 1 || parsed > 64) {
        return false;
    }
    value = parsed;
    return true;
}

bool parsePort(const std::string& text, uint16_t& value) {
    uint32_t parsed = 0;
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last || parsed > 65535) return false;
    value = static_cast<uint16_t>(parsed);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = argv[2];
    
    // Parse options
    DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;
    
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    std::string rules_file;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--block-ip" && i + 1 < argc) {
            block_ips.push_back(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            block_apps.push_back(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            block_domains.push_back(argv[++i]);
        } else if (arg == "--block-port" && i + 1 < argc) {
            uint16_t port = 0;
            if (!parsePort(argv[++i], port)) {
                std::cerr << "Invalid --block-port value: expected an integer from 0 to 65535\n";
                return 2;
            }
            block_ports.push_back(port);
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--lbs" && i + 1 < argc) {
            if (!parseThreadCount(argv[++i], config.num_load_balancers)) {
                std::cerr << "Invalid --lbs value: expected an integer from 1 to 64\n";
                return 2;
            }
        } else if (arg == "--fps" && i + 1 < argc) {
            if (!parseThreadCount(argv[++i], config.fps_per_lb)) {
                std::cerr << "Invalid --fps value: expected an integer from 1 to 64\n";
                return 2;
            }
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option or missing value: " << arg << "\n";
            return 2;
        }
    }

    if (config.num_load_balancers * config.fps_per_lb > 256) {
        std::cerr << "Worker configuration exceeds the limit of 256 fast paths\n";
        return 2;
    }
    
    // Create DPI engine
    DPIEngine engine(config);
    
    // Initialize
    if (!engine.initialize()) {
        std::cerr << "Failed to initialize DPI engine\n";
        return 1;
    }
    
    // Load rules from file if specified
    if (!rules_file.empty()) {
        if (!engine.loadRules(rules_file)) {
            std::cerr << "Failed to load rules file: " << rules_file << "\n";
            return 1;
        }
    }
    
    // Apply command-line blocking rules
    for (const auto& ip : block_ips) {
        engine.blockIP(ip);
    }
    
    for (const auto& app : block_apps) {
        engine.blockApp(app);
    }
    
    for (const auto& domain : block_domains) {
        engine.blockDomain(domain);
    }

    for (const auto port : block_ports) {
        engine.blockPort(port);
    }
    
    // Process the file
    if (!engine.processFile(input_file, output_file)) {
        std::cerr << "Failed to process file\n";
        return 1;
    }
    
    std::cout << "\nProcessing complete!\n";
    std::cout << "Output written to: " << output_file << "\n";
    
    return 0;
}
