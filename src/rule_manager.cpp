#include "rule_manager.h"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <mutex>
#include <cctype>
#include <limits>

namespace DPI {

// ============================================================================
// IP Blocking
// ============================================================================

std::optional<uint32_t> RuleManager::parseIP(const std::string& ip) {
    uint32_t result = 0;
    size_t position = 0;
    for (int index = 0; index < 4; ++index) {
        if (position >= ip.size() || ip[position] < '0' || ip[position] > '9') {
            return std::nullopt;
        }
        uint32_t octet = 0;
        size_t digits = 0;
        while (position < ip.size() && ip[position] >= '0' && ip[position] <= '9') {
            octet = octet * 10 + static_cast<uint32_t>(ip[position] - '0');
            if (octet > 255 || ++digits > 3) return std::nullopt;
            ++position;
        }
        result |= octet << (index * 8);
        if (index < 3) {
            if (position >= ip.size() || ip[position] != '.') return std::nullopt;
            ++position;
        }
    }
    if (position != ip.size()) return std::nullopt;
    return result;
}

std::string RuleManager::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

void RuleManager::blockIP(uint32_t ip) {
    std::unique_lock<std::mutex> lock(ip_mutex_);
    blocked_ips_.insert(ip);
    std::cout << "[RuleManager] Blocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::blockIP(const std::string& ip) {
    if (const auto parsed = parseIP(ip)) blockIP(*parsed);
}

void RuleManager::unblockIP(uint32_t ip) {
    std::unique_lock<std::mutex> lock(ip_mutex_);
    blocked_ips_.erase(ip);
    std::cout << "[RuleManager] Unblocked IP: " << ipToString(ip) << std::endl;
}

void RuleManager::unblockIP(const std::string& ip) {
    if (const auto parsed = parseIP(ip)) unblockIP(*parsed);
}

bool RuleManager::isIPBlocked(uint32_t ip) const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    return blocked_ips_.count(ip) > 0;
}

std::vector<std::string> RuleManager::getBlockedIPs() const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (uint32_t ip : blocked_ips_) {
        result.push_back(ipToString(ip));
    }
    return result;
}

// ============================================================================
// Application Blocking
// ============================================================================

void RuleManager::blockApp(AppType app) {
    std::unique_lock<std::mutex> lock(app_mutex_);
    blocked_apps_.insert(app);
    std::cout << "[RuleManager] Blocked app: " << appTypeToString(app) << std::endl;
}

void RuleManager::unblockApp(AppType app) {
    std::unique_lock<std::mutex> lock(app_mutex_);
    blocked_apps_.erase(app);
    std::cout << "[RuleManager] Unblocked app: " << appTypeToString(app) << std::endl;
}

bool RuleManager::isAppBlocked(AppType app) const {
    std::lock_guard<std::mutex> lock(app_mutex_);
    return blocked_apps_.count(app) > 0;
}

std::vector<AppType> RuleManager::getBlockedApps() const {
    std::lock_guard<std::mutex> lock(app_mutex_);
    return std::vector<AppType>(blocked_apps_.begin(), blocked_apps_.end());
}

// ============================================================================
// Domain Blocking
// ============================================================================

void RuleManager::blockDomain(const std::string& domain) {
    std::string normalized = domain;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::unique_lock<std::mutex> lock(domain_mutex_);
    
    if (normalized.find('*') != std::string::npos) {
        domain_patterns_.push_back(normalized);
    } else {
        blocked_domains_.insert(normalized);
    }
    
    std::cout << "[RuleManager] Blocked domain: " << domain << std::endl;
}

void RuleManager::unblockDomain(const std::string& domain) {
    std::string normalized = domain;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::unique_lock<std::mutex> lock(domain_mutex_);
    
    if (normalized.find('*') != std::string::npos) {
        auto it = std::find(domain_patterns_.begin(), domain_patterns_.end(), normalized);
        if (it != domain_patterns_.end()) {
            domain_patterns_.erase(it);
        }
    } else {
        blocked_domains_.erase(normalized);
    }
    
    std::cout << "[RuleManager] Unblocked domain: " << domain << std::endl;
}

bool RuleManager::domainMatchesPattern(const std::string& domain, const std::string& pattern) {
    // Handle *.example.com pattern
    if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        std::string suffix = pattern.substr(1);  // .example.com
        
        // Check if domain ends with the pattern
        if (domain.size() >= suffix.size() &&
            domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        
        // Also match the bare domain (example.com matches *.example.com)
        if (domain == pattern.substr(2)) {
            return true;
        }
    }
    
    return false;
}

bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(domain_mutex_);

    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    
    // Check exact match
    if (blocked_domains_.count(lower_domain) > 0) {
        return true;
    }
    
    // Check patterns
    for (const auto& pattern : domain_patterns_) {
        std::string lower_pattern = pattern;
        std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        
        if (domainMatchesPattern(lower_domain, lower_pattern)) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> RuleManager::getBlockedDomains() const {
    std::lock_guard<std::mutex> lock(domain_mutex_);
    std::vector<std::string> result(blocked_domains_.begin(), blocked_domains_.end());
    result.insert(result.end(), domain_patterns_.begin(), domain_patterns_.end());
    return result;
}

// ============================================================================
// Port Blocking
// ============================================================================

void RuleManager::blockPort(uint16_t port) {
    std::unique_lock<std::mutex> lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Blocked port: " << port << std::endl;
}

void RuleManager::unblockPort(uint16_t port) {
    std::unique_lock<std::mutex> lock(port_mutex_);
    blocked_ports_.erase(port);
}

bool RuleManager::isPortBlocked(uint16_t port) const {
    std::lock_guard<std::mutex> lock(port_mutex_);
    return blocked_ports_.count(port) > 0;
}

// ============================================================================
// Combined Check
// ============================================================================

std::optional<RuleManager::BlockReason> RuleManager::shouldBlock(
    uint32_t src_ip,
    uint16_t dst_port,
    AppType app,
    const std::string& domain) const {
    
    // Check IP first (most specific)
    if (isIPBlocked(src_ip)) {
        return BlockReason{BlockReason::IP, ipToString(src_ip)};
    }
    
    // Check port
    if (isPortBlocked(dst_port)) {
        return BlockReason{BlockReason::PORT, std::to_string(dst_port)};
    }
    
    // Check app
    if (isAppBlocked(app)) {
        return BlockReason{BlockReason::APP, appTypeToString(app)};
    }
    
    // Check domain
    if (!domain.empty() && isDomainBlocked(domain)) {
        return BlockReason{BlockReason::DOMAIN, domain};
    }
    
    return std::nullopt;
}

// ============================================================================
// Persistence
// ============================================================================

bool RuleManager::saveRules(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    // Save blocked IPs
    file << "[BLOCKED_IPS]\n";
    for (const auto& ip : getBlockedIPs()) {
        file << ip << "\n";
    }
    
    // Save blocked apps
    file << "\n[BLOCKED_APPS]\n";
    for (const auto& app : getBlockedApps()) {
        file << appTypeToString(app) << "\n";
    }
    
    // Save blocked domains
    file << "\n[BLOCKED_DOMAINS]\n";
    for (const auto& domain : getBlockedDomains()) {
        file << domain << "\n";
    }
    
    // Save blocked ports
    file << "\n[BLOCKED_PORTS]\n";
    {
        std::lock_guard<std::mutex> lock(port_mutex_);
        for (uint16_t port : blocked_ports_) {
            file << port << "\n";
        }
    }
    
    file.close();
    if (file.fail()) return false;
    std::cout << "[RuleManager] Rules saved to: " << filename << std::endl;
    return true;
}

bool RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    std::unordered_set<uint32_t> staged_ips;
    std::unordered_set<AppType> staged_apps;
    std::unordered_set<std::string> staged_domains;
    std::vector<std::string> staged_patterns;
    std::unordered_set<uint16_t> staged_ports;
    std::string line;
    std::string current_section;

    while (std::getline(file, line)) {
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] == '#' || line[first] == ';') continue;
        const auto last = line.find_last_not_of(" \t\r\n");
        line = line.substr(first, last - first + 1);

        if (line.front() == '[' && line.back() == ']') {
            current_section = line;
            if (current_section != "[BLOCKED_IPS]" && current_section != "[BLOCKED_APPS]" &&
                current_section != "[BLOCKED_DOMAINS]" && current_section != "[BLOCKED_PORTS]") {
                return false;
            }
            continue;
        }

        if (current_section == "[BLOCKED_IPS]") {
            const auto ip = parseIP(line);
            if (!ip) return false;
            staged_ips.insert(*ip);
        } else if (current_section == "[BLOCKED_APPS]") {
            bool found = false;
            for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
                if (appTypeToString(static_cast<AppType>(i)) == line) {
                    staged_apps.insert(static_cast<AppType>(i));
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        } else if (current_section == "[BLOCKED_DOMAINS]") {
            std::string normalized = line;
            std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            const auto wildcard = normalized.find('*');
            if (wildcard != std::string::npos &&
                (wildcard != 0 || normalized.size() < 3 || normalized[1] != '.')) {
                return false;
            }
            if (wildcard == std::string::npos) staged_domains.insert(std::move(normalized));
            else staged_patterns.push_back(std::move(normalized));
        } else if (current_section == "[BLOCKED_PORTS]") {
            if (line.empty()) return false;
            uint32_t port = 0;
            for (char c : line) {
                if (c < '0' || c > '9') return false;
                port = port * 10 + static_cast<uint32_t>(c - '0');
                if (port > std::numeric_limits<uint16_t>::max()) return false;
            }
            staged_ports.insert(static_cast<uint16_t>(port));
        } else {
            return false;
        }
    }

    if (file.bad()) return false;
    {
        std::scoped_lock lock(ip_mutex_, app_mutex_, domain_mutex_, port_mutex_);
        blocked_ips_.swap(staged_ips);
        blocked_apps_.swap(staged_apps);
        blocked_domains_.swap(staged_domains);
        domain_patterns_.swap(staged_patterns);
        blocked_ports_.swap(staged_ports);
    }
    std::cout << "[RuleManager] Rules loaded from: " << filename << std::endl;
    return true;
}

void RuleManager::clearAll() {
    {
        std::unique_lock<std::mutex> lock(ip_mutex_);
        blocked_ips_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(app_mutex_);
        blocked_apps_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(domain_mutex_);
        blocked_domains_.clear();
        domain_patterns_.clear();
    }
    {
        std::unique_lock<std::mutex> lock(port_mutex_);
        blocked_ports_.clear();
    }
    std::cout << "[RuleManager] All rules cleared" << std::endl;
}

RuleManager::RuleStats RuleManager::getStats() const {
    RuleStats stats;
    
    {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        stats.blocked_ips = blocked_ips_.size();
    }
    {
        std::lock_guard<std::mutex> lock(app_mutex_);
        stats.blocked_apps = blocked_apps_.size();
    }
    {
        std::lock_guard<std::mutex> lock(domain_mutex_);
        stats.blocked_domains = blocked_domains_.size() + domain_patterns_.size();
    }
    {
        std::lock_guard<std::mutex> lock(port_mutex_);
        stats.blocked_ports = blocked_ports_.size();
    }
    
    return stats;
}

} // namespace DPI
