#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace DPI
{

    std::string FiveTuple::toString() const
    {
        std::ostringstream ss;

        // Format IP addresses
        auto formatIP = [](uint32_t ip)
        {
            std::ostringstream s;
            s << ((ip >> 0) & 0xFF) << "."
              << ((ip >> 8) & 0xFF) << "."
              << ((ip >> 16) & 0xFF) << "."
              << ((ip >> 24) & 0xFF);
            return s.str();
        };

        ss << formatIP(src_ip) << ":" << src_port
           << " -> "
           << formatIP(dst_ip) << ":" << dst_port
           << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP"
                                                              : "?")
           << ")";

        return ss.str();
    }

    std::string appTypeToString(AppType type)
    {
        switch (type)
        {
        case AppType::UNKNOWN:
            return "Unknown";
        case AppType::HTTP:
            return "HTTP";
        case AppType::HTTPS:
            return "HTTPS";
        case AppType::DNS:
            return "DNS";
        case AppType::TLS:
            return "TLS";
        case AppType::QUIC:
            return "QUIC";
        case AppType::GOOGLE:
            return "Google";
        case AppType::FACEBOOK:
            return "Facebook";
        case AppType::YOUTUBE:
            return "YouTube";
        case AppType::TWITTER:
            return "Twitter/X";
        case AppType::INSTAGRAM:
            return "Instagram";
        case AppType::NETFLIX:
            return "Netflix";
        case AppType::AMAZON:
            return "Amazon";
        case AppType::MICROSOFT:
            return "Microsoft";
        case AppType::APPLE:
            return "Apple";
        case AppType::WHATSAPP:
            return "WhatsApp";
        case AppType::TELEGRAM:
            return "Telegram";
        case AppType::TIKTOK:
            return "TikTok";
        case AppType::SPOTIFY:
            return "Spotify";
        case AppType::ZOOM:
            return "Zoom";
        case AppType::DISCORD:
            return "Discord";
        case AppType::GITHUB:
            return "GitHub";
        case AppType::CLOUDFLARE:
            return "Cloudflare";
        default:
            return "Unknown";
        }
    }

    // Map hostnames using DNS label boundaries to avoid substring false positives.
    AppType sniToAppType(const std::string &sni)
    {
        if (sni.empty()) return AppType::UNKNOWN;

        std::string host = sni;
        std::transform(host.begin(), host.end(), host.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        while (!host.empty() && host.back() == '.') host.pop_back();

        const auto matches = [&host](std::initializer_list<const char*> domains) {
            for (const char* domain : domains) {
                const std::string suffix(domain);
                if (host == suffix || (host.size() > suffix.size() &&
                    host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0 &&
                    host[host.size() - suffix.size() - 1] == '.')) return true;
            }
            return false;
        };

        if (matches({"youtube.com", "youtube-nocookie.com", "youtu.be", "ytimg.com"})) return AppType::YOUTUBE;
        if (matches({"google.com", "gstatic.com", "googleapis.com", "ggpht.com", "gvt1.com"})) return AppType::GOOGLE;
        if (matches({"facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "meta.com"})) return AppType::FACEBOOK;
        if (matches({"instagram.com", "cdninstagram.com"})) return AppType::INSTAGRAM;
        if (matches({"whatsapp.com", "whatsapp.net", "wa.me"})) return AppType::WHATSAPP;
        if (matches({"twitter.com", "twimg.com", "x.com", "t.co"})) return AppType::TWITTER;
        if (matches({"netflix.com", "nflxvideo.net", "nflximg.net"})) return AppType::NETFLIX;
        if (matches({"amazon.com", "amazonaws.com"})) return AppType::AMAZON;
        if (matches({"microsoft.com", "msn.com", "office.com", "azure.com", "live.com", "outlook.com", "bing.com"})) return AppType::MICROSOFT;
        if (matches({"apple.com", "icloud.com", "mzstatic.com", "itunes.apple.com"})) return AppType::APPLE;
        if (matches({"telegram.org", "t.me"})) return AppType::TELEGRAM;
        if (matches({"tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com"})) return AppType::TIKTOK;
        if (matches({"spotify.com", "scdn.co"})) return AppType::SPOTIFY;
        if (matches({"zoom.us", "zoom.com"})) return AppType::ZOOM;
        if (matches({"discord.com", "discordapp.com"})) return AppType::DISCORD;
        if (matches({"github.com", "githubusercontent.com"})) return AppType::GITHUB;
        if (matches({"cloudflare.com", "cloudflare-dns.com"})) return AppType::CLOUDFLARE;

        return AppType::HTTPS;
    }

} // namespace DPI
