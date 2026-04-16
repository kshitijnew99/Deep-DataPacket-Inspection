// DPI Engine entrypoint compatible with older MinGW toolchains.
// Keeps the same CLI while avoiding std::thread dependencies.

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

struct Flow {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
};

class BlockingRules {
public:
    void blockIP(const std::string& ip) {
        blocked_ips.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }

    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            AppType type = static_cast<AppType>(i);
            if (appTypeToString(type) == app) {
                blocked_apps.insert(type);
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }

    void blockDomain(const std::string& domain) {
        blocked_domains.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }

    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(src_ip) > 0) return true;
        if (blocked_apps.count(app) > 0) return true;
        for (std::vector<std::string>::const_iterator it = blocked_domains.begin();
             it != blocked_domains.end(); ++it) {
            if (sni.find(*it) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;
        for (std::string::const_iterator it = ip.begin(); it != ip.end(); ++it) {
            const char c = *it;
            if (c == '.') {
                result |= (static_cast<uint32_t>(octet) << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        return result | (static_cast<uint32_t>(octet) << shift);
    }

    std::unordered_set<uint32_t> blocked_ips;
    std::unordered_set<AppType> blocked_apps;
    std::vector<std::string> blocked_domains;
};

static uint32_t parseIPv4(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;
    for (std::string::const_iterator it = ip.begin(); it != ip.end(); ++it) {
        const char c = *it;
        if (c == '.') {
            result |= (static_cast<uint32_t>(octet) << shift);
            shift += 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    return result | (static_cast<uint32_t>(octet) << shift);
}

static bool computeTCPPayload(const std::vector<uint8_t>& data,
                              size_t& payload_offset,
                              size_t& payload_len) {
    const size_t eth_len = 14;
    const size_t min_ip_len = 20;
    const size_t min_tcp_len = 20;

    if (data.size() < eth_len + min_ip_len + min_tcp_len) {
        return false;
    }

    const size_t ip_offset = eth_len;
    const uint8_t ip_ihl = data[ip_offset] & 0x0F;
    const size_t ip_len = static_cast<size_t>(ip_ihl) * 4;
    if (ip_len < min_ip_len) {
        return false;
    }

    const size_t tcp_offset = ip_offset + ip_len;
    if (tcp_offset + 12 >= data.size()) {
        return false;
    }

    const uint8_t tcp_doff = (data[tcp_offset + 12] >> 4) & 0x0F;
    const size_t tcp_len = static_cast<size_t>(tcp_doff) * 4;
    if (tcp_len < min_tcp_len) {
        return false;
    }

    payload_offset = tcp_offset + tcp_len;
    if (payload_offset > data.size()) {
        return false;
    }

    payload_len = data.size() - payload_offset;
    return true;
}

static void printUsage(const char* prog) {
    std::cout << "\n"
              << "DPI Engine - Deep Packet Inspection System\n"
              << "==========================================\n\n"
              << "Usage: " << prog << " <input.pcap> <output.pcap> [options]\n\n"
              << "Options:\n"
              << "  --block-ip <ip>        Block traffic from source IP\n"
              << "  --block-app <app>      Block application (YouTube, Facebook, etc.)\n"
              << "  --block-domain <dom>   Block domain (substring match)\n\n"
              << "Example:\n"
              << "  " << prog
              << " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    const std::string input_file = argv[1];
    const std::string output_file = argv[2];

    BlockingRules rules;
    for (int i = 3; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) {
            rules.blockIP(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
            rules.blockApp(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.blockDomain(argv[++i]);
        }
    }

    std::cout << "\n"
              << "====================================\n"
              << "DPI ENGINE (Compatibility Mode)\n"
              << "====================================\n\n";

    PcapReader reader;
    if (!reader.open(input_file)) {
        return 1;
    }

    std::ofstream output(output_file.c_str(), std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Cannot open output file\n";
        reader.close();
        return 1;
    }

    const PcapGlobalHeader& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    std::unordered_map<AppType, uint64_t> app_stats;

    RawPacket raw;
    ParsedPacket parsed;

    std::cout << "[DPI] Processing packets...\n";

    while (reader.readNextPacket(raw)) {
        total_packets++;

        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        FiveTuple tuple;
        tuple.src_ip = parseIPv4(parsed.src_ip);
        tuple.dst_ip = parseIPv4(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        Flow& flow = flows[tuple];
        if (flow.packets == 0) {
            flow.tuple = tuple;
        }
        flow.packets++;
        flow.bytes += raw.data.size();

        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 443) {
            size_t payload_offset = 0;
            size_t payload_len = 0;
            if (computeTCPPayload(raw.data, payload_offset, payload_len) && payload_len > 5) {
                const uint8_t* payload = raw.data.data() + payload_offset;
                std::optional<std::string> sni = SNIExtractor::extract(payload, payload_len);
                if (sni) {
                    flow.sni = *sni;
                    flow.app_type = sniToAppType(*sni);
                }
            }
        }

        if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP) &&
            flow.sni.empty() && parsed.has_tcp && parsed.dest_port == 80) {
            size_t payload_offset = 0;
            size_t payload_len = 0;
            if (computeTCPPayload(raw.data, payload_offset, payload_len)) {
                const uint8_t* payload = raw.data.data() + payload_offset;
                std::optional<std::string> host = HTTPHostExtractor::extract(payload, payload_len);
                if (host) {
                    flow.sni = *host;
                    flow.app_type = sniToAppType(*host);
                }
            }
        }

        if (flow.app_type == AppType::UNKNOWN &&
            (parsed.dest_port == 53 || parsed.src_port == 53)) {
            flow.app_type = AppType::DNS;
        }

        if (flow.app_type == AppType::UNKNOWN) {
            if (parsed.dest_port == 443) flow.app_type = AppType::HTTPS;
            else if (parsed.dest_port == 80) flow.app_type = AppType::HTTP;
        }

        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni);
            if (flow.blocked) {
                std::cout << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                          << " (" << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) std::cout << ": " << flow.sni;
                std::cout << ")\n";
            }
        }

        app_stats[flow.app_type]++;

        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;

            PcapPacketHeader pkt_hdr;
            pkt_hdr.ts_sec = raw.header.ts_sec;
            pkt_hdr.ts_usec = raw.header.ts_usec;
            pkt_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
            pkt_hdr.orig_len = static_cast<uint32_t>(raw.data.size());
            output.write(reinterpret_cast<const char*>(&pkt_hdr), sizeof(pkt_hdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }

    reader.close();
    output.close();

    std::cout << "\n====================================\n"
              << "PROCESSING REPORT\n"
              << "====================================\n"
              << "Total Packets: " << total_packets << "\n"
              << "Forwarded:     " << forwarded << "\n"
              << "Dropped:       " << dropped << "\n"
              << "Active Flows:  " << flows.size() << "\n\n";

    std::vector<std::pair<AppType, uint64_t> > sorted_apps(app_stats.begin(), app_stats.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const std::pair<AppType, uint64_t>& a,
                 const std::pair<AppType, uint64_t>& b) {
                  return a.second > b.second;
              });

    std::cout << "Application Breakdown:\n";
    for (std::vector<std::pair<AppType, uint64_t> >::const_iterator it = sorted_apps.begin();
         it != sorted_apps.end(); ++it) {
        const AppType app = it->first;
        const uint64_t count = it->second;
        const double pct = total_packets == 0 ? 0.0 : (100.0 * count / total_packets);
        std::cout << "  " << std::setw(15) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << count
                  << "  " << std::fixed << std::setprecision(1) << pct << "%\n";
    }

    std::unordered_map<std::string, AppType> unique_snis;
    for (std::unordered_map<FiveTuple, Flow, FiveTupleHash>::const_iterator it = flows.begin();
         it != flows.end(); ++it) {
        const Flow& flow = it->second;
        if (!flow.sni.empty()) {
            unique_snis[flow.sni] = flow.app_type;
        }
    }

    if (!unique_snis.empty()) {
        std::cout << "\nDetected Applications/Domains:\n";
        for (std::unordered_map<std::string, AppType>::const_iterator it = unique_snis.begin();
             it != unique_snis.end(); ++it) {
            std::cout << "  - " << it->first << " -> " << appTypeToString(it->second) << "\n";
        }
    }

    std::cout << "\nOutput written to: " << output_file << "\n";
    return 0;
}
