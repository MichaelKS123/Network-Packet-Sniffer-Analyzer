#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <map>

using namespace std;

class PacketStats {
public:
    int totalPackets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int icmpPackets = 0;
    int httpPackets = 0;
    int httpsPackets = 0;
    int otherPackets = 0;
    map<string, int> ipSources;
    
    void display() {
        cout << "\n╔════════════════════════════════════════╗\n";
        cout << "║        PACKET STATISTICS               ║\n";
        cout << "╚════════════════════════════════════════╝\n";
        cout << "Total Packets:  " << totalPackets << endl;
        cout << "TCP Packets:    " << tcpPackets << endl;
        cout << "UDP Packets:    " << udpPackets << endl;
        cout << "ICMP Packets:   " << icmpPackets << endl;
        cout << "HTTP Packets:   " << httpPackets << endl;
        cout << "HTTPS Packets:  " << httpsPackets << endl;
        cout << "Other Packets:  " << otherPackets << endl;
        
        if (!ipSources.empty()) {
            cout << "\n--- Top Source IPs ---\n";
            int count = 0;
            for (auto it = ipSources.rbegin(); it != ipSources.rend() && count < 5; ++it, ++count) {
                cout << it->first << ": " << it->second << " packets\n";
            }
        }
    }
};

class SilkPacketPro {
private:
    pcap_t* handle;
    string filterExpression;
    bool logToFile;
    ofstream logFile;
    PacketStats stats;
    bool isRunning;
    
public:
    SilkPacketPro() : handle(nullptr), logToFile(false), isRunning(false) {}
    
    ~SilkPacketPro() {
        if (handle) {
            pcap_close(handle);
        }
        if (logFile.is_open()) {
            logFile.close();
        }
    }
    
    void displayTitle() {
        cout << "\n";
        cout << "╔══════════════════════════════════════════════════════════╗\n";
        cout << "║                                                          ║\n";
        cout << "║              SILKPACKET PRO v1.0                         ║\n";
        cout << "║          Network Packet Sniffer & Analyzer               ║\n";
        cout << "║                   by Michael Semera                      ║\n";
        cout << "║                                                          ║\n";
        cout << "╚══════════════════════════════════════════════════════════╝\n";
    }
    
    void listDevices() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs, *d;
        
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            cerr << "Error finding devices: " << errbuf << endl;
            return;
        }
        
        cout << "\n╔════════════════════════════════════════╗\n";
        cout << "║     AVAILABLE NETWORK DEVICES          ║\n";
        cout << "╚════════════════════════════════════════╝\n";
        
        int i = 1;
        for (d = alldevs; d != nullptr; d = d->next) {
            cout << i++ << ". " << d->name;
            if (d->description) {
                cout << " (" << d->description << ")";
            }
            cout << endl;
        }
        
        pcap_freealldevs(alldevs);
    }
    
    bool openDevice(const string& deviceName) {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
        
        if (handle == nullptr) {
            cerr << "Error opening device: " << errbuf << endl;
            return false;
        }
        
        cout << "✓ Successfully opened device: " << deviceName << endl;
        return true;
    }
    
    bool setFilter(const string& filter) {
        if (!handle) {
            cerr << "Device not opened!" << endl;
            return false;
        }
        
        struct bpf_program fp;
        bpf_u_int32 net, mask;
        char errbuf[PCAP_ERRBUF_SIZE];
        
        if (pcap_lookupnet(pcap_datalink_name_to_val("EN10MB"), &net, &mask, errbuf) == -1) {
            net = 0;
            mask = 0;
        }
        
        if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
            cerr << "Error compiling filter: " << pcap_geterr(handle) << endl;
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error setting filter: " << pcap_geterr(handle) << endl;
            return false;
        }
        
        pcap_freecode(&fp);
        filterExpression = filter;
        cout << "✓ Filter applied: " << filter << endl;
        return true;
    }
    
    void enableLogging(const string& filename) {
        logFile.open(filename, ios::app);
        if (logFile.is_open()) {
            logToFile = true;
            time_t now = time(0);
            logFile << "\n=== Capture Session Started: " << ctime(&now) << "===\n";
            cout << "✓ Logging enabled to: " << filename << endl;
        }
    }
    
    string getTimestamp() {
        time_t now = time(0);
        struct tm* timeinfo = localtime(&now);
        char buffer[80];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return string(buffer);
    }
    
    void processEthernet(const u_char* packet, int packetSize) {
        struct ether_header* eth = (struct ether_header*)packet;
        
        cout << "\n┌─── ETHERNET FRAME ───────────────────────┐\n";
        cout << "│ Source MAC:      ";
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_shost[i]);
            if (i < 5) cout << ":";
        }
        cout << "       │\n│ Destination MAC: ";
        for (int i = 0; i < 6; i++) {
            printf("%02x", eth->ether_dhost[i]);
            if (i < 5) cout << ":";
        }
        cout << "       │\n";
        cout << "│ Ethernet Type:   0x" << hex << ntohs(eth->ether_type) << dec << "                    │\n";
    }
    
    void processIP(const u_char* packet) {
        struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));
        
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(iph->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dstIP, INET_ADDRSTRLEN);
        
        cout << "├─── IP HEADER ────────────────────────────┤\n";
        cout << "│ Version:         " << (int)iph->ip_v << "                            │\n";
        cout << "│ Header Length:   " << (int)iph->ip_hl * 4 << " bytes                     │\n";
        cout << "│ Total Length:    " << ntohs(iph->ip_len) << " bytes                   │\n";
        cout << "│ TTL:             " << (int)iph->ip_ttl << "                            │\n";
        cout << "│ Protocol:        ";
        
        string protocol;
        switch (iph->ip_p) {
            case IPPROTO_TCP:
                cout << "TCP (6)";
                protocol = "TCP";
                stats.tcpPackets++;
                break;
            case IPPROTO_UDP:
                cout << "UDP (17)";
                protocol = "UDP";
                stats.udpPackets++;
                break;
            case IPPROTO_ICMP:
                cout << "ICMP (1)";
                protocol = "ICMP";
                stats.icmpPackets++;
                break;
            default:
                cout << "Other (" << (int)iph->ip_p << ")";
                protocol = "Other";
                stats.otherPackets++;
        }
        cout << "                      │\n";
        cout << "│ Source IP:       " << setw(15) << left << srcIP << "              │\n";
        cout << "│ Destination IP:  " << setw(15) << left << dstIP << "              │\n";
        
        stats.ipSources[srcIP]++;
        
        if (logToFile) {
            logFile << "[" << getTimestamp() << "] " << protocol << " | "
                   << srcIP << " -> " << dstIP << " | Size: " << ntohs(iph->ip_len) << " bytes\n";
        }
        
        if (iph->ip_p == IPPROTO_TCP) {
            processTCP(packet, iph);
        } else if (iph->ip_p == IPPROTO_UDP) {
            processUDP(packet, iph);
        }
    }
    
    void processTCP(const u_char* packet, struct ip* iph) {
        struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + iph->ip_hl * 4);
        
        int srcPort = ntohs(tcph->th_sport);
        int dstPort = ntohs(tcph->th_dport);
        
        cout << "├─── TCP HEADER ───────────────────────────┤\n";
        cout << "│ Source Port:     " << setw(5) << srcPort << "                        │\n";
        cout << "│ Dest Port:       " << setw(5) << dstPort << "                        │\n";
        cout << "│ Sequence:        " << ntohl(tcph->th_seq) << "                 │\n";
        cout << "│ Ack Number:      " << ntohl(tcph->th_ack) << "                 │\n";
        cout << "│ Flags:           ";
        
        if (tcph->th_flags & TH_SYN) cout << "SYN ";
        if (tcph->th_flags & TH_ACK) cout << "ACK ";
        if (tcph->th_flags & TH_FIN) cout << "FIN ";
        if (tcph->th_flags & TH_RST) cout << "RST ";
        if (tcph->th_flags & TH_PUSH) cout << "PSH ";
        
        cout << "                   │\n";
        
        // Detect HTTP/HTTPS
        if (srcPort == 80 || dstPort == 80) {
            cout << "│ [HTTP TRAFFIC DETECTED]                  │\n";
            stats.httpPackets++;
        } else if (srcPort == 443 || dstPort == 443) {
            cout << "│ [HTTPS TRAFFIC DETECTED]                 │\n";
            stats.httpsPackets++;
        }
    }
    
    void processUDP(const u_char* packet, struct ip* iph) {
        struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct ether_header) + iph->ip_hl * 4);
        
        cout << "├─── UDP HEADER ───────────────────────────┤\n";
        cout << "│ Source Port:     " << ntohs(udph->uh_sport) << "                        │\n";
        cout << "│ Dest Port:       " << ntohs(udph->uh_dport) << "                        │\n";
        cout << "│ Length:          " << ntohs(udph->uh_ulen) << " bytes                   │\n";
    }
    
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        SilkPacketPro* sniffer = (SilkPacketPro*)userData;
        
        sniffer->stats.totalPackets++;
        
        cout << "\n╔══════════════════════════════════════════╗\n";
        cout << "║  PACKET #" << setw(4) << sniffer->stats.totalPackets 
             << " | Size: " << setw(5) << pkthdr->len << " bytes        ║\n";
        cout << "║  Timestamp: " << sniffer->getTimestamp() << "      ║\n";
        cout << "╚══════════════════════════════════════════╝\n";
        
        sniffer->processEthernet(packet, pkthdr->len);
        sniffer->processIP(packet);
        
        cout << "└──────────────────────────────────────────┘\n";
    }
    
    void startCapture(int packetCount = 0) {
        if (!handle) {
            cerr << "Device not opened!" << endl;
            return;
        }
        
        cout << "\n🔍 Starting packet capture...\n";
        cout << "Press Ctrl+C to stop\n";
        cout << string(50, '=') << endl;
        
        isRunning = true;
        pcap_loop(handle, packetCount, packetHandler, (u_char*)this);
    }
    
    PacketStats& getStats() {
        return stats;
    }
};

void displayMenu() {
    cout << "\n╔════════════════════════════════════════╗\n";
    cout << "║           MAIN MENU                    ║\n";
    cout << "╚════════════════════════════════════════╝\n";
    cout << " 1. List Network Devices\n";
    cout << " 2. Start Packet Capture\n";
    cout << " 3. Set Filter (BPF)\n";
    cout << " 4. Enable Logging\n";
    cout << " 5. View Statistics\n";
    cout << " 6. Quick Filters\n";
    cout << " 7. About\n";
    cout << " 8. Exit\n";
    cout << "════════════════════════════════════════\n";
    cout << "Enter choice: ";
}

void displayQuickFilters() {
    cout << "\n╔════════════════════════════════════════╗\n";
    cout << "║        QUICK FILTERS                   ║\n";
    cout << "╚════════════════════════════════════════╝\n";
    cout << " 1. HTTP traffic only (port 80)\n";
    cout << " 2. HTTPS traffic only (port 443)\n";
    cout << " 3. TCP traffic only\n";
    cout << " 4. UDP traffic only\n";
    cout << " 5. ICMP traffic only\n";
    cout << " 6. Specific IP address\n";
    cout << " 7. Custom filter\n";
    cout << " 8. Clear filter (capture all)\n";
    cout << "════════════════════════════════════════\n";
}

void displayAbout() {
    cout << "\n╔══════════════════════════════════════════════════════════╗\n";
    cout << "║            ABOUT SILKPACKET PRO v1.0                     ║\n";
    cout << "╚══════════════════════════════════════════════════════════╝\n";
    cout << "\nSilkPacket Pro is a powerful network packet sniffer and\n";
    cout << "analyzer built with libpcap for real-time traffic monitoring.\n\n";
    cout << "Features:\n";
    cout << "  • Real-time packet capture and analysis\n";
    cout << "  • Support for TCP, UDP, ICMP protocols\n";
    cout << "  • HTTP/HTTPS traffic detection\n";
    cout << "  • Berkeley Packet Filter (BPF) support\n";
    cout << "  • Packet logging to file\n";
    cout << "  • Traffic statistics and analysis\n";
    cout << "  • MAC and IP address tracking\n\n";
    cout << "Created by: Michael\n";
    cout << "Version: 1.0\n";
    cout << "Built with: libpcap\n\n";
    cout << "⚠️  IMPORTANT: Requires root/administrator privileges!\n";
    cout << "Use responsibly and only on authorized networks.\n";
}

int main() {
    SilkPacketPro sniffer;
    int choice;
    string deviceName, filter, filename, ipAddr;
    int packetCount;
    
    sniffer.displayTitle();
    cout << "\n⚠️  WARNING: This tool requires root/administrator privileges!\n";
    cout << "Make sure you have permission to capture network traffic.\n";
    
    while (true) {
        displayMenu();
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
            case 1:
                sniffer.listDevices();
                break;
                
            case 2:
                cout << "\nEnter device name (e.g., eth0, wlan0, en0): ";
                getline(cin, deviceName);
                
                if (sniffer.openDevice(deviceName)) {
                    cout << "Enter number of packets to capture (0 for unlimited): ";
                    cin >> packetCount;
                    sniffer.startCapture(packetCount);
                    sniffer.getStats().display();
                }
                break;
                
            case 3:
                cout << "\nEnter BPF filter expression: ";
                getline(cin, filter);
                sniffer.setFilter(filter);
                break;
                
            case 4:
                cout << "\nEnter log filename: ";
                getline(cin, filename);
                sniffer.enableLogging(filename);
                break;
                
            case 5:
                sniffer.getStats().display();
                break;
                
            case 6:
                displayQuickFilters();
                cout << "Enter choice: ";
                cin >> choice;
                cin.ignore();
                
                switch (choice) {
                    case 1:
                        sniffer.setFilter("tcp port 80");
                        break;
                    case 2:
                        sniffer.setFilter("tcp port 443");
                        break;
                    case 3:
                        sniffer.setFilter("tcp");
                        break;
                    case 4:
                        sniffer.setFilter("udp");
                        break;
                    case 5:
                        sniffer.setFilter("icmp");
                        break;
                    case 6:
                        cout << "Enter IP address: ";
                        getline(cin, ipAddr);
                        sniffer.setFilter("host " + ipAddr);
                        break;
                    case 7:
                        cout << "Enter custom filter: ";
                        getline(cin, filter);
                        sniffer.setFilter(filter);
                        break;
                    case 8:
                        sniffer.setFilter("");
                        cout << "✓ Filter cleared\n";
                        break;
                }
                break;
                
            case 7:
                displayAbout();
                break;
                
            case 8:
                cout << "\nThank you for using SilkPacket Pro!\n";
                cout << "Stay secure! - Michael\n\n";
                return 0;
                
            default:
                cout << "\nInvalid choice! Please try again.\n";
        }
        
        cout << "\nPress Enter to continue...";
        cin.get();
    }
    
    return 0;
}