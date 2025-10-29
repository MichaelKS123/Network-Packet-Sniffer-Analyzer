# SilkPacket Pro v1.0
**Network Packet Sniffer & Analyser**  
**by Michael Semera**

---

## 🌐 Overview

SilkPacket Pro is a powerful, real-time network packet sniffer and analyser built with C++ and libpcap. It captures and dissects network traffic, providing detailed insights into Ethernet frames, IP packets, TCP/UDP segments, and application-layer protocols.

## ⚠️ IMPORTANT NOTICE

**This tool requires ROOT/ADMINISTRATOR privileges to capture network packets!**

**Legal Warning:** Only use this tool on networks you own or have explicit permission to monitor. Unauthorised packet sniffing is illegal in many jurisdictions.

---

## ✨ Features

### Core Capabilities
- **Real-time Packet Capture** - Live network traffic monitoring
- **Multi-Protocol Support** - TCP, UDP, ICMP, and more
- **Layer-by-Layer Analysis** - Ethernet, IP, Transport layer dissection
- **HTTP/HTTPS Detection** - Automatic identification of web traffic
- **Berkeley Packet Filter (BPF)** - Advanced filtering capabilities
- **Packet Logging** - Save captures to file for later analysis
- **Traffic Statistics** - Real-time packet counting and analysis
- **Source IP Tracking** - Monitor most active hosts

### Advanced Features
- MAC address extraction
- Port number analysis
- TCP flags inspection (SYN, ACK, FIN, RST, PSH)
- Sequence and acknowledgment numbers
- TTL (Time To Live) monitoring
- Packet size tracking
- Timestamp logging

---

## 🔧 Prerequisites

### Required Libraries

**On Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
sudo apt-get install build-essential
```

**On Fedora/RHEL/CentOS:**
```bash
sudo dnf install libpcap-devel
sudo dnf install gcc-c++
```

**On macOS:**
```bash
# libpcap is pre-installed on macOS
# Ensure you have Xcode Command Line Tools
xcode-select --install
```

**On Windows:**
- Download and install [WinPcap](https://www.winpcap.org/) or [Npcap](https://npcap.com/)
- Install MinGW or Visual Studio for compilation

---

## 📦 Installation

### Compilation

**Linux/macOS:**
```bash
g++ -o silkpacket silkpacket.cpp -lpcap
```

**With debugging symbols:**
```bash
g++ -g -o silkpacket silkpacket.cpp -lpcap
```

**With optimizations:**
```bash
g++ -O3 -o silkpacket silkpacket.cpp -lpcap
```

---

## 🚀 Usage

### Running the Tool

**Linux/macOS:**
```bash
sudo ./silkpacket
```

**Why sudo?** Raw socket access requires elevated privileges.

### Basic Workflow

1. **List Available Devices**
   ```
   Select option 1 to see all network interfaces
   ```

2. **Start Packet Capture**
   ```
   Select option 2
   Enter device name (e.g., eth0, wlan0, en0)
   Specify packet count (0 for unlimited)
   ```

3. **Apply Filters** (Optional)
   ```
   Select option 3 or 6 for quick filters
   Enter BPF filter expression
   ```

4. **View Statistics**
   ```
   Press Ctrl+C to stop capture
   Select option 5 to view detailed statistics
   ```

---

## 🔍 Filter Examples

SilkPacket Pro uses Berkeley Packet Filter (BPF) syntax for filtering.

### Common Filters

**Capture HTTP traffic only:**
```
tcp port 80
```

**Capture HTTPS traffic only:**
```
tcp port 443
```

**Capture all web traffic:**
```
tcp port 80 or tcp port 443
```

**Capture specific IP address:**
```
host 192.168.1.100
```

**Capture traffic from specific IP:**
```
src host 192.168.1.100
```

**Capture traffic to specific IP:**
```
dst host 192.168.1.100
```

**Capture specific network:**
```
net 192.168.1.0/24
```

**Capture TCP traffic only:**
```
tcp
```

**Capture UDP traffic only:**
```
udp
```

**Capture ICMP (ping) traffic:**
```
icmp
```

**Capture traffic on specific port:**
```
port 22
```

**Complex filter (HTTP from specific IP):**
```
tcp port 80 and src host 192.168.1.100
```

**Exclude specific traffic:**
```
not port 22
```

---

## 📊 Understanding Output

### Sample Packet Output

```
╔══════════════════════════════════════════╗
║  PACKET #1    | Size:  74   bytes        ║
║  Timestamp: 2025-10-29 14:30:45          ║
╚══════════════════════════════════════════╝

┌─── ETHERNET FRAME ───────────────────────┐
│ Source MAC:      00:1a:2b:3c:4d:5e       │
│ Destination MAC: ff:ff:ff:ff:ff:ff       │
│ Ethernet Type:   0x800                   │
├─── IP HEADER ────────────────────────────┤
│ Version:         4                       │
│ Header Length:   20 bytes                │
│ Total Length:    60 bytes                │
│ TTL:             64                      │
│ Protocol:        TCP (6)                 │
│ Source IP:       192.168.1.100           │
│ Destination IP:  142.250.185.46          │
├─── TCP HEADER ───────────────────────────┤
│ Source Port:     54321                   │
│ Dest Port:       443                     │
│ Sequence:        1234567890              │
│ Ack Number:      9876543210              │
│ Flags:           SYN ACK                 │
│ [HTTPS TRAFFIC DETECTED]                 │
└──────────────────────────────────────────┘
```

### Field Explanations

**Ethernet Frame:**
- **Source/Dest MAC** - Hardware addresses
- **Ethernet Type** - Protocol type (0x800 = IPv4)

**IP Header:**
- **Version** - IP version (4 or 6)
- **Header Length** - Size of IP header
- **Total Length** - Entire packet size
- **TTL** - Hops before packet expires
- **Protocol** - Transport layer protocol

**TCP Header:**
- **Source/Dest Port** - Application endpoints
- **Sequence** - Data stream position
- **Ack Number** - Acknowledgment of received data
- **Flags** - TCP control flags

---

## 📈 Statistics Overview

```
╔════════════════════════════════════════╗
║        PACKET STATISTICS               ║
╚════════════════════════════════════════╝
Total Packets:  150
TCP Packets:    120
UDP Packets:    25
ICMP Packets:   5
HTTP Packets:   30
HTTPS Packets:  85
Other Packets:  0

--- Top Source IPs ---
192.168.1.100: 95 packets
192.168.1.50: 30 packets
10.0.0.5: 15 packets
```

---

## 🛠️ Common Use Cases

### 1. Network Troubleshooting
Monitor connectivity issues and diagnose network problems.

**Example:**
```bash
sudo ./silkpacket
# Select device
# Capture ICMP packets to test ping connectivity
```

### 2. Security Analysis
Detect unusual traffic patterns or potential security threats.

**Example:**
```bash
# Monitor for suspicious connections
# Filter by specific ports or protocols
```

### 3. Protocol Analysis
Study how different protocols work at the packet level.

**Example:**
```bash
# Capture HTTP traffic to see headers
# Analyze TCP handshake process
```

### 4. Bandwidth Monitoring
Identify which hosts or services consume most bandwidth.

**Example:**
```bash
# Capture all traffic
# Review statistics to find top talkers
```

### 5. Web Traffic Analysis
Monitor HTTP/HTTPS connections for debugging web applications.

**Example:**
```bash
# Filter for ports 80 and 443
# Log traffic to file for analysis
```

---

## 📝 Log File Format

When logging is enabled, packets are saved in the following format:

```
=== Capture Session Started: 2025-10-29 14:30:00 ===
[2025-10-29 14:30:01] TCP | 192.168.1.100 -> 142.250.185.46 | Size: 60 bytes
[2025-10-29 14:30:01] TCP | 142.250.185.46 -> 192.168.1.100 | Size: 54 bytes
[2025-10-29 14:30:02] UDP | 192.168.1.100 -> 8.8.8.8 | Size: 72 bytes
```

---

## 🔒 Security Considerations

### Best Practices

1. **Only monitor authorized networks**
2. **Secure log files** - They may contain sensitive data
3. **Use filters** - Capture only necessary traffic
4. **Limit capture duration** - Don't run indefinitely
5. **Review privacy laws** - Know local regulations

### Privacy Notes

- Packet captures may contain sensitive information
- Passwords might be visible in cleartext protocols
- Consider encryption (HTTPS, SSH) when transmitting sensitive data
- Store logs securely and delete when no longer needed

---

## 🐛 Troubleshooting

### Common Issues

**Problem:** "Permission denied" error
```bash
# Solution: Run with sudo
sudo ./silkpacket
```

**Problem:** "No suitable device found"
```bash
# Solution: Check available devices
ip link show        # Linux
ifconfig            # macOS/BSD
```

**Problem:** "libpcap not found" during compilation
```bash
# Solution: Install libpcap development package
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo dnf install libpcap-devel    # Fedora/RHEL
```

**Problem:** No packets captured
```bash
# Check:
# 1. Interface is up and active
# 2. Filter isn't too restrictive
# 3. Traffic is actually flowing
```

**Problem:** Cannot see specific traffic
```bash
# Solution: Verify filter syntax
# Test with: tcp port 80
# Ensure traffic exists on that port
```

---

## 🎓 Technical Details

### Protocols Supported

- **Layer 2 (Data Link):** Ethernet
- **Layer 3 (Network):** IPv4, ICMP
- **Layer 4 (Transport):** TCP, UDP
- **Layer 7 (Application):** HTTP/HTTPS detection

### Packet Structure

```
┌─────────────────┐
│  Ethernet Frame │  14 bytes
├─────────────────┤
│   IP Header     │  20+ bytes
├─────────────────┤
│  TCP/UDP Header │  20/8 bytes
├─────────────────┤
│   Payload Data  │  Variable
└─────────────────┘
```

### BPF Filter Performance

- Filters are compiled to bytecode
- Executed in kernel space for efficiency
- Minimal performance impact on capture

---

## 🔄 Future Enhancements

Potential features for future versions:

- [ ] IPv6 support
- [ ] Packet payload hexdump
- [ ] DNS query analysis
- [ ] ARP traffic monitoring
- [ ] Graphical statistics
- [ ] PCAP file export
- [ ] Packet replay capability
- [ ] Real-time bandwidth graphs
- [ ] Protocol-specific parsers (HTTP headers, etc.)
- [ ] Network topology visualization

---

## 📚 Additional Resources

### Learning Materials

- **RFC 793** - TCP Protocol
- **RFC 768** - UDP Protocol
- **RFC 791** - IP Protocol
- **tcpdump.org** - BPF filter syntax
- **Wireshark** - GUI packet analyser for comparison

### Similar Tools

- **tcpdump** - Command-line packet analyzer
- **Wireshark** - Graphical network analyzer
- **tshark** - Terminal-based Wireshark
- **ngrep** - Network grep

---

## 📄 License

This project is released for educational purposes.

**Disclaimer:** The author is not responsible for misuse of this tool.

---

## 🤝 Contributing

Suggestions and improvements welcome:
- Report bugs
- Suggest features
- Improve documentation
- Add protocol support

---

## 👤 Author

**Michael Semera**
- LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)
- GitHub: [MichaelKS123](https://github.com/MichaelKS123)
- Email: michaelsemera15@gmail.com

Created as a network analysis and educational tool.

---

## 🙏 Acknowledgments

Built with:
- **libpcap** - Packet capture library
- **C++** - Programming language
- Inspired by tcpdump and Wireshark

---

## ⚖️ Legal Disclaimer

**READ CAREFULLY:**

This software is provided "as is" for **EDUCATIONAL PURPOSES ONLY**.

- **DO** use on your own networks
- **DO** use on networks with explicit permission
- **DO NOT** use for unauthorized monitoring
- **DO NOT** use to intercept private communications
- **DO NOT** use in violation of local laws

The author assumes **NO LIABILITY** for misuse of this software.

Users are responsible for complying with:
- Computer Fraud and Abuse Act (USA)
- General Data Protection Regulation (EU)
- Local privacy and cybersecurity laws

---

**Thank you for using SilkPacket Pro!**

*Monitor responsibly, analyse effectively, secure thoroughly.* 🔐

---

## 📞 Contact & Support

For questions, suggestions, or collaboration opportunities:
- Open an issue on GitHub
- Email: michaelsemera15@gmail.com
- LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)

For issues or questions:
- Review this documentation
- Check the troubleshooting section
- Ensure proper privileges and setup
- Verify libpcap installation

**Version:** 1.0  
**Last Updated:** 2023
