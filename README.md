# Network Packet Analyzer with Deep Packet Inspection (DPI)

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A sophisticated Python-based network traffic analysis tool featuring deep packet inspection, flow analysis, and visualization capabilities. Ideal for network monitoring, security analysis, and troubleshooting.

## Key Features

- **Live Packet Capture**: Capture traffic from any network interface
- **PCAP Analysis**: Process existing packet capture files
- **Deep Packet Inspection**:
  - Protocol classification (TCP, UDP, ICMP, etc.)
  - HTTP request/response analysis
  - DNS query inspection
  - IP and port statistics
- **Advanced Traffic Analysis**:
  - Flow analysis (conversations between hosts)
  - Anomaly detection (port scans, high-volume flows)
  - Timeline reconstruction
- **Visualization**:
  - Protocol distribution charts
  - Top talkers visualization
  - Port usage heatmaps
  - Conversation graphs
- **Extensible Architecture**: Easy to add new protocol analyzers

## Installation

### Prerequisites

- Python 3.7 or higher
- TShark/Wireshark (for full packet capture functionality)
- Root/Administrator privileges (for live capture)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/InfosecSamurai/packet-analyzer.git
   cd packet-analyzer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Install Wireshark/TShark for full functionality:
   - Linux: `sudo apt-get install wireshark`
   - macOS: `brew install wireshark`
   - Windows: Download from [wireshark.org](https://www.wireshark.org)

## Usage

### Basic Capture and Analysis

```python
from analyzer.packet_capture import PacketCapture
from analyzer.dpi_engine import DPIAnalyzer

# Initialize components
capture = PacketCapture(interface='eth0')
dpi = DPIAnalyzer()

# Capture 100 packets
packets = capture.start_live_capture(packet_count=100)

# Analyze each packet
for packet in packets:
    dpi.analyze_packet(packet)

# View results
print("Protocol Statistics:", dpi.get_protocol_statistics())
print("Top IPs:", dpi.get_ip_statistics())
```

### Advanced Flow Analysis

```python
from analyzer.packet_analysis import PacketAnalyzer

analyzer = PacketAnalyzer()
flow_stats = analyzer.analyze_flow(packets)
anomalies = analyzer.detect_anomalies(packets)

print("Flow Statistics:", flow_stats)
print("Potential Anomalies:", anomalies)
```

### Command Line Interface

The package includes a basic CLI interface:

```bash
python -m analyzer.cli --interface eth0 --count 200 --output report.html
```

(Note: You'll need to implement the CLI module based on the provided core functionality)

## Documentation

### Core Modules

1. **Packet Capture (`packet_capture.py`)**
   - `LiveCapture`: Capture packets from network interfaces
   - `FileCapture`: Analyze existing PCAP files
   - Supports BPF filters for selective capture

2. **DPI Engine (`dpi_engine.py`)**
   - Protocol identification
   - Application layer analysis (HTTP, DNS)
   - Statistical aggregation

3. **Packet Analysis (`packet_analysis.py`)**
   - Flow analysis
   - Anomaly detection
   - Conversation tracking

4. **Visualization (`visualization.py`)**
   - Matplotlib-based charts
   - Network graphs
   - Timeline visualization

### Example Use Cases

1. **Network Monitoring**:
   ```python
   # Monitor HTTP traffic on port 80
   capture = PacketCapture(display_filter='tcp port 80')
   ```

2. **Security Analysis**:
   ```python
   # Detect port scanning activity
   anomalies = analyzer.detect_anomalies(packets)
   ```

3. **Troubleshooting**:
   ```python
   # Analyze retransmissions
   capture = PacketCapture(display_filter='tcp.analysis.retransmission')
   ```


### Top Conversations
```text
192.168.1.10 ↔ 8.8.8.8: 450 packets (DNS)
192.168.1.12 ↔ 151.101.1.69: 320 packets (HTTP)
192.168.1.15 ↔ 239.255.255.250: 150 packets (SSDP)
```

### Anomaly Detection Alert
```text
[WARNING] Potential port scan detected:
  Source: 192.168.1.100
  Ports scanned: 42
  Timeframe: 00:01:23
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by Wireshark and tcpdump
- Uses [PyShark](https://github.com/KimiNewt/pyshark) for packet capture
- Visualization powered by Matplotlib
