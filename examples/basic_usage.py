from analyzer.packet_capture import PacketCapture
from analyzer.dpi_engine import DPIAnalyzer
from analyzer.visualization import TrafficVisualizer

def main():
    # Initialize components
    capture = PacketCapture(interface='eth0', display_filter='tcp')
    dpi = DPIAnalyzer()
    
    # Capture 100 packets
    print("Starting packet capture...")
    packets = capture.start_live_capture(packet_count=100)
    
    if packets:
        # Analyze each packet
        for packet in packets:
            dpi.analyze_packet(packet)
            
        # Get statistics
        protocol_stats = dpi.get_protocol_statistics()
        ip_stats = dpi.get_ip_statistics()
        port_stats = dpi.get_port_statistics()
        
        # Visualize results
        TrafficVisualizer.plot_protocol_distribution(protocol_stats)
        TrafficVisualizer.plot_top_ips(ip_stats)
        TrafficVisualizer.plot_port_heatmap(port_stats)
        
        print(f"Captured and analyzed {len(packets)} packets")
    else:
        print("No packets were captured")

if __name__ == "__main__":
    main()
