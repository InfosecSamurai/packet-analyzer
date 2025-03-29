from analyzer.packet_capture import PacketCapture
from analyzer.packet_analysis import PacketAnalyzer
from analyzer.dpi_engine import DPIAnalyzer
from analyzer.visualization import TrafficVisualizer
import matplotlib.pyplot as plt

def advanced_analysis():
    # Initialize components
    capture = PacketCapture(interface='eth0')
    dpi = DPIAnalyzer()
    analyzer = PacketAnalyzer()
    
    print("Starting advanced packet capture and analysis...")
    packets = capture.start_live_capture(packet_count=500)
    
    if not packets:
        print("No packets captured")
        return
        
    # Perform deep packet inspection
    for packet in packets:
        dpi.analyze_packet(packet)
    
    # Perform advanced flow analysis
    flow_stats = analyzer.analyze_flow(packets)
    anomalies = analyzer.detect_anomalies(packets)
    conversations = analyzer.get_conversation_stats(packets)
    
    # Print summary
    print("\n=== Analysis Summary ===")
    print(f"Total packets analyzed: {len(packets)}")
    print(f"Unique flows detected: {len(flow_stats)}")
    
    # Print potential anomalies
    if anomalies['high_volume_flows']:
        print("\nHigh volume flows detected:")
        for flow in anomalies['high_volume_flows']:
            print(f"  {flow['flow']}: {flow['packet_count']} packets")
            
    if anomalies['port_scans']:
        print("\nPossible port scans detected:")
        for src, count in anomalies['port_scans'].items():
            print(f"  {src} scanned {count} ports")
    
    # Visualize top conversations
    top_conversations = sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:5]
    labels = [f"{conv[0][0]} ↔ {conv[0][1]}" for conv in top_conversations]
    values = [conv[1] for conv in top_conversations]
    
    plt.figure(figsize=(10, 6))
    plt.barh(labels, values)
    plt.title("Top 5 Host Conversations")
    plt.xlabel("Packet Count")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    advanced_analysis()
