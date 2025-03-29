import pyshark
from datetime import datetime
from .utils import get_network_interfaces

class PacketCapture:
    def __init__(self, interface=None, display_filter=None, output_file=None):
        """
        Initialize packet capture
        :param interface: Network interface to capture from
        :param display_filter: BPF filter for capture
        :param output_file: File to save captured packets
        """
        self.interface = interface or get_network_interfaces()[0]
        self.display_filter = display_filter
        self.output_file = output_file
        self.capture = None
        
    def start_live_capture(self, packet_count=100, timeout=30):
        """
        Start live packet capture
        :param packet_count: Number of packets to capture
        :param timeout: Capture timeout in seconds
        :return: List of captured packets
        """
        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=self.display_filter,
                output_file=self.output_file
            )
            
            print(f"Starting capture on interface {self.interface}...")
            packets = self.capture.sniff(packet_count=packet_count, timeout=timeout)
            return packets
            
        except Exception as e:
            print(f"Capture error: {e}")
            return None
            
    def analyze_pcap_file(self, pcap_file):
        """
        Analyze packets from a PCAP file
        :param pcap_file: Path to PCAP file
        :return: List of packets
        """
        try:
            self.capture = pyshark.FileCapture(pcap_file, display_filter=self.display_filter)
            return list(self.capture)
        except Exception as e:
            print(f"PCAP analysis error: {e}")
            return None
            
    def stop_capture(self):
        """Stop ongoing capture"""
        if self.capture:
            self.capture.close()
