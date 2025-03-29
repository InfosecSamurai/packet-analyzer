from collections import defaultdict
from datetime import datetime
import dpkt
import socket

class PacketAnalyzer:
    def __init__(self):
        self.flows = defaultdict(list)
        self.conversations = defaultdict(int)
        self.timeline = []
        
    def analyze_flow(self, packets):
        """
        Analyze packet flows between hosts
        :param packets: List of packets to analyze
        :return: Dictionary of flow statistics
        """
        flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None,
            'protocols': set()
        })
        
        for packet in packets:
            try:
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    flow_key = (src, dst)
                    
                    # Update flow statistics
                    flow = flow_stats[flow_key]
                    flow['packet_count'] += 1
                    if hasattr(packet, packet.transport_layer):
                        flow['byte_count'] += int(getattr(packet, packet.transport_layer).length)
                        flow['protocols'].add(packet.transport_layer)
                    
                    # Update timeline
                    timestamp = packet.sniff_time
                    self.timeline.append((timestamp, flow_key))
                    
                    # Track first and last packet times
                    if flow['start_time'] is None or timestamp < flow['start_time']:
                        flow['start_time'] = timestamp
                    if flow['end_time'] is None or timestamp > flow['end_time']:
                        flow['end_time'] = timestamp
                        
            except AttributeError:
                continue
                
        return flow_stats
        
    def detect_anomalies(self, packets, threshold=100):
        """
        Detect potential network anomalies
        :param packets: List of packets to analyze
        :param threshold: Packet count threshold for alerting
        :return: Dictionary of potential anomalies
        """
        anomalies = {
            'high_volume_flows': [],
            'port_scans': defaultdict(int),
            'possible_ddos': []
        }
        
        # Analyze flows for high volume
        flow_stats = self.analyze_flow(packets)
        for flow, stats in flow_stats.items():
            if stats['packet_count'] > threshold:
                anomalies['high_volume_flows'].append({
                    'flow': flow,
                    'packet_count': stats['packet_count'],
                    'duration': stats['end_time'] - stats['start_time']
                })
        
        # Detect port scanning patterns
        port_access = defaultdict(lambda: defaultdict(int))
        for packet in packets:
            try:
                if hasattr(packet, 'tcp'):
                    src = packet.ip.src
                    dst_port = packet.tcp.dstport
                    port_access[src][dst_port] += 1
            except AttributeError:
                continue
                
        for src, ports in port_access.items():
            if len(ports) > 10:  # More than 10 distinct ports
                anomalies['port_scans'][src] = len(ports)
                
        return anomalies
        
    def get_conversation_stats(self, packets):
        """
        Get statistics about host conversations
        :param packets: List of packets to analyze
        :return: Dictionary of conversation statistics
        """
        for packet in packets:
            try:
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    key = tuple(sorted((src, dst)))
                    self.conversations[key] += 1
            except AttributeError:
                continue
                
        return self.conversations
