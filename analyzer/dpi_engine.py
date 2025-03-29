from collections import defaultdict
import dpkt
import socket

class DPIAnalyzer:
    def __init__(self):
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.http_requests = []
        self.dns_queries = []
        
    def analyze_packet(self, packet):
        """Analyze a single packet with DPI"""
        try:
            # Basic protocol analysis
            if hasattr(packet, 'transport_layer'):
                self.protocol_stats[packet.transport_layer] += 1
            
            # IP analysis
            if hasattr(packet, 'ip'):
                self.ip_stats[packet.ip.src] += 1
                self.ip_stats[packet.ip.dst] += 1
                
            # Port analysis
            if hasattr(packet, 'tcp'):
                self.port_stats[packet.tcp.srcport] += 1
                self.port_stats[packet.tcp.dstport] += 1
            elif hasattr(packet, 'udp'):
                self.port_stats[packet.udp.srcport] += 1
                self.port_stats[packet.udp.dstport] += 1
                
            # HTTP analysis
            if hasattr(packet, 'http'):
                self._analyze_http(packet)
                
            # DNS analysis
            if hasattr(packet, 'dns'):
                self._analyze_dns(packet)
                
        except AttributeError as e:
            pass
            
    def _analyze_http(self, packet):
        """Extract HTTP request information"""
        http_layer = packet.http
        request = {
            'method': getattr(http_layer, 'request_method', ''),
            'uri': getattr(http_layer, 'request_uri', ''),
            'host': getattr(http_layer, 'host', ''),
            'user_agent': getattr(http_layer, 'user_agent', ''),
            'timestamp': packet.sniff_time.isoformat()
        }
        self.http_requests.append(request)
        
    def _analyze_dns(self, packet):
        """Extract DNS query information"""
        if packet.dns.qry_name:
            query = {
                'query': packet.dns.qry_name,
                'type': packet.dns.qry_type,
                'response': bool(packet.dns.flags_response),
                'timestamp': packet.sniff_time.isoformat()
            }
            self.dns_queries.append(query)
            
    def get_protocol_statistics(self):
        """Get protocol distribution statistics"""
        return dict(self.protocol_stats)
        
    def get_ip_statistics(self):
        """Get IP traffic statistics"""
        return dict(self.ip_stats)
        
    def get_port_statistics(self):
        """Get port usage statistics"""
        return dict(self.port_stats)
