import unittest
from unittest.mock import MagicMock
from analyzer.dpi_engine import DPIAnalyzer

class TestDPIAnalyzer(unittest.TestCase):
    def setUp(self):
        self.dpi = DPIAnalyzer()
        
    def test_tcp_analysis(self):
        # Create mock TCP packet
        packet = MagicMock()
        packet.transport_layer = 'TCP'
        packet.ip.src = '192.168.1.1'
        packet.ip.dst = '192.168.1.2'
        packet.tcp.srcport = '12345'
        packet.tcp.dstport = '80'
        
        # Analyze packet
        self.dpi.analyze_packet(packet)
        
        # Check statistics
        stats = self.dpi.get_protocol_statistics()
        self.assertEqual(stats['TCP'], 1)
        
        ip_stats = self.dpi.get_ip_statistics()
        self.assertEqual(ip_stats['192.168.1.1'], 1)
        self.assertEqual(ip_stats['192.168.1.2'], 1)
        
        port_stats = self.dpi.get_port_statistics()
        self.assertEqual(port_stats['12345'], 1)
        self.assertEqual(port_stats['80'], 1)
        
    def test_http_analysis(self):
        # Create mock HTTP packet
        packet = MagicMock()
        packet.transport_layer = 'TCP'
        packet.http.request_method = 'GET'
        packet.http.request_uri = '/index.html'
        packet.http.host = 'example.com'
        packet.http.user_agent = 'TestAgent'
        packet.sniff_time.isoformat.return_value = '2023-01-01T00:00:00'
        
        # Analyze packet
        self.dpi.analyze_packet(packet)
        
        # Check HTTP requests
        self.assertEqual(len(self.dpi.http_requests), 1)
        request = self.dpi.http_requests[0]
        self.assertEqual(request['method'], 'GET')
        self.assertEqual(request['uri'], '/index.html')
        self.assertEqual(request['host'], 'example.com')
        
    def test_dns_analysis(self):
        # Create mock DNS packet
        packet = MagicMock()
        packet.dns.qry_name = 'example.com'
        packet.dns.qry_type = 1  # A record
        packet.dns.flags_response = 0
        packet.sniff_time.isoformat.return_value = '2023-01-01T00:00:00'
        
        # Analyze packet
        self.dpi.analyze_packet(packet)
        
        # Check DNS queries
        self.assertEqual(len(self.dpi.dns_queries), 1)
        query = self.dpi.dns_queries[0]
        self.assertEqual(query['query'], 'example.com')
        self.assertEqual(query['type'], 1)
        self.assertFalse(query['response'])

if __name__ == '__main__':
    unittest.main()
