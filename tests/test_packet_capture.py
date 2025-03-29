import unittest
from unittest.mock import patch, MagicMock
from analyzer.packet_capture import PacketCapture
from analyzer.utils import get_network_interfaces

class TestPacketCapture(unittest.TestCase):
    @patch('analyzer.packet_capture.pyshark.LiveCapture')
    def test_live_capture(self, mock_live_capture):
        # Setup mock
        mock_capture = MagicMock()
        mock_capture.sniff.return_value = ['pkt1', 'pkt2', 'pkt3']
        mock_live_capture.return_value = mock_capture
        
        # Test capture
        capture = PacketCapture(interface='eth0')
        packets = capture.start_live_capture(packet_count=3)
        
        # Assertions
        self.assertEqual(len(packets), 3)
        mock_live_capture.assert_called_once_with(
            interface='eth0',
            display_filter=None,
            output_file=None
        )
        mock_capture.sniff.assert_called_once_with(packet_count=3, timeout=30)
        
    @patch('analyzer.packet_capture.pyshark.FileCapture')
    def test_pcap_analysis(self, mock_file_capture):
        # Setup mock
        mock_capture = MagicMock()
        mock_capture.__iter__.return_value = ['pkt1', 'pkt2']
        mock_file_capture.return_value = mock_capture
        
        # Test PCAP analysis
        capture = PacketCapture()
        packets = capture.analyze_pcap_file('test.pcap')
        
        # Assertions
        self.assertEqual(len(packets), 2)
        mock_file_capture.assert_called_once_with(
            'test.pcap',
            display_filter=None
        )
        
    def test_interface_selection(self):
        # Test that interface selection works
        interfaces = get_network_interfaces()
        if interfaces:
            capture = PacketCapture(interface=interfaces[0])
            self.assertEqual(capture.interface, interfaces[0])

if __name__ == '__main__':
    unittest.main()
