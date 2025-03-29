import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict

class TrafficVisualizer:
    @staticmethod
    def plot_protocol_distribution(protocol_stats, title="Protocol Distribution"):
        """Plot a pie chart of protocol distribution"""
        if not protocol_stats:
            print("No protocol data to visualize")
            return
            
        df = pd.DataFrame(list(protocol_stats.items()), columns=['Protocol', 'Count'])
        df.plot.pie(y='Count', labels=df['Protocol'], autopct='%1.1f%%', legend=False)
        plt.title(title)
        plt.ylabel('')
        plt.show()
        
    @staticmethod
    def plot_top_ips(ip_stats, top_n=10, title="Top IP Addresses"):
        """Plot bar chart of top IP addresses"""
        if not ip_stats:
            print("No IP data to visualize")
            return
            
        df = pd.DataFrame(list(ip_stats.items()), columns=['IP', 'Count'])
        df = df.sort_values('Count', ascending=False).head(top_n)
        df.plot.bar(x='IP', y='Count', legend=False)
        plt.title(title)
        plt.ylabel('Packet Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()
        
    @staticmethod
    def plot_port_heatmap(port_stats, title="Port Usage Heatmap"):
        """Plot heatmap of port usage"""
        if not port_stats:
            print("No port data to visualize")
            return
            
        # Categorize ports
        port_categories = defaultdict(int)
        for port, count in port_stats.items():
            try:
                port_num = int(port)
                if port_num <= 1023:
                    port_categories['Well-known'] += count
                elif 1024 <= port_num <= 49151:
                    port_categories['Registered'] += count
                else:
                    port_categories['Dynamic/Private'] += count
            except ValueError:
                port_categories['Other'] += count
                
        df = pd.DataFrame(list(port_categories.items()), columns=['Category', 'Count'])
        df.plot.bar(x='Category', y='Count', legend=False)
        plt.title(title)
        plt.ylabel('Packet Count')
        plt.show()
