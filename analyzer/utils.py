import psutil
import platform
import socket

def get_network_interfaces():
    """
    Get available network interfaces
    :return: List of interface names
    """
    interfaces = []
    if platform.system() == "Linux":
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces.append(interface)
    else:
        # Windows/MacOS implementation
        interfaces = list(psutil.net_if_addrs().keys())
    return interfaces

def ip_to_hostname(ip_address):
    """
    Resolve IP address to hostname
    :param ip_address: IP address to resolve
    :return: Hostname or original IP if resolution fails
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return ip_address

def is_private_ip(ip_address):
    """
    Check if IP address is private
    :param ip_address: IP address to check
    :return: Boolean indicating if IP is private
    """
    try:
        ip = list(map(int, ip_address.split('.')))
        # Check for private IP ranges
        return (ip[0] == 10) or \
               (ip[0] == 172 and 16 <= ip[1] <= 31) or \
               (ip[0] == 192 and ip[1] == 168)
    except (ValueError, IndexError):
        return False

def format_bytes(size):
    """
    Convert bytes to human-readable format
    :param size: Size in bytes
    :return: Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
