import socket
import ipaddress
import subprocess

def get_local_ip():
    # Method 1: try the Google DNS trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        pass

    # Method 2: fallback - read IP from hostname
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except OSError:
        pass

    # Method 3: fallback - parse 'ip route' directly
    try:
        result = subprocess.check_output(["ip", "route"], text=True)
        for line in result.splitlines():
            if "src" in line:
                parts = line.split()
                src_index = parts.index("src")
                return parts[src_index + 1]
    except Exception:
        pass

    return None


def get_subnet():
    ip = get_local_ip()
    if not ip:
        return None
    network = ipaddress.IPv4Network(ip + "/24", strict=False)
    return str(network)
