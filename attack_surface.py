import nmap
import json
from database import save_scan_result

# -----------------------------
# DANGEROUS PORTS
# Ports that are inherently risky
# if found open on a device
# -----------------------------
DANGEROUS_PORTS = {
    21:   "FTP - Unencrypted file transfer",
    22:   "SSH - Remote access (verify it's intended)",
    23:   "Telnet - Unencrypted remote access (critical risk)",
    25:   "SMTP - Mail server (verify if intended)",
    53:   "DNS - Could be used for DNS tunneling",
    80:   "HTTP - Unencrypted web service",
    110:  "POP3 - Unencrypted mail retrieval",
    135:  "RPC - Windows remote procedure call",
    139:  "NetBIOS - Windows file sharing (legacy)",
    143:  "IMAP - Unencrypted mail access",
    443:  "HTTPS - Encrypted web service",
    445:  "SMB - Windows file sharing (ransomware target)",
    554:  "RTSP - Streaming (often IP cameras)",
    1433: "MSSQL - Microsoft SQL Server",
    1723: "PPTP VPN - Weak VPN protocol",
    3306: "MySQL - Database exposed to network",
    3389: "RDP - Remote Desktop (high value target)",
    5900: "VNC - Remote desktop (often unencrypted)",
    6379: "Redis - Database often left unsecured",
    8080: "HTTP Alternate - Web service on non-standard port",
    8443: "HTTPS Alternate - Encrypted web on non-standard port",
    9200: "Elasticsearch - Often left open without auth",
    27017:"MongoDB - Database often left unsecured",
}

# -----------------------------
# SEVERITY OF DANGEROUS PORTS
# -----------------------------
PORT_SEVERITY = {
    23:   "CRITICAL",
    445:  "CRITICAL",
    3389: "HIGH",
    5900: "HIGH",
    6379: "HIGH",
    9200: "HIGH",
    27017:"HIGH",
    3306: "HIGH",
    1433: "HIGH",
    21:   "MEDIUM",
    139:  "MEDIUM",
    135:  "MEDIUM",
    1723: "MEDIUM",
    80:   "LOW",
    8080: "LOW",
    554:  "LOW",
    22:   "LOW",
    25:   "LOW",
    53:   "LOW",
    110:  "LOW",
    143:  "LOW",
    443:  "LOW",
    8443: "LOW",
}

# -----------------------------
# MISCONFIGURATION CHECKS
# -----------------------------
def check_misconfigurations(open_ports, services):
    misconfigs = []

    # Telnet open — should never be open
    if 23 in open_ports:
        misconfigs.append({
            "type": "UNENCRYPTED_REMOTE_ACCESS",
            "severity": "CRITICAL",
            "detail": "Telnet (port 23) is open. Telnet transmits data in plain text including passwords. Replace with SSH immediately."
        })

    # RDP exposed
    if 3389 in open_ports:
        misconfigs.append({
            "type": "REMOTE_DESKTOP_EXPOSED",
            "severity": "HIGH",
            "detail": "RDP (port 3389) is open. Remote Desktop is a common ransomware entry point. Restrict access with firewall rules."
        })

    # SMB exposed
    if 445 in open_ports:
        misconfigs.append({
            "type": "SMB_EXPOSED",
            "severity": "CRITICAL",
            "detail": "SMB (port 445) is open. SMB is the attack vector for EternalBlue/WannaCry. Disable if not needed."
        })

    # VNC exposed
    if 5900 in open_ports:
        misconfigs.append({
            "type": "VNC_EXPOSED",
            "severity": "HIGH",
            "detail": "VNC (port 5900) is open. VNC is often unencrypted and weakly authenticated."
        })

    # Unencrypted web service
    if 80 in open_ports and 443 not in open_ports:
        misconfigs.append({
            "type": "HTTP_NO_HTTPS",
            "severity": "MEDIUM",
            "detail": "HTTP (port 80) is open but HTTPS (port 443) is not. Traffic is unencrypted."
        })

    # Database ports exposed
    for port, db_name in [(3306, "MySQL"), (5432, "PostgreSQL"), (27017, "MongoDB"), (6379, "Redis"), (9200, "Elasticsearch"), (1433, "MSSQL")]:
        if port in open_ports:
            misconfigs.append({
                "type": "DATABASE_EXPOSED",
                "severity": "HIGH",
                "detail": f"{db_name} (port {port}) is exposed to the network. Databases should never be directly accessible."
            })

    # FTP open
    if 21 in open_ports:
        misconfigs.append({
            "type": "FTP_EXPOSED",
            "severity": "MEDIUM",
            "detail": "FTP (port 21) is open. FTP transmits credentials in plain text. Use SFTP instead."
        })

    # Legacy NetBIOS
    if 139 in open_ports:
        misconfigs.append({
            "type": "NETBIOS_EXPOSED",
            "severity": "MEDIUM",
            "detail": "NetBIOS (port 139) is open. This is a legacy Windows protocol and an attack surface."
        })

    return misconfigs

# -----------------------------
# ATTACK SURFACE SCORING
# -----------------------------
def calculate_attack_surface_score(open_ports, misconfigurations):
    score = 0

    # Score based on port severity
    for port in open_ports:
        severity = PORT_SEVERITY.get(port, None)
        if severity == "CRITICAL":
            score += 40
        elif severity == "HIGH":
            score += 25
        elif severity == "MEDIUM":
            score += 15
        elif severity == "LOW":
            score += 5

    # Score based on misconfigurations
    for m in misconfigurations:
        if m["severity"] == "CRITICAL":
            score += 30
        elif m["severity"] == "HIGH":
            score += 20
        elif m["severity"] == "MEDIUM":
            score += 10

    # Cap score at 100
    return min(score, 100)

# -----------------------------
# THREAT LEVEL FROM SCORE
# -----------------------------
def score_to_threat_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    elif score >= 10:
        return "LOW"
    else:
        return "NONE"

# -----------------------------
# MAIN SCAN FUNCTION
# -----------------------------
def scan_device(ip, mac):
    print(f"  [SCAN] {ip} ({mac})")
    nm = nmap.PortScanner()

    try:
        # -sV = service version detection
        # -O  = OS detection
        # -T4 = aggressive timing (faster)
        # --top-ports 1000 = scan top 1000 most common ports
        nm.scan(hosts=ip, arguments="-sV -O -T4 --top-ports 1000")
    except Exception as e:
        print(f"  [ERROR] Could not scan {ip}: {e}")
        return None

    open_ports = []
    services = {}
    os_guess = "Unknown"

    if ip not in nm.all_hosts():
        print(f"  [WARN] {ip} did not respond to scan")
        return None

    # Extract open ports and services
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto].keys():
            state = nm[ip][proto][port]["state"]
            if state == "open":
                open_ports.append(port)
                service_name = nm[ip][proto][port].get("name", "unknown")
                service_version = nm[ip][proto][port].get("version", "")
                services[port] = f"{service_name} {service_version}".strip()

    # Extract OS guess
    try:
        os_matches = nm[ip]["osmatch"]
        if os_matches:
            os_guess = os_matches[0]["name"]
    except (KeyError, IndexError):
        os_guess = "Unknown"

    # Run misconfiguration checks
    misconfigurations = check_misconfigurations(open_ports, services)

    # Calculate attack surface score
    score = calculate_attack_surface_score(open_ports, misconfigurations)

    # Save to database
    save_scan_result(ip, mac, open_ports, services, os_guess, misconfigurations, score)

    print(f"  [DONE] {ip} — {len(open_ports)} open ports, score: {score}")

    return {
        "ip": ip,
        "mac": mac,
        "open_ports": open_ports,
        "services": services,
        "os_guess": os_guess,
        "misconfigurations": misconfigurations,
        "attack_surface_score": score,
        "threat_level": score_to_threat_level(score)
    }


def scan_all_devices(devices):
    print(f"\n[ATTACK SURFACE] Scanning {len(devices)} devices...\n")
    results = []
    for device in devices:
        result = scan_device(device["ip"], device["mac"])
        if result:
            results.append(result)
    return results


if __name__ == "__main__":
    # Quick test
    result = scan_device("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    if result:
        print(json.dumps(result, indent=2))
