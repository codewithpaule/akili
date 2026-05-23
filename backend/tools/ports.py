import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

COMMON_PORTS = [
    (21, "FTP", "HIGH"),
    (22, "SSH", "MEDIUM"),
    (23, "Telnet", "CRITICAL"),
    (25, "SMTP", "MEDIUM"),
    (53, "DNS", "LOW"),
    (80, "HTTP", "LOW"),
    (110, "POP3", "MEDIUM"),
    (143, "IMAP", "MEDIUM"),
    (443, "HTTPS", "LOW"),
    (445, "SMB", "CRITICAL"),
    (3306, "MySQL", "CRITICAL"),
    (3389, "RDP", "CRITICAL"),
    (5432, "PostgreSQL", "HIGH"),
    (5900, "VNC", "HIGH"),
    (6379, "Redis", "CRITICAL"),
    (8080, "HTTP-Alt", "MEDIUM"),
    (8443, "HTTPS-Alt", "MEDIUM"),
    (27017, "MongoDB", "CRITICAL"),
]


def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run(url: str, context: dict) -> dict:
    hostname = urlparse(url).hostname
    open_ports = []
    findings = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_check_port, hostname, p[0]): p for p in COMMON_PORTS}
        for future in as_completed(futures):
            port_info = futures[future]
            port, service, risk = port_info
            if future.result():
                entry = {
                    "port": port,
                    "service": service,
                    "status": "open",
                    "risk": risk,
                }
                open_ports.append(entry)
                if risk in ("CRITICAL", "HIGH"):
                    findings.append({
                        "severity": risk,
                        "name": f"Port {port} ({service}) exposed",
                        "explanation": f"Port {port} is open and accepting connections.",
                        "recommendation": f"Close port {port} if not required, or restrict via firewall.",
                    })

    context["open_ports"] = open_ports
    severity = "INFO"
    if any(p["risk"] == "CRITICAL" for p in open_ports):
        severity = "CRITICAL"
    elif open_ports:
        severity = "MEDIUM"

    return {
        "tool": "ports",
        "severity": severity,
        "title": "Port scan",
        "detail": f"{len(open_ports)} open ports of {len(COMMON_PORTS)} checked",
        "raw": {"ports": open_ports},
        "findings": findings,
    }
