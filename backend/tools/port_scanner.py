import asyncio
import socket
import ssl
from typing import List, Dict, Any
from datetime import datetime
from urllib.parse import urlparse


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Extended port ranges requested by user (string form to keep file compact).
EXTENDED_PORT_RANGES = (
    "7,9,13,20-23,25-26,37,42-43,53,70,79-81,88,102,106,110-111,113,119,135,137-139,143-144,"
    "179,199,201,264,318,383,389,411-412,427,443-445,464-465,497,512-515,540,543-544,546-548,"
    "554,563,587,591,593,596,631,639,646,691,860,873,902,989-990,993,995,1025-1029,1080,1110,"
    "1194,1214,1241,1311,1337,1433,1589,1701,1720,1723,1741,1755,1900,2000-2002,2049,2078,2080,"
    "2082-2083,2086-2087,2100,2121,2222,2483-2484,2717,2967,3000,3050,3128,3222,3306,3389,3690,"
    "3784,3986,4280,4333,4444-4445,4899,5000,5004-5005,5009,5013,5051,5060,5101,5190,5222-5223,"
    "5357,5432,5631,5666,5800,5900-5901,5985-5986,6000-6001,6129,6346-6347,6379,6588,6646,6665,"
    "6679,6699,7000-7001,7070,7199,8000,8008-8009,8080-8081,8200,8222,8443,8500,8888,9000,9042,"
    "9100,9800,9999-10000,10161-10162,19638,20000,27017,32768,49152-49157"
)


def _expand_ports(range_str: str):
    ports = set()
    for part in range_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a_i = int(a); b_i = int(b)
            except Exception:
                continue
            for p in range(a_i, b_i + 1):
                ports.add(p)
        else:
            try:
                ports.add(int(part))
            except Exception:
                continue
    return sorted(ports)


async def check_port(hostname: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Check if a specific port is open and attempt to identify the service."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        # Try to get more info about the service
        service_info = await get_service_info(hostname, port)
        
        return {
            "port": port,
            "status": "open",
            "service": COMMON_PORTS.get(port, "unknown"),
            "info": service_info
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {
            "port": port,
            "status": "closed",
            "service": COMMON_PORTS.get(port, "unknown"),
            "info": None
        }


async def get_service_info(hostname: str, port: int) -> Dict[str, Any]:
    """Attempt to get more information about the service running on a port."""
    info = {}
    
    try:
        if port in [80, 8080, 8000]:
            # Try HTTP
            try:
                import httpx
                async with httpx.AsyncClient(timeout=3.0) as client:
                    response = await client.get(f"http://{hostname}:{port}", follow_redirects=True)
                    server = response.headers.get("Server", "")
                    powered_by = response.headers.get("X-Powered-By", "")
                    info["server"] = server
                    info["powered_by"] = powered_by
                    info["status_code"] = response.status_code
            except Exception:
                pass
        
        elif port in [443, 8443]:
            # Try HTTPS with SSL info
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=context),
                    timeout=3.0
                )
                
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    cert = ssl_object.getpeercert()
                    if cert:
                        info["certificate"] = {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "version": cert.get("version"),
                            "not_before": cert.get("notBefore"),
                            "not_after": cert.get("notAfter"),
                        }
                
                writer.close()
                await writer.wait_closed()
                
                # Also try HTTP request
                try:
                    import httpx
                    async with httpx.AsyncClient(timeout=3.0, verify=False) as client:
                        response = await client.get(f"https://{hostname}:{port}", follow_redirects=True)
                        server = response.headers.get("Server", "")
                        powered_by = response.headers.get("X-Powered-By", "")
                        info["server"] = server
                        info["powered_by"] = powered_by
                        info["status_code"] = response.status_code
                except Exception:
                    pass
            except Exception:
                pass
        
        elif port == 22:
            # Try SSH banner
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=3.0
                )
                banner = await asyncio.wait_for(reader.read(100), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                if banner:
                    info["banner"] = banner.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
        
        elif port in [25, 587]:
            # Try SMTP banner
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=3.0
                )
                banner = await asyncio.wait_for(reader.read(200), timeout=2.0)
                writer.close()
                await writer.wait_closed()
                if banner:
                    info["banner"] = banner.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
        
    except Exception:
        pass
    
    return info


async def scan_ports(hostname: str, ports: List[int] = None, max_concurrent: int = 50) -> Dict[str, Any]:
    """Scan multiple ports concurrently."""
    if ports is None:
        # Use the extended list by default for deeper coverage
        ports = _expand_ports(EXTENDED_PORT_RANGES)
    
    open_ports = []
    closed_ports = []
    
    # Create semaphore to limit concurrent connections
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(port):
        async with semaphore:
            return await check_port(hostname, port)
    
    # Run all port checks concurrently
    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, Exception):
            continue
        
        if result["status"] == "open":
            open_ports.append(result)
        else:
            closed_ports.append(result)
    
    return {
        "hostname": hostname,
        "total_ports_scanned": len(ports),
        "open_ports": open_ports,
        "closed_ports_count": len(closed_ports),
        "open_ports_count": len(open_ports),
        "scan_timestamp": datetime.utcnow().isoformat()
    }


def run_port_scan(hostname: str, context: dict) -> dict:
    """Run port scan (synchronous wrapper for async function)."""
    from tools.async_util import run_async
    
    # If the caller explicitly requested credential brute-force, we refuse to perform it.
    if context.get('bruteforce'):
        result = run_async(scan_ports(hostname), timeout=180)
        findings = [{
            "severity": "INFO",
            "name": "Credential brute-force disabled",
            "explanation": "Brute-force of usernames/passwords is not supported by AKILI. This behavior is potentially harmful and has been disabled.",
            "recommendation": "If you need authenticated checks, provide valid credentials and use authorized testing tooling or configure targeted checks that you control.",
        }]
        return {
            "tool": "port_scanner",
            "severity": "INFO",
            "title": "Port scan results",
            "detail": f"{len(result['open_ports'])} open ports found (brute-force disabled)",
            "raw": result,
            "findings": findings,
        }

    result = run_async(scan_ports(hostname), timeout=180)
    
    findings = []
    
    # Generate findings based on open ports
    for port_info in result["open_ports"]:
        port = port_info["port"]
        service = port_info["service"]
        
        # High-risk ports
        if port in [21, 23, 135, 139, 445, 3389, 5900]:
            findings.append({
                "severity": "HIGH",
                "name": f"High-risk port {port} ({service}) is open",
                "explanation": f"Port {port} ({service}) is accessible from the internet. This service may have known vulnerabilities.",
                "recommendation": "Ensure this service is required and properly secured. Consider firewall rules to restrict access."
            })
        
        # Medium-risk ports
        elif port in [22, 25, 110, 143, 3306, 5432, 6379, 27017]:
            findings.append({
                "severity": "MEDIUM",
                "name": f"Port {port} ({service}) is open",
                "explanation": f"Port {port} ({service}) is accessible. Ensure authentication is properly configured.",
                "recommendation": "Review access controls and ensure strong authentication is enforced."
            })
        
        # Check for SSL/TLS issues
        if port in [443, 8443] and port_info.get("info", {}).get("certificate"):
            cert = port_info["info"]["certificate"]
            # Could add SSL validation here
    
    # If many ports open, flag as potential attack surface
    if len(result["open_ports"]) > 10:
        findings.append({
            "severity": "MEDIUM",
            "name": "Large attack surface",
            "explanation": f"{len(result['open_ports'])} ports are open, increasing the attack surface.",
            "recommendation": "Review open ports and close any unnecessary services."
        })
    
    severity = "INFO"
    if any(f["severity"] == "HIGH" for f in findings):
        severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        severity = "MEDIUM"
    
    return {
        "tool": "port_scanner",
        "severity": severity,
        "title": "Port scan results",
        "detail": f"{len(result['open_ports'])} open ports found",
        "raw": result,
        "findings": findings,
    }
