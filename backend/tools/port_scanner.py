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
        ports = list(COMMON_PORTS.keys())
    
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
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    result = loop.run_until_complete(scan_ports(hostname))
    
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
