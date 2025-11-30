"""Port Scanner Module - Port scanning and service detection"""

import socket
import subprocess
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class PortScanner:
    """Port scanning and service detection"""
    
    def __init__(self):
        # Common ports
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        # Well-known ports
        self.well_known_ports = list(range(1, 1024))
        
        # Service detection
        self.service_signatures = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
    
    def scan(self, target: str, ports: str = 'common', timeout: float = 1.0, threads: int = 50) -> Dict:
        """Scan ports on target"""
        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'banners': {}
        }
        
        # Determine port range
        port_list = self._get_port_list(ports)
        
        # Scan ports
        open_ports = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._scan_port, target, port, timeout): port for port in port_list}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        open_ports.append(port)
                        if banner:
                            results['banners'][port] = banner
                        # Detect service
                        service = self._detect_service(port, banner)
                        if service:
                            results['services'][port] = service
                except Exception:
                    pass
        
        results['open_ports'] = sorted(open_ports)
        
        # Add service info for open ports
        for port in results['open_ports']:
            if port not in results['services']:
                service = self.service_signatures.get(port, 'Unknown')
                results['services'][port] = service
        
        return results
    
    def _scan_port(self, target: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                # Try to grab banner
                banner = self._grab_banner(target, port, timeout)
                return True, banner
            return False, None
        except:
            return False, None
    
    def _grab_banner(self, target: str, port: int, timeout: float) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Try to receive banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:200]  # Limit banner length
            except:
                sock.close()
                return None
        except:
            return None
    
    def _detect_service(self, port: int, banner: Optional[str]) -> Optional[str]:
        """Detect service from port and banner"""
        # First check known port mappings
        if port in self.service_signatures:
            return self.service_signatures[port]
        
        # Try to detect from banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                return 'SSH'
            elif 'ftp' in banner_lower:
                return 'FTP'
            elif 'smtp' in banner_lower:
                return 'SMTP'
            elif 'http' in banner_lower:
                return 'HTTP'
            elif 'mysql' in banner_lower:
                return 'MySQL'
            elif 'apache' in banner_lower:
                return 'Apache'
            elif 'nginx' in banner_lower:
                return 'Nginx'
            elif 'iis' in banner_lower:
                return 'IIS'
        
        return None
    
    def _get_port_list(self, ports: str) -> List[int]:
        """Get list of ports to scan"""
        if ports == 'common':
            return self.common_ports
        elif ports == 'well-known':
            return self.well_known_ports
        elif ports == 'all':
            return list(range(1, 65536))
        elif '-' in ports:
            # Range like "1-1000"
            start, end = map(int, ports.split('-'))
            return list(range(start, end + 1))
        elif ',' in ports:
            # Comma-separated list
            return [int(p.strip()) for p in ports.split(',')]
        else:
            # Single port
            return [int(ports)]
    
    def scan_with_nmap(self, target: str, ports: str = 'common') -> Dict:
        """Use nmap for advanced scanning (if available)"""
        results = {
            'target': target,
            'open_ports': [],
            'services': {},
            'banners': {},
            'os': None
        }
        
        try:
            # Check if nmap is available
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            
            # Build nmap command
            port_arg = ports if ports not in ['common', 'well-known', 'all'] else None
            
            cmd = ['nmap', '-sV', '-sC', '--open']
            if port_arg:
                cmd.extend(['-p', port_arg])
            else:
                if ports == 'common':
                    cmd.extend(['-p', ','.join(map(str, self.common_ports))])
                elif ports == 'all':
                    cmd.append('-p-')
            
            cmd.append(target)
            
            # Run nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse nmap output
                output = result.stdout
                # Simple parsing (in production, use nmap XML output)
                for line in output.split('\n'):
                    if '/tcp' in line or '/udp' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            port_info = parts[0].split('/')
                            if len(port_info) == 2:
                                port = int(port_info[0])
                                state = parts[1]
                                if state == 'open':
                                    results['open_ports'].append(port)
                                    if len(parts) >= 3:
                                        results['services'][port] = ' '.join(parts[2:])
        
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to basic scan
            return self.scan(target, ports)
        except Exception:
            return self.scan(target, ports)
        
        return results

