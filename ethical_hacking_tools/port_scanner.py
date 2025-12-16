#!/usr/bin/env python3
"""
Port Scanner - Ethical Hacking Tools Suite
Educational and Testing Purposes Only

A comprehensive port scanner similar to Nmap but implemented in Python.
Uses socket and scapy libraries for network scanning.
"""

import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Warning: Scapy not available. Some advanced features disabled.")

from ethical_hacking_tools.utils.logger import setup_logger, log_scan_result

class PortScanner:
    """
    Advanced Port Scanner with multiple scanning techniques
    """
    
    def __init__(self):
        self.logger = setup_logger('port_scanner')
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = {}
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443
        ]
        
        # Service mappings
        self.service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
    
    def parse_ports(self, port_string):
        """
        Parse port string into list of ports
        Supports ranges (1-1000) and comma-separated lists (80,443,22)
        """
        ports = []
        
        if '-' in port_string:
            # Range format: 1-1000
            start, end = map(int, port_string.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_string:
            # Comma-separated: 80,443,22
            ports = [int(p.strip()) for p in port_string.split(',')]
        else:
            # Single port
            ports = [int(port_string)]
        
        return ports
    
    def tcp_connect_scan(self, target, port, timeout=1):
        """
        TCP Connect Scan - Most reliable but easily detected
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return 'open'
            else:
                return 'closed'
        except Exception as e:
            self.logger.debug(f"TCP connect scan error on port {port}: {e}")
            return 'filtered'
    
    def tcp_syn_scan(self, target, port, timeout=1):
        """
        TCP SYN Scan (Half-open scan) - Stealthier than connect scan
        Requires scapy and root privileges
        """
        if not SCAPY_AVAILABLE:
            return self.tcp_connect_scan(target, port, timeout)
        
        try:
            # Create SYN packet
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            
            # Send packet and receive response
            response = sr1(packet, timeout=timeout, verbose=0)
            
            if response is None:
                return 'filtered'
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=target) / TCP(dport=port, flags="R")
                    send(rst_packet, verbose=0)
                    return 'open'
                elif response[TCP].flags == 0x14:  # RST-ACK
                    return 'closed'
                else:
                    return 'filtered'
            else:
                return 'filtered'
        except Exception as e:
            self.logger.debug(f"TCP SYN scan error on port {port}: {e}")
            return 'filtered'
    
    def udp_scan(self, target, port, timeout=1):
        """
        UDP Scan - Slower but necessary for UDP services
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return 'open'
            except socket.timeout:
                sock.close()
                return 'open|filtered'  # UDP is stateless, hard to determine
        except Exception as e:
            self.logger.debug(f"UDP scan error on port {port}: {e}")
            return 'filtered'
    
    def scan_port(self, target, port, scan_type='tcp_connect'):
        """
        Scan a single port using specified method
        """
        start_time = time.time()
        
        if scan_type == 'tcp_connect':
            result = self.tcp_connect_scan(target, port)
        elif scan_type == 'tcp_syn':
            result = self.tcp_syn_scan(target, port)
        elif scan_type == 'udp':
            result = self.udp_scan(target, port)
        else:
            result = self.tcp_connect_scan(target, port)
        
        scan_time = time.time() - start_time
        
        port_info = {
            'port': port,
            'state': result,
            'service': self.service_map.get(port, 'Unknown'),
            'scan_time': scan_time
        }
        
        return port_info
    
    def scan(self, target, ports='1-1000', max_threads=100, verbose=False, scan_type='tcp_connect'):
        """
        Main scanning function
        """
        self.logger.info(f"Starting port scan on {target}")
        print(f"\n[+] Starting port scan on {target}")
        print(f"[+] Port range: {ports}")
        print(f"[+] Scan type: {scan_type}")
        print(f"[+] Max threads: {max_threads}")
        print("-" * 50)
        
        # Parse ports
        port_list = self.parse_ports(ports)
        
        # Reset results
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all scan tasks
            future_to_port = {
                executor.submit(self.scan_port, target, port, scan_type): port
                for port in port_list
            }
            
            # Process completed scans
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    
                    if result['state'] == 'open':
                        self.open_ports.append(result)
                        print(f"[+] Port {result['port']}/tcp open - {result['service']}")
                    elif verbose and result['state'] == 'closed':
                        self.closed_ports.append(result)
                        print(f"[-] Port {result['port']}/tcp closed")
                    elif verbose and result['state'] == 'filtered':
                        self.filtered_ports.append(result)
                        print(f"[?] Port {result['port']}/tcp filtered")
                    
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")
                    if verbose:
                        print(f"[!] Error scanning port {port}: {e}")
        
        scan_duration = time.time() - start_time
        
        # Print summary
        print("-" * 50)
        print(f"[+] Scan completed in {scan_duration:.2f} seconds")
        print(f"[+] Open ports found: {len(self.open_ports)}")
        if verbose:
            print(f"[-] Closed ports: {len(self.closed_ports)}")
            print(f"[?] Filtered ports: {len(self.filtered_ports)}")
        
        # Log results
        open_port_numbers = [p['port'] for p in self.open_ports]
        log_scan_result(
            self.logger, 
            'port_scan', 
            target, 
            ports_found=open_port_numbers
        )
        
        return {
            'target': target,
            'open_ports': self.open_ports,
            'closed_ports': self.closed_ports,
            'filtered_ports': self.filtered_ports,
            'scan_duration': scan_duration,
            'total_ports_scanned': len(port_list)
        }
    
    def banner_grab(self, target, port, timeout=3):
        """
        Attempt to grab service banner from open port
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send common probes
            probes = [
                b'\r\n\r\n',  # HTTP-like
                b'HELP\r\n',  # FTP-like
                b'QUIT\r\n',  # SMTP-like
            ]
            
            banner = b''
            for probe in probes:
                try:
                    sock.send(probe)
                    banner += sock.recv(1024)
                except:
                    pass
            
            sock.close()
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            self.logger.debug(f"Banner grab error on port {port}: {e}")
            return None
    
    def scan_with_banner_grab(self, target, ports='1-1000', max_threads=50):
        """
        Scan ports and attempt banner grabbing on open ports
        """
        print(f"\n[+] Starting comprehensive scan with banner grabbing on {target}")
        
        # First, do a quick scan
        results = self.scan(target, ports, max_threads, verbose=False)
        
        # Then grab banners from open ports
        print("\n[+] Grabbing banners from open ports...")
        for port_info in self.open_ports:
            port = port_info['port']
            banner = self.banner_grab(target, port)
            if banner:
                print(f"[+] Port {port}: {banner}")
                port_info['banner'] = banner
            else:
                print(f"[+] Port {port}: No banner received")
        
        return results

def main():
    """
    Command line interface for Port Scanner
    """
    parser = argparse.ArgumentParser(description='Port Scanner - Ethical Hacking Tools')
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000, 80,443,22)')
    parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads')
    parser.add_argument('-s', '--scan-type', choices=['tcp_connect', 'tcp_syn', 'udp'], 
                       default='tcp_connect', help='Scan type')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-b', '--banner', action='store_true', help='Grab banners from open ports')
    
    args = parser.parse_args()
    
    scanner = PortScanner()
    
    if args.banner:
        scanner.scan_with_banner_grab(args.target, args.ports, args.threads)
    else:
        scanner.scan(args.target, args.ports, args.threads, args.verbose, args.scan_type)

if __name__ == "__main__":
    main()
