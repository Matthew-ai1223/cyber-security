#!/usr/bin/env python3
"""
Packet Sniffer - Ethical Hacking Tools Suite
Educational and Testing Purposes Only

Captures and analyzes network traffic including:
- HTTP requests and responses
- DNS queries
- TCP/UDP packets
- ARP packets
- ICMP packets
- Custom protocol analysis
"""

import socket
import struct
import time
import threading
import json
import argparse
from datetime import datetime
import os
import sys

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Warning: Scapy not available. Packet sniffing functionality disabled.")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("[!] Warning: netifaces not available. Interface detection disabled.")

from ethical_hacking_tools.utils.logger import setup_logger, log_security_event

class PacketSniffer:
    """
    Advanced packet sniffer for network traffic analysis
    """
    
    def __init__(self):
        self.logger = setup_logger('packet_sniffer')
        self.is_running = False
        self.packet_count = 0
        self.start_time = None
        self.captured_packets = []
        
        # Statistics
        self.protocol_stats = {}
        self.ip_stats = {}
        self.port_stats = {}
        
        # Filters
        self.bpf_filter = None
        self.protocol_filter = None
        self.ip_filter = None
        self.port_filter = None
        
        # Output
        self.output_file = None
        self.console_output = True
        
        print("[!] WARNING: Packet sniffing is for educational purposes only!")
        print("[!] Use only on networks you own or have permission to monitor!")
        print("[!] Unauthorized packet capture may violate laws and regulations!")
    
    def get_available_interfaces(self):
        """
        Get list of available network interfaces
        """
        interfaces = []
        
        if NETIFACES_AVAILABLE:
            try:
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        interfaces.append((interface, ip))
            except Exception as e:
                self.logger.error(f"Error getting interfaces: {e}")
        
        # Fallback to basic interface detection
        if not interfaces:
            try:
                # Get default interface
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                interfaces.append(('eth0', local_ip))
            except:
                interfaces.append(('eth0', '127.0.0.1'))
        
        return interfaces
    
    def packet_handler(self, packet):
        """
        Handle captured packets
        """
        if not self.is_running:
            return
        
        try:
            self.packet_count += 1
            
            # Parse packet
            packet_info = self.parse_packet(packet)
            
            if packet_info:
                self.captured_packets.append(packet_info)
                
                # Update statistics
                self.update_statistics(packet_info)
                
                # Output packet info
                if self.console_output:
                    self.display_packet(packet_info)
                
                # Write to file
                if self.output_file:
                    self.write_packet_to_file(packet_info)
                
                # Log security events
                self.check_security_events(packet_info)
        
        except Exception as e:
            self.logger.error(f"Error handling packet: {e}")
    
    def parse_packet(self, packet):
        """
        Parse packet and extract relevant information
        """
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'packet_number': self.packet_count,
            'size': len(packet)
        }
        
        try:
            # Ethernet layer
            if packet.haslayer(Ether):
                eth = packet[Ether]
                packet_info['src_mac'] = eth.src
                packet_info['dst_mac'] = eth.dst
                packet_info['ethertype'] = eth.type
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_info['src_ip'] = ip.src
                packet_info['dst_ip'] = ip.dst
                packet_info['protocol'] = ip.proto
                packet_info['ttl'] = ip.ttl
                packet_info['length'] = ip.len
                
                # Protocol-specific parsing
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_info['src_port'] = tcp.sport
                    packet_info['dst_port'] = tcp.dport
                    packet_info['flags'] = tcp.flags
                    packet_info['seq'] = tcp.seq
                    packet_info['ack'] = tcp.ack
                    packet_info['protocol_name'] = 'TCP'
                    
                    # HTTP analysis
                    if packet.haslayer(Raw):
                        raw_data = packet[Raw].load
                        if self.is_http_data(raw_data):
                            packet_info['http_data'] = self.parse_http_data(raw_data)
                
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_info['src_port'] = udp.sport
                    packet_info['dst_port'] = udp.dport
                    packet_info['protocol_name'] = 'UDP'
                    
                    # DNS analysis
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        packet_info['dns_query'] = self.parse_dns_query(dns)
                
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    packet_info['icmp_type'] = icmp.type
                    packet_info['icmp_code'] = icmp.code
                    packet_info['protocol_name'] = 'ICMP'
            
            # ARP layer
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                packet_info['arp_op'] = arp.op
                packet_info['src_ip'] = arp.psrc
                packet_info['dst_ip'] = arp.pdst
                packet_info['src_mac'] = arp.hwsrc
                packet_info['dst_mac'] = arp.hwdst
                packet_info['protocol_name'] = 'ARP'
            
            return packet_info
        
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            return None
    
    def is_http_data(self, data):
        """
        Check if raw data contains HTTP
        """
        try:
            data_str = data.decode('utf-8', errors='ignore')
            return any(method in data_str for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD '])
        except:
            return False
    
    def parse_http_data(self, data):
        """
        Parse HTTP data from raw packet
        """
        try:
            data_str = data.decode('utf-8', errors='ignore')
            lines = data_str.split('\r\n')
            
            http_info = {}
            
            # Parse request line
            if lines[0]:
                parts = lines[0].split(' ')
                if len(parts) >= 3:
                    http_info['method'] = parts[0]
                    http_info['uri'] = parts[1]
                    http_info['version'] = parts[2]
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                elif line == '':
                    break
            
            http_info['headers'] = headers
            
            return http_info
        
        except Exception as e:
            self.logger.error(f"Error parsing HTTP data: {e}")
            return None
    
    def parse_dns_query(self, dns):
        """
        Parse DNS query information
        """
        try:
            dns_info = {
                'id': dns.id,
                'qr': dns.qr,
                'opcode': dns.opcode,
                'rcode': dns.rcode
            }
            
            if dns.qd:
                dns_info['query_name'] = dns.qd.qname.decode('utf-8')
                dns_info['query_type'] = dns.qd.qtype
            
            if dns.an:
                dns_info['answers'] = []
                for answer in dns.an:
                    dns_info['answers'].append({
                        'name': answer.rrname.decode('utf-8'),
                        'type': answer.rtype,
                        'data': answer.rdata
                    })
            
            return dns_info
        
        except Exception as e:
            self.logger.error(f"Error parsing DNS query: {e}")
            return None
    
    def update_statistics(self, packet_info):
        """
        Update packet statistics
        """
        # Protocol statistics
        protocol = packet_info.get('protocol_name', 'Unknown')
        self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
        
        # IP statistics
        src_ip = packet_info.get('src_ip')
        if src_ip:
            self.ip_stats[src_ip] = self.ip_stats.get(src_ip, 0) + 1
        
        # Port statistics
        src_port = packet_info.get('src_port')
        if src_port:
            self.port_stats[src_port] = self.port_stats.get(src_port, 0) + 1
    
    def display_packet(self, packet_info):
        """
        Display packet information in console
        """
        try:
            timestamp = packet_info['timestamp']
            packet_num = packet_info['packet_number']
            size = packet_info['size']
            
            # Basic info
            print(f"[{timestamp}] Packet #{packet_num} ({size} bytes)")
            
            # Protocol-specific display
            protocol = packet_info.get('protocol_name', 'Unknown')
            
            if protocol == 'TCP':
                src_ip = packet_info.get('src_ip', 'Unknown')
                dst_ip = packet_info.get('dst_ip', 'Unknown')
                src_port = packet_info.get('src_port', 'Unknown')
                dst_port = packet_info.get('dst_port', 'Unknown')
                flags = packet_info.get('flags', 'Unknown')
                
                print(f"  TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]")
                
                # HTTP info
                if 'http_data' in packet_info:
                    http_data = packet_info['http_data']
                    if 'method' in http_data and 'uri' in http_data:
                        print(f"  HTTP: {http_data['method']} {http_data['uri']}")
            
            elif protocol == 'UDP':
                src_ip = packet_info.get('src_ip', 'Unknown')
                dst_ip = packet_info.get('dst_ip', 'Unknown')
                src_port = packet_info.get('src_port', 'Unknown')
                dst_port = packet_info.get('dst_port', 'Unknown')
                
                print(f"  UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # DNS info
                if 'dns_query' in packet_info:
                    dns_query = packet_info['dns_query']
                    if 'query_name' in dns_query:
                        print(f"  DNS: Query for {dns_query['query_name']}")
            
            elif protocol == 'ICMP':
                src_ip = packet_info.get('src_ip', 'Unknown')
                dst_ip = packet_info.get('dst_ip', 'Unknown')
                icmp_type = packet_info.get('icmp_type', 'Unknown')
                icmp_code = packet_info.get('icmp_code', 'Unknown')
                
                print(f"  ICMP: {src_ip} -> {dst_ip} (Type: {icmp_type}, Code: {icmp_code})")
            
            elif protocol == 'ARP':
                src_ip = packet_info.get('src_ip', 'Unknown')
                dst_ip = packet_info.get('dst_ip', 'Unknown')
                src_mac = packet_info.get('src_mac', 'Unknown')
                dst_mac = packet_info.get('dst_mac', 'Unknown')
                arp_op = packet_info.get('arp_op', 'Unknown')
                
                op_str = 'Request' if arp_op == 1 else 'Reply'
                print(f"  ARP: {op_str} {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")
            
            print()
        
        except Exception as e:
            self.logger.error(f"Error displaying packet: {e}")
    
    def write_packet_to_file(self, packet_info):
        """
        Write packet information to file
        """
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(f"PACKET: {json.dumps(packet_info)}\n")
        except Exception as e:
            self.logger.error(f"Error writing packet to file: {e}")
    
    def check_security_events(self, packet_info):
        """
        Check for security-related events
        """
        try:
            # Check for suspicious activity
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            protocol = packet_info.get('protocol_name')
            
            # Port scanning detection
            if protocol == 'TCP' and packet_info.get('flags') == 2:  # SYN flag
                log_security_event(
                    self.logger,
                    'syn_packet',
                    f"{src_ip}:{packet_info.get('src_port')} -> {dst_ip}:{packet_info.get('dst_port')}",
                    'Potential port scan'
                )
            
            # DNS tunneling detection (simplified)
            if protocol == 'UDP' and packet_info.get('dst_port') == 53:
                dns_query = packet_info.get('dns_query')
                if dns_query and 'query_name' in dns_query:
                    query_name = dns_query['query_name']
                    if len(query_name) > 50:  # Suspiciously long DNS query
                        log_security_event(
                            self.logger,
                            'suspicious_dns',
                            query_name,
                            'Potentially suspicious DNS query'
                        )
            
            # ARP spoofing detection
            if protocol == 'ARP':
                arp_op = packet_info.get('arp_op')
                if arp_op == 2:  # ARP Reply
                    log_security_event(
                        self.logger,
                        'arp_reply',
                        f"{src_ip} ({packet_info.get('src_mac')})",
                        'ARP reply detected'
                    )
        
        except Exception as e:
            self.logger.error(f"Error checking security events: {e}")
    
    def sniff(self, interface=None, filter_str=None, count=None, timeout=None):
        """
        Start packet sniffing
        """
        if not SCAPY_AVAILABLE:
            print("[!] Error: Scapy not available. Cannot start packet sniffing.")
            return False
        
        print(f"\n[+] Starting packet sniffer...")
        print(f"[+] Interface: {interface or 'default'}")
        print(f"[+] Filter: {filter_str or 'none'}")
        print(f"[+] Count: {count or 'unlimited'}")
        print(f"[+] Timeout: {timeout or 'none'}")
        print(f"[+] Press Ctrl+C to stop")
        print("-" * 50)
        
        # Setup
        self.is_running = True
        self.start_time = time.time()
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_stats = {}
        self.ip_stats = {}
        self.port_stats = {}
        
        # Create output file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = f"packet_capture_{timestamp}.log"
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(f"PACKET CAPTURE STARTED: {datetime.now().isoformat()}\n")
                f.write(f"INTERFACE: {interface or 'default'}\n")
                f.write(f"FILTER: {filter_str or 'none'}\n")
                f.write("-" * 50 + "\n")
            
            # Start sniffing
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_handler,
                count=count,
                timeout=timeout
            )
        
        except KeyboardInterrupt:
            print(f"\n[!] Packet sniffing interrupted by user")
            self.stop()
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {e}")
            print(f"[!] Error: {e}")
            return False
        
        return True
    
    def stop(self):
        """
        Stop packet sniffing
        """
        print(f"\n[!] Stopping packet sniffer...")
        self.is_running = False
        
        # Write summary
        self.write_summary()
        
        # Log security event
        duration = time.time() - self.start_time if self.start_time else 0
        log_security_event(
            self.logger,
            'packet_sniffing_stopped',
            'network',
            f"Duration: {duration:.2f}s, Packets: {self.packet_count}"
        )
    
    def write_summary(self):
        """
        Write sniffing summary
        """
        if not self.output_file:
            return
        
        try:
            duration = time.time() - self.start_time if self.start_time else 0
            
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write("-" * 50 + "\n")
                f.write(f"PACKET CAPTURE ENDED: {datetime.now().isoformat()}\n")
                f.write(f"DURATION: {duration:.2f} seconds\n")
                f.write(f"TOTAL PACKETS: {self.packet_count}\n")
                f.write(f"PACKETS PER SECOND: {self.packet_count / duration if duration > 0 else 0:.2f}\n")
                
                f.write(f"\nPROTOCOL STATISTICS:\n")
                for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {protocol}: {count}\n")
                
                f.write(f"\nTOP SOURCE IPS:\n")
                for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {ip}: {count}\n")
                
                f.write(f"\nTOP PORTS:\n")
                for port, count in sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"  {port}: {count}\n")
        
        except Exception as e:
            self.logger.error(f"Error writing summary: {e}")
    
    def analyze_capture(self, capture_file):
        """
        Analyze captured packet file
        """
        if not os.path.exists(capture_file):
            print(f"[!] Error: Capture file '{capture_file}' not found")
            return
        
        print(f"\n[+] Analyzing packet capture: {capture_file}")
        
        try:
            packets = []
            with open(capture_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('PACKET:'):
                        packet_data = json.loads(line[7:])
                        packets.append(packet_data)
            
            if not packets:
                print("[!] No packets found in capture file")
                return
            
            # Analysis
            print(f"\nANALYSIS RESULTS:")
            print(f"-" * 30)
            print(f"Total packets: {len(packets)}")
            
            # Protocol analysis
            protocols = {}
            for packet in packets:
                protocol = packet.get('protocol_name', 'Unknown')
                protocols[protocol] = protocols.get(protocol, 0) + 1
            
            print(f"\nProtocol distribution:")
            for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(packets)) * 100
                print(f"  {protocol}: {count} ({percentage:.1f}%)")
            
            # HTTP analysis
            http_packets = [p for p in packets if 'http_data' in p]
            if http_packets:
                print(f"\nHTTP packets: {len(http_packets)}")
                
                # Most requested URLs
                uris = {}
                for packet in http_packets:
                    http_data = packet['http_data']
                    if 'uri' in http_data:
                        uri = http_data['uri']
                        uris[uri] = uris.get(uri, 0) + 1
                
                if uris:
                    print(f"\nMost requested URLs:")
                    for uri, count in sorted(uris.items(), key=lambda x: x[1], reverse=True)[:5]:
                        print(f"  {uri}: {count}")
            
            # DNS analysis
            dns_packets = [p for p in packets if 'dns_query' in p]
            if dns_packets:
                print(f"\nDNS queries: {len(dns_packets)}")
                
                # Most queried domains
                domains = {}
                for packet in dns_packets:
                    dns_query = packet['dns_query']
                    if 'query_name' in dns_query:
                        domain = dns_query['query_name']
                        domains[domain] = domains.get(domain, 0) + 1
                
                if domains:
                    print(f"\nMost queried domains:")
                    for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]:
                        print(f"  {domain}: {count}")
        
        except Exception as e:
            self.logger.error(f"Error analyzing capture: {e}")
            print(f"[!] Error analyzing capture: {e}")

def main():
    """
    Command line interface for Packet Sniffer
    """
    parser = argparse.ArgumentParser(description='Packet Sniffer - Ethical Hacking Tools')
    parser.add_argument('-i', '--interface', help='Network interface to sniff')
    parser.add_argument('-f', '--filter', help='BPF filter string')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-t', '--timeout', type=int, help='Timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-a', '--analyze', help='Analyze existing capture file')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy library not available.")
        print("[!] Install with: pip install scapy")
        return
    
    sniffer = PacketSniffer()
    
    if args.list_interfaces:
        interfaces = sniffer.get_available_interfaces()
        print("\nAvailable network interfaces:")
        for interface, ip in interfaces:
            print(f"  {interface}: {ip}")
        return
    
    if args.analyze:
        sniffer.analyze_capture(args.analyze)
    else:
        sniffer.sniff(
            interface=args.interface,
            filter_str=args.filter,
            count=args.count,
            timeout=args.timeout
        )

if __name__ == "__main__":
    main()
