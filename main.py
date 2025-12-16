#!/usr/bin/env python3
"""
Ethical Hacking Tools Suite - Main Entry Point
Educational and Testing Purposes Only

This suite contains various ethical hacking tools for educational purposes.
Use responsibly and only on systems you own or have explicit permission to test.
"""

import argparse
import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ethical_hacking_tools.port_scanner import PortScanner
from ethical_hacking_tools.vulnerability_scanner import VulnerabilityScanner
from ethical_hacking_tools.password_cracker import PasswordCracker
from ethical_hacking_tools.keylogger import Keylogger
from ethical_hacking_tools.packet_sniffer import PacketSniffer
from ethical_hacking_tools.exploitation_scripts import ExploitationTester
from ethical_hacking_tools.wifi_tools import WiFiTools
from ethical_hacking_tools.utils.logger import setup_logger

def main():
    """Main entry point for the Ethical Hacking Tools Suite"""
    
    # Setup logging
    logger = setup_logger()
    logger.info("Ethical Hacking Tools Suite started")
    
    parser = argparse.ArgumentParser(
        description="Ethical Hacking Tools Suite - Educational Purposes Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py port-scan -t 192.168.1.1 -p 1-1000
  python main.py vuln-scan -t http://example.com
  python main.py password-crack -f passwords.txt --hash 5d41402abc4b2a76b9719d911017c592
  python main.py packet-sniff -i eth0
  python main.py wifi-scan
        """
    )
    
    subparsers = parser.add_subparsers(dest='tool', help='Available tools')
    
    # Port Scanner
    port_parser = subparsers.add_parser('port-scan', help='Scan for open ports')
    port_parser.add_argument('-t', '--target', required=True, help='Target IP address')
    port_parser.add_argument('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000, 80,443,22)')
    port_parser.add_argument('-T', '--threads', type=int, default=100, help='Number of threads')
    port_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Vulnerability Scanner
    vuln_parser = subparsers.add_parser('vuln-scan', help='Scan for vulnerabilities')
    vuln_parser.add_argument('-t', '--target', required=True, help='Target URL or IP')
    vuln_parser.add_argument('-p', '--port', type=int, default=80, help='Target port')
    vuln_parser.add_argument('-s', '--scan-type', choices=['web', 'network'], default='web', help='Scan type')
    
    # Password Cracker
    pass_parser = subparsers.add_parser('password-crack', help='Crack passwords')
    pass_parser.add_argument('-f', '--wordlist', required=True, help='Wordlist file')
    pass_parser.add_argument('--hash', required=True, help='Hash to crack')
    pass_parser.add_argument('-a', '--algorithm', default='md5', help='Hash algorithm')
    
    # Keylogger
    key_parser = subparsers.add_parser('keylog', help='Start keylogger (ethical testing only)')
    key_parser.add_argument('-o', '--output', default='keystrokes.log', help='Output file')
    key_parser.add_argument('-t', '--timeout', type=int, default=60, help='Timeout in seconds')
    
    # Packet Sniffer
    sniff_parser = subparsers.add_parser('packet-sniff', help='Sniff network packets')
    sniff_parser.add_argument('-i', '--interface', required=True, help='Network interface')
    sniff_parser.add_argument('-f', '--filter', help='BPF filter')
    sniff_parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    
    # Exploitation Scripts
    exploit_parser = subparsers.add_parser('exploit-test', help='Test for common vulnerabilities')
    exploit_parser.add_argument('-t', '--target', required=True, help='Target URL')
    exploit_parser.add_argument('-v', '--vulnerability', choices=['sql', 'xss', 'headers'], help='Vulnerability type')
    
    # WiFi Tools
    wifi_parser = subparsers.add_parser('wifi-scan', help='Scan WiFi networks')
    wifi_parser.add_argument('-i', '--interface', help='Wireless interface')
    wifi_parser.add_argument('-c', '--crack', help='Attempt to crack WPA handshake')
    
    args = parser.parse_args()
    
    if not args.tool:
        parser.print_help()
        return
    
    try:
        if args.tool == 'port-scan':
            scanner = PortScanner()
            scanner.scan(args.target, args.ports, args.threads, args.verbose)
            
        elif args.tool == 'vuln-scan':
            scanner = VulnerabilityScanner()
            scanner.scan(args.target, args.port, args.scan_type)
            
        elif args.tool == 'password-crack':
            cracker = PasswordCracker()
            cracker.crack(args.wordlist, args.hash, args.algorithm)
            
        elif args.tool == 'keylog':
            logger.warning("Starting keylogger for ethical testing purposes only")
            keylogger = Keylogger()
            keylogger.start(args.output, args.timeout)
            
        elif args.tool == 'packet-sniff':
            sniffer = PacketSniffer()
            sniffer.sniff(args.interface, args.filter, args.count)
            
        elif args.tool == 'exploit-test':
            tester = ExploitationTester()
            tester.test(args.target, args.vulnerability)
            
        elif args.tool == 'wifi-scan':
            wifi = WiFiTools()
            wifi.scan(args.interface)
            
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"[!] Error: {e}")
    
    logger.info("Ethical Hacking Tools Suite finished")

if __name__ == "__main__":
    main()
