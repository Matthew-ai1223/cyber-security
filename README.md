# Ethical Hacking Tools Suite

A comprehensive collection of ethical hacking tools implemented in Python for educational and testing purposes only.

## ⚠️ IMPORTANT DISCLAIMER

**This tool suite is for educational and ethical testing purposes only. Use only on systems you own or have explicit permission to test. Unauthorized use may violate laws and regulations.**

## 🛠️ Tools Included

### 1. Port Scanner
- **File**: `ethical_hacking_tools/port_scanner.py`
- **Features**:
  - TCP Connect Scan
  - TCP SYN Scan (Half-open)
  - UDP Scan
  - Banner Grabbing
  - Multi-threaded scanning
  - Service detection

**Usage**:
```bash
python main.py port-scan -t 192.168.1.1 -p 1-1000 -T 100 -v
python main.py port-scan -t 192.168.1.1 -p 80,443,22 -s tcp_syn
python main.py port-scan -t 192.168.1.1 -p 1-1000 -b  # With banner grabbing
```

### 2. Vulnerability Scanner
- **File**: `ethical_hacking_tools/vulnerability_scanner.py`
- **Features**:
  - Web application scanning
  - Network service scanning
  - Security header analysis
  - Sensitive file detection
  - Default login page detection
  - Information disclosure checks
  - Outdated software detection

**Usage**:
```bash
python main.py vuln-scan -t http://example.com -s web
python main.py vuln-scan -t 192.168.1.1 -p 80 -s network
```

### 3. Password Cracker
- **File**: `ethical_hacking_tools/password_cracker.py`
- **Features**:
  - Dictionary attacks
  - Brute force attacks
  - Hybrid attacks
  - Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, bcrypt)
  - Password variations
  - Custom wordlist creation

**Usage**:
```bash
python main.py password-crack -f wordlist.txt --hash 5d41402abc4b2a76b9719d911017c592 -a md5
python main.py password-crack -f wordlist.txt --hash hash.txt -t brute_force -l 4 -c alphanum
python main.py password-crack --create-wordlist custom_wordlist.txt
```

### 4. Keylogger
- **File**: `ethical_hacking_tools/keylogger.py`
- **Features**:
  - Keystroke capture
  - Mouse click logging
  - Screenshot capture
  - Process monitoring
  - Log analysis
  - Exit combination (Ctrl+Shift+Q)

**Usage**:
```bash
python main.py keylog -o keystrokes.log -t 60 -s -m -p
python main.py keylog -a keystrokes.log  # Analyze existing log
```

### 5. Packet Sniffer
- **File**: `ethical_hacking_tools/packet_sniffer.py`
- **Features**:
  - Network traffic capture
  - HTTP request/response analysis
  - DNS query analysis
  - Protocol statistics
  - Security event detection
  - BPF filter support

**Usage**:
```bash
python main.py packet-sniff -i eth0 -f "tcp port 80" -c 100
python main.py packet-sniff -i wlan0 -t 60
python main.py packet-sniff -a capture.log  # Analyze existing capture
```

### 6. Exploitation Scripts
- **File**: `ethical_hacking_tools/exploitation_scripts.py`
- **Features**:
  - SQL Injection testing
  - Cross-Site Scripting (XSS) testing
  - Local File Inclusion (LFI) testing
  - Command Injection testing
  - HTTP header vulnerability testing

**Usage**:
```bash
python main.py exploit-test -t http://example.com/page.php?id=1
python main.py exploit-test -t http://example.com -v sql
python main.py exploit-test -t http://example.com -v xss
```

### 7. WiFi Tools
- **File**: `ethical_hacking_tools/wifi_tools.py`
- **Features**:
  - Network scanning
  - WPA handshake capture
  - Deauthentication attacks
  - WPA password cracking
  - Hidden network detection

**Usage**:
```bash
python main.py wifi-scan -i wlan0 -d 30
python main.py wifi-scan --capture AA:BB:CC:DD:EE:FF --channel 6
python main.py wifi-scan --deauth AA:BB:CC:DD:EE:FF --count 20
```

## 📋 Requirements

### Quick Installation (Recommended)
```bash
python install.py
```

### Manual Installation
```bash
pip install -r requirements.txt
```

**Note for Windows users**: The `netifaces` package requires Microsoft Visual C++ Build Tools. If installation fails, the tools will work with reduced functionality for network interface detection.

### Required Libraries:
- `scapy>=2.4.5` - Network packet manipulation
- `requests>=2.28.0` - HTTP requests
- `beautifulsoup4>=4.11.0` - HTML parsing
- `cryptography>=3.4.8` - Cryptographic functions
- `bcrypt>=4.0.0` - Password hashing
- `passlib>=1.7.4` - Password hashing library
- `pynput>=1.7.6` - Input monitoring
- `keyboard>=0.13.5` - Keyboard input
- `netifaces>=0.11.0` - Network interface detection
- `psutil>=5.9.0` - System utilities
- `selenium>=4.8.0` - Web automation
- `colorama>=0.4.6` - Colored terminal output
- `termcolor>=2.2.0` - Terminal colors
- `tqdm>=4.64.0` - Progress bars

### System Requirements:
- **Linux/Unix**: Full functionality (WiFi tools require aircrack-ng suite)
- **Windows**: Most features work (WiFi tools limited)
- **macOS**: Most features work (WiFi tools limited)

## 🚀 Quick Start

1. **Clone or download the project**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the main interface**:
   ```bash
   python main.py --help
   ```

## 📖 Detailed Usage Examples

### Port Scanning
```bash
# Basic port scan
python main.py port-scan -t 192.168.1.1 -p 1-1000

# Advanced scan with banner grabbing
python main.py port-scan -t 192.168.1.1 -p 1-1000 -b -T 200

# UDP scan
python main.py port-scan -t 192.168.1.1 -p 53,67,68 -s udp
```

### Vulnerability Assessment
```bash
# Web application scan
python main.py vuln-scan -t http://example.com

# Network service scan
python main.py vuln-scan -t 192.168.1.1 -p 22 -s network
```

### Password Security Testing
```bash
# Dictionary attack
python main.py password-crack -f common_passwords.txt --hash target_hash.txt -a sha256

# Brute force attack
python main.py password-crack -f wordlist.txt --hash hash.txt -t brute_force -l 6 -c all

# Create custom wordlist
python main.py password-crack --create-wordlist my_wordlist.txt
```

### Network Monitoring
```bash
# Capture network traffic
python main.py packet-sniff -i eth0 -f "tcp port 80" -c 1000

# Monitor specific protocol
python main.py packet-sniff -i wlan0 -f "udp port 53" -t 300
```

### Security Testing
```bash
# Test for SQL injection
python main.py exploit-test -t "http://example.com/page.php?id=1" -v sql

# Test for XSS
python main.py exploit-test -t "http://example.com/search.php?q=test" -v xss

# Comprehensive testing
python main.py exploit-test -t "http://example.com/page.php?id=1"
```

## 📁 Project Structure

```
ethical_hacking_tools/
├── __init__.py
├── port_scanner.py          # Port scanning functionality
├── vulnerability_scanner.py # Vulnerability assessment
├── password_cracker.py      # Password cracking tools
├── keylogger.py            # Keystroke monitoring
├── packet_sniffer.py       # Network traffic analysis
├── exploitation_scripts.py # Exploitation testing
├── wifi_tools.py           # WiFi security tools
└── utils/
    ├── __init__.py
    └── logger.py           # Logging utilities

main.py                     # Main entry point
requirements.txt            # Python dependencies
README.md                   # This file
logs/                      # Log files directory
```

## 🔒 Security Considerations

1. **Legal Compliance**: Only use on systems you own or have explicit permission to test
2. **Network Impact**: Some tools may generate significant network traffic
3. **Detection**: Tools may be detected by security systems
4. **Logging**: All activities are logged for audit purposes
5. **Ethics**: Use responsibly and ethically

## 📊 Logging and Monitoring

All tools include comprehensive logging:
- **Activity logs**: Track all operations
- **Security events**: Log security-related activities
- **Scan results**: Store scan outputs
- **Error handling**: Log errors and exceptions

Log files are stored in the `logs/` directory with timestamps.

## 🛡️ Ethical Guidelines

1. **Authorization**: Always obtain proper authorization before testing
2. **Scope**: Stay within the defined testing scope
3. **Documentation**: Document all findings and activities
4. **Responsibility**: Take responsibility for your actions
5. **Education**: Use for learning and improving security

## 🔧 Troubleshooting

### Common Issues:

1. **Permission Errors**: Some tools require root/administrator privileges
2. **Missing Dependencies**: Install all required packages
3. **Network Interface Issues**: Ensure correct interface names
4. **Firewall Blocking**: Check firewall settings

### Getting Help:

1. Check the logs in `logs/` directory
2. Verify all dependencies are installed
3. Ensure proper permissions
4. Check network connectivity

## 📝 License and Disclaimer

This project is for educational purposes only. The authors are not responsible for any misuse of these tools. Users must comply with all applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. Code follows ethical guidelines
2. Proper documentation is included
3. Security considerations are addressed
4. Testing is performed

## 📞 Support

For questions or issues:
1. Check the documentation
2. Review the logs
3. Ensure proper setup
4. Follow ethical guidelines

---

**Remember: With great power comes great responsibility. Use these tools ethically and legally.**
#   c y b e r - s e c u r i t y  
 