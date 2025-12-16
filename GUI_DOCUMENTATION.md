# Ethical Hacking Tools Suite - Web GUI Documentation

## 🌐 Web-Based Graphical User Interface

A modern, responsive web interface for the Ethical Hacking Tools Suite that provides an intuitive way to use all the tools through a browser.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install flask flask-cors
```

### 2. Start the Web Server
```bash
python start_gui.py
```

### 3. Access the Interface
Open your browser and navigate to: `http://localhost:5000`

## 📋 Features

### 🎨 Modern Interface
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark/Light Theme**: Toggle between themes
- **Real-time Output**: Live streaming of tool output
- **Progress Tracking**: Visual progress indicators
- **File Management**: Upload/download files through the interface

### 🛠️ Tool Integration
All command-line tools are available through the web interface:

1. **Port Scanner**
   - Target IP address input
   - Port range configuration
   - Scan type selection (TCP Connect, SYN, UDP)
   - Thread count adjustment
   - Banner grabbing option

2. **Vulnerability Scanner**
   - Web application scanning
   - Network service scanning
   - Security header analysis
   - Sensitive file detection

3. **Password Cracker**
   - File upload for wordlists
   - Hash input (text area)
   - Algorithm selection
   - Attack type configuration
   - Brute force options

4. **Keylogger**
   - Output file configuration
   - Timeout settings
   - Screenshot capture
   - Mouse click logging
   - Process monitoring

5. **Packet Sniffer**
   - Network interface selection
   - BPF filter configuration
   - Packet count limits
   - Timeout settings

6. **Exploitation Scripts**
   - Target URL input
   - Vulnerability type selection
   - Automated testing

7. **WiFi Tools**
   - Interface selection
   - Scan duration configuration
   - Handshake capture options

## 🔧 Configuration

### Settings Panel
Access settings by clicking the gear icon in the header:

- **API URL**: Backend server URL (default: http://localhost:5000)
- **Theme**: Dark or Light theme selection
- **Auto-scroll**: Automatically scroll output panel

### Keyboard Shortcuts
- `Ctrl+K`: Clear output
- `Ctrl+S`: Open settings
- `Ctrl+Q`: Stop all tools

## 📁 File Structure

```
ethical_hacking_tools/
├── templates/
│   └── index.html          # Main GUI template
├── static/
│   ├── css/
│   │   └── style.css      # Styling
│   └── js/
│       └── app.js         # JavaScript functionality
├── web_gui.py             # Flask backend server
├── start_gui.py           # GUI launcher script
└── logs/                  # Log files
```

## 🔒 Security Features

### Authentication
- Token-based authentication (configurable via environment variable)
- Rate limiting to prevent abuse
- Input validation and sanitization

### File Security
- File upload size limits (16MB max)
- Filename sanitization
- Temporary file cleanup

### Network Security
- CORS configuration
- Request rate limiting
- Input validation

## 🌐 API Endpoints

### Tool Endpoints
- `POST /api/port-scanner` - Start port scanning
- `POST /api/vulnerability-scanner` - Start vulnerability scanning
- `POST /api/password-cracker` - Start password cracking
- `POST /api/keylogger` - Start keylogger
- `POST /api/packet-sniffer` - Start packet sniffing
- `POST /api/exploitation-scripts` - Start exploitation testing
- `POST /api/wifi-tools` - Start WiFi scanning

### Control Endpoints
- `POST /api/stop` - Stop all tools
- `POST /api/stop/<tool_id>` - Stop specific tool
- `GET /api/status` - Get tool status
- `GET /api/output/<tool_id>` - Stream tool output

### File Endpoints
- `POST /api/files/upload` - Upload files
- `GET /api/files/download/<filename>` - Download files

### System Endpoints
- `GET /api/system/info` - Get system information

## 📊 Real-time Output

The GUI provides real-time output streaming with:

- **Live Updates**: See results as they happen
- **Color Coding**: Different colors for success, error, warning, info
- **Timestamps**: Each output line includes timestamp
- **Download**: Save output to file
- **Clear**: Clear output panel
- **Collapse**: Minimize output panel

## 🎯 Usage Examples

### Port Scanning
1. Select "Port Scanner" from the sidebar
2. Enter target IP address (e.g., 192.168.1.1)
3. Configure port range (e.g., 1-1000)
4. Select scan type and options
5. Click "Start Scan"
6. Monitor real-time output

### Password Cracking
1. Select "Password Cracker" from the sidebar
2. Upload a wordlist file
3. Enter the hash to crack
4. Select hash algorithm
5. Choose attack type
6. Click "Start Cracking"
7. Watch for password discovery

### Vulnerability Scanning
1. Select "Vulnerability Scanner" from the sidebar
2. Enter target URL or IP
3. Select scan type (web/network)
4. Click "Start Scan"
5. Review discovered vulnerabilities

## 🔧 Troubleshooting

### Common Issues

1. **Server Won't Start**
   - Check if port 5000 is available
   - Ensure Flask is installed
   - Check Python version compatibility

2. **Tools Not Working**
   - Verify all dependencies are installed
   - Check system permissions
   - Review error messages in output panel

3. **File Upload Issues**
   - Check file size limits
   - Ensure file format is supported
   - Verify file permissions

4. **Network Issues**
   - Check firewall settings
   - Verify network interface availability
   - Ensure proper permissions

### Debug Mode
Enable debug mode by setting environment variable:
```bash
export FLASK_DEBUG=1
python web_gui.py
```

## 🌍 Browser Compatibility

- **Chrome**: Full support
- **Firefox**: Full support
- **Safari**: Full support
- **Edge**: Full support
- **Mobile Browsers**: Responsive design support

## 📱 Mobile Support

The GUI is fully responsive and works on mobile devices:
- Touch-friendly interface
- Responsive layout
- Mobile-optimized controls
- Swipe navigation

## 🔄 Updates and Maintenance

### Log Management
- Logs are automatically rotated
- Old logs are cleaned up periodically
- Log levels can be configured

### Performance Optimization
- Output buffering for smooth streaming
- Efficient memory management
- Background cleanup processes

## ⚠️ Security Considerations

### Production Deployment
- Change default authentication token
- Use HTTPS in production
- Configure proper firewall rules
- Regular security updates

### Access Control
- Limit access to authorized users only
- Use strong authentication
- Monitor access logs
- Regular security audits

## 🆘 Support

### Getting Help
1. Check the output panel for error messages
2. Review the logs in the `logs/` directory
3. Verify all dependencies are installed
4. Check system permissions

### Reporting Issues
When reporting issues, include:
- Browser type and version
- Operating system
- Error messages from output panel
- Steps to reproduce the issue

## 📈 Future Enhancements

### Planned Features
- User authentication system
- Tool result history
- Report generation
- Plugin system
- Advanced analytics
- Cloud integration

### Contributing
Contributions are welcome! Please ensure:
- Code follows security best practices
- Proper error handling
- Documentation updates
- Testing coverage

---

**Remember: This GUI is for educational and ethical testing purposes only. Use responsibly and legally!**
