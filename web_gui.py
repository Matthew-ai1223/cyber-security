#!/usr/bin/env python3
"""
Ethical Hacking Tools Suite - Flask Web Server
Educational and Testing Purposes Only

Flask backend for the web GUI interface
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, stream_template
from flask_cors import CORS
import tempfile
import uuid
import hashlib
import secrets
from functools import wraps

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Serve frontend assets from the new frontend/ folder
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "frontend"),
    static_folder=os.path.join(BASE_DIR, "frontend", "static"),
    static_url_path="/static"
)
CORS(app)

# Security configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Rate limiting
request_counts = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # max requests per window

# Authentication (simple token-based for demo)
AUTH_TOKEN = os.environ.get('ETHICAL_HACKING_TOKEN', secrets.token_hex(32))

# Global variables for managing running tools
running_tools = {}
tool_threads = {}
logger = setup_logger('web_gui')

def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        current_time = time.time()
        
        # Clean old entries
        if client_ip in request_counts:
            request_counts[client_ip] = [
                req_time for req_time in request_counts[client_ip]
                if current_time - req_time < RATE_LIMIT_WINDOW
            ]
        else:
            request_counts[client_ip] = []
        
        # Check rate limit
        if len(request_counts[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return jsonify({'error': 'Rate limit exceeded'}), 429
        
        # Add current request
        request_counts[client_ip].append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != f'Bearer {AUTH_TOKEN}':
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def validate_input(data, required_fields=None, max_lengths=None):
    """Validate input data"""
    if not isinstance(data, dict):
        return False, "Invalid data format"
    
    # Check required fields
    if required_fields:
        for field in required_fields:
            if field not in data or not data[field]:
                return False, f"Missing required field: {field}"
    
    # Check field lengths
    if max_lengths:
        for field, max_length in max_lengths.items():
            if field in data and len(str(data[field])) > max_length:
                return False, f"Field {field} exceeds maximum length"
    
    return True, "Valid"

def sanitize_filename(filename):
    """Sanitize filename for security"""
    # Remove path components
    filename = os.path.basename(filename)
    # Remove dangerous characters
    dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    return filename

class ToolManager:
    """Manages running tools and their output streams"""
    
    def __init__(self):
        self.tools = {}
        self.output_streams = {}
        self.stop_flags = {}
    
    def start_tool(self, tool_name, tool_instance, method_name, *args, **kwargs):
        """Start a tool in a separate thread"""
        tool_id = str(uuid.uuid4())
        
        # Create output stream
        self.output_streams[tool_id] = []
        self.stop_flags[tool_id] = False
        
        # Start tool in thread
        thread = threading.Thread(
            target=self._run_tool,
            args=(tool_id, tool_name, tool_instance, method_name, args, kwargs)
        )
        thread.daemon = True
        thread.start()
        
        self.tools[tool_id] = {
            'thread': thread,
            'tool_name': tool_name,
            'start_time': time.time(),
            'status': 'running'
        }
        
        return tool_id
    
    def _run_tool(self, tool_id, tool_name, tool_instance, method_name, args, kwargs):
        """Run tool and capture output"""
        try:
            # Add output callback to kwargs
            kwargs['output_callback'] = lambda msg, level='info': self._add_output(tool_id, msg, level)
            
            # Call the tool method
            method = getattr(tool_instance, method_name)
            result = method(*args, **kwargs)
            
            # Add completion message
            self._add_output(tool_id, f"{tool_name.replace('_', ' ').title()} completed successfully", 'success')
            self._add_output(tool_id, json.dumps({'type': 'complete', 'result': result}), 'info')
            
        except Exception as e:
            self._add_output(tool_id, f"Error: {str(e)}", 'error')
            logger.error(f"Tool {tool_name} error: {e}")
        
        finally:
            self.tools[tool_id]['status'] = 'completed'
    
    def _add_output(self, tool_id, message, level='info'):
        """Add output to stream"""
        if tool_id in self.output_streams:
            self.output_streams[tool_id].append({
                'message': message,
                'level': level,
                'timestamp': datetime.now().isoformat()
            })
    
    def get_output_stream(self, tool_id):
        """Get output stream for a tool"""
        return self.output_streams.get(tool_id, [])
    
    def stop_tool(self, tool_id):
        """Stop a running tool"""
        if tool_id in self.stop_flags:
            self.stop_flags[tool_id] = True
            self._add_output(tool_id, "Tool stopped by user", 'warning')
    
    def stop_all_tools(self):
        """Stop all running tools"""
        for tool_id in self.stop_flags:
            self.stop_flags[tool_id] = True
            self._add_output(tool_id, "All tools stopped", 'warning')
    
    def cleanup_completed_tools(self):
        """Clean up completed tools"""
        completed_tools = []
        for tool_id, tool_info in self.tools.items():
            if tool_info['status'] == 'completed' and not tool_info['thread'].is_alive():
                completed_tools.append(tool_id)
        
        for tool_id in completed_tools:
            del self.tools[tool_id]
            if tool_id in self.output_streams:
                del self.output_streams[tool_id]
            if tool_id in self.stop_flags:
                del self.stop_flags[tool_id]

# Global tool manager
tool_manager = ToolManager()

@app.route('/')
def index():
    """Serve the main GUI page"""
    return render_template('index.html')

@app.route('/api/port-scanner', methods=['POST'])
@rate_limit
def api_port_scanner():
    """Port Scanner API endpoint"""
    try:
        data = request.get_json()
        
        # Validate input
        is_valid, error_msg = validate_input(
            data, 
            required_fields=['target'],
            max_lengths={'target': 255, 'ports': 100}
        )
        if not is_valid:
            return jsonify({'error': error_msg}), 400
        
        # Create scanner instance
        scanner = PortScanner()
        
        # Start scanning
        tool_id = tool_manager.start_tool(
            'port_scanner',
            scanner,
            'scan',
            data['target'],
            data.get('ports', '1-1000'),
            data.get('threads', 100),
            data.get('verbose', False),
            data.get('scanType', 'tcp_connect')
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Port scanner API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability-scanner', methods=['POST'])
def api_vulnerability_scanner():
    """Vulnerability Scanner API endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('target'):
            return jsonify({'error': 'Target is required'}), 400
        
        scanner = VulnerabilityScanner()
        
        tool_id = tool_manager.start_tool(
            'vulnerability_scanner',
            scanner,
            'scan',
            data['target'],
            data.get('port', 80),
            data.get('scanType', 'web')
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Vulnerability scanner API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/password-cracker', methods=['POST'])
def api_password_cracker():
    """Password Cracker API endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('hash'):
            return jsonify({'error': 'Hash is required'}), 400
        
        # Handle wordlist file
        wordlist_file = None
        if 'wordlist' in data and data['wordlist']:
            # Save uploaded wordlist to temporary file
            wordlist_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            wordlist_file.write(data['wordlist'])
            wordlist_file.close()
            wordlist_file = wordlist_file.name
        
        cracker = PasswordCracker()
        
        tool_id = tool_manager.start_tool(
            'password_cracker',
            cracker,
            'crack',
            wordlist_file or 'common_passwords.txt',
            data['hash'],
            data.get('algorithm', 'md5'),
            data.get('attackType', 'dictionary'),
            max_length=data.get('maxLength', 6),
            char_set=data.get('charSet', 'alphanum')
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Password cracker API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/keylogger', methods=['POST'])
def api_keylogger():
    """Keylogger API endpoint"""
    try:
        data = request.get_json()
        
        keylogger = Keylogger()
        
        tool_id = tool_manager.start_tool(
            'keylogger',
            keylogger,
            'start',
            data.get('output', 'keystrokes.log'),
            data.get('timeout', 60),
            data.get('screenshots', False),
            data.get('mouseCapture', False),
            data.get('processMonitor', False)
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Keylogger API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/packet-sniffer', methods=['POST'])
def api_packet_sniffer():
    """Packet Sniffer API endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('interface'):
            return jsonify({'error': 'Interface is required'}), 400
        
        sniffer = PacketSniffer()
        
        tool_id = tool_manager.start_tool(
            'packet_sniffer',
            sniffer,
            'sniff',
            data['interface'],
            data.get('filter'),
            data.get('count'),
            data.get('timeout')
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Packet sniffer API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/exploitation-scripts', methods=['POST'])
def api_exploitation_scripts():
    """Exploitation Scripts API endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('target'):
            return jsonify({'error': 'Target is required'}), 400
        
        tester = ExploitationTester()
        
        tool_id = tool_manager.start_tool(
            'exploitation_scripts',
            tester,
            'test',
            data['target'],
            data.get('vulnerability')
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"Exploitation scripts API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi-tools', methods=['POST'])
def api_wifi_tools():
    """WiFi Tools API endpoint"""
    try:
        data = request.get_json()
        
        wifi = WiFiTools()
        
        tool_id = tool_manager.start_tool(
            'wifi_tools',
            wifi,
            'scan',
            data.get('interface'),
            data.get('duration', 30)
        )
        
        return jsonify({'tool_id': tool_id, 'status': 'started'})
        
    except Exception as e:
        logger.error(f"WiFi tools API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/output/<tool_id>')
def api_output(tool_id):
    """Stream output for a specific tool"""
    def generate():
        while True:
            if tool_id in tool_manager.output_streams:
                output_stream = tool_manager.output_streams[tool_id]
                if output_stream:
                    # Send new output
                    for output in output_stream:
                        yield f"data: {json.dumps(output)}\n\n"
                    
                    # Clear sent output
                    tool_manager.output_streams[tool_id] = []
                else:
                    # Check if tool is still running
                    if tool_id not in tool_manager.tools or tool_manager.tools[tool_id]['status'] == 'completed':
                        yield f"data: {json.dumps({'type': 'complete'})}\n\n"
                        break
            else:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Tool not found'})}\n\n"
                break
            
            time.sleep(0.1)  # Small delay to prevent excessive CPU usage
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/stop', methods=['POST'])
def api_stop():
    """Stop all running tools"""
    try:
        tool_manager.stop_all_tools()
        return jsonify({'status': 'stopped'})
    except Exception as e:
        logger.error(f"Stop API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop/<tool_id>', methods=['POST'])
def api_stop_tool(tool_id):
    """Stop a specific tool"""
    try:
        tool_manager.stop_tool(tool_id)
        return jsonify({'status': 'stopped'})
    except Exception as e:
        logger.error(f"Stop tool API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/status')
def api_status():
    """Get status of all tools"""
    try:
        tool_manager.cleanup_completed_tools()
        
        status = {
            'running_tools': len(tool_manager.tools),
            'tools': {}
        }
        
        for tool_id, tool_info in tool_manager.tools.items():
            status['tools'][tool_id] = {
                'name': tool_info['tool_name'],
                'status': tool_info['status'],
                'start_time': tool_info['start_time'],
                'duration': time.time() - tool_info['start_time']
            }
        
        return jsonify(status)
    except Exception as e:
        logger.error(f"Status API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/upload', methods=['POST'])
def api_upload_file():
    """Upload file endpoint"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save file to temporary location
        filename = f"{uuid.uuid4()}_{file.filename}"
        filepath = os.path.join(tempfile.gettempdir(), filename)
        file.save(filepath)
        
        return jsonify({'filename': filename, 'filepath': filepath})
        
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download/<filename>')
def api_download_file(filename):
    """Download file endpoint"""
    try:
        filepath = os.path.join(tempfile.gettempdir(), filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        return Response(
            open(filepath, 'rb').read(),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
        
    except Exception as e:
        logger.error(f"File download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/info')
def api_system_info():
    """Get system information"""
    try:
        import platform
        import psutil
        
        info = {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent
        }
        
        return jsonify(info)
    except Exception as e:
        logger.error(f"System info API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def cleanup_temp_files():
    """Clean up temporary files"""
    try:
        temp_dir = tempfile.gettempdir()
        for filename in os.listdir(temp_dir):
            if filename.startswith('ethical_hacking_'):
                filepath = os.path.join(temp_dir, filename)
                if os.path.isfile(filepath):
                    os.remove(filepath)
    except Exception as e:
        logger.error(f"Cleanup error: {e}")

if __name__ == '__main__':
    print("Ethical Hacking Tools Suite - Web GUI Server")
    print("=" * 50)
    print("WARNING: This is for educational purposes only!")
    print("Use only on systems you own or have permission to test!")
    print("=" * 50)
    
    # Cleanup on startup
    cleanup_temp_files()
    
    # Start the Flask server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
