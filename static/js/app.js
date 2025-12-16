// Ethical Hacking Tools Suite - Web GUI JavaScript

class EthicalHackingGUI {
    constructor() {
        this.currentTool = 'port-scanner';
        this.isRunning = false;
        this.outputBuffer = [];
        this.settings = {
            apiUrl: 'http://localhost:5000',
            theme: 'dark',
            autoScroll: true
        };
        
        this.init();
    }

    init() {
        this.loadSettings();
        this.setupEventListeners();
        this.updateTheme();
        this.updateTime();
        this.setupToolPanels();
        
        // Update time every second
        setInterval(() => this.updateTime(), 1000);
    }

    loadSettings() {
        const savedSettings = localStorage.getItem('ethicalHackingSettings');
        if (savedSettings) {
            this.settings = { ...this.settings, ...JSON.parse(savedSettings) };
        }
    }

    saveSettings() {
        localStorage.setItem('ethicalHackingSettings', JSON.stringify(this.settings));
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const tool = e.currentTarget.dataset.tool;
                this.switchTool(tool);
            });
        });

        // Tool forms
        document.querySelectorAll('.tool-form').forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleFormSubmit(e.target);
            });
        });

        // Output panel controls
        document.getElementById('clearOutputBtn').addEventListener('click', () => {
            this.clearOutput();
        });

        document.getElementById('downloadOutputBtn').addEventListener('click', () => {
            this.downloadOutput();
        });

        document.getElementById('toggleOutputBtn').addEventListener('click', () => {
            this.toggleOutputPanel();
        });

        // Settings modal
        document.getElementById('settingsBtn').addEventListener('click', () => {
            this.openSettingsModal();
        });

        document.getElementById('closeSettingsModal').addEventListener('click', () => {
            this.closeSettingsModal();
        });

        document.getElementById('saveSettings').addEventListener('click', () => {
            this.saveSettingsFromModal();
        });

        // Stop all button
        document.getElementById('stopAllBtn').addEventListener('click', () => {
            this.stopAllTools();
        });

        // Attack type change for password cracker
        document.getElementById('attackType').addEventListener('change', (e) => {
            this.toggleBruteForceOptions(e.target.value);
        });

        // Handshake capture toggle for WiFi tools
        document.getElementById('captureHandshake').addEventListener('change', (e) => {
            this.toggleHandshakeOptions(e.target.checked);
        });

        // Theme change
        document.getElementById('theme').addEventListener('change', (e) => {
            this.settings.theme = e.target.value;
            this.updateTheme();
        });

        // Auto-scroll toggle
        document.getElementById('autoScroll').addEventListener('change', (e) => {
            this.settings.autoScroll = e.target.checked;
        });

        // Close modal when clicking outside
        document.getElementById('settingsModal').addEventListener('click', (e) => {
            if (e.target.id === 'settingsModal') {
                this.closeSettingsModal();
            }
        });
    }

    switchTool(tool) {
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-tool="${tool}"]`).classList.add('active');

        // Update panels
        document.querySelectorAll('.tool-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tool}-panel`).classList.add('active');

        this.currentTool = tool;
        this.updateStatus('Ready', 'ready');
    }

    async handleFormSubmit(form) {
        // Build a normalized payload with proper types
        const data = {};

        Array.from(form.elements).forEach(el => {
            if (!el.name) return;
            if (el.type === 'checkbox') {
                data[el.name] = el.checked;
            } else if (el.type === 'number') {
                const val = el.value.trim();
                if (val !== '') data[el.name] = Number(val);
            } else if (el.type === 'file') {
                // handled below asynchronously
            } else {
                data[el.name] = el.value;
            }
        });

        // Handle file inputs by reading content as text (backend expects content)
        const fileInputs = form.querySelectorAll('input[type="file"]');
        for (const input of fileInputs) {
            if (input.files && input.files.length > 0) {
                const file = input.files[0];
                const text = await file.text();
                data[input.name] = text;
            }
        }

        this.startTool(this.currentTool, data);
    }

    async startTool(tool, data) {
        if (this.isRunning) {
            this.addOutput('Error: Another tool is already running', 'error');
            return;
        }

        this.isRunning = true;
        this.updateStatus('Running', 'running');
        this.clearOutput();
        this.addOutput(`Starting ${tool.replace('-', ' ')}...`, 'info');

        try {
            const response = await fetch(`${this.settings.apiUrl}/api/${tool}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) {
                const errText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errText}`);
            }

            const json = await response.json();
            if (!json.tool_id) {
                throw new Error('No tool_id returned by server');
            }

            this.addOutput(`Tool started (id: ${json.tool_id})`, 'info');
            this.openOutputStream(json.tool_id);
        } catch (error) {
            this.addOutput(`Error: ${error.message}`, 'error');
            console.error('Tool execution error:', error);
            this.isRunning = false;
            this.updateStatus('Ready', 'ready');
        }
    }

    openOutputStream(toolId) {
        // Use Server-Sent Events to receive output
        const source = new EventSource(`${this.settings.apiUrl}/api/output/${toolId}`);

        source.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                // Backend may send either structured {type: ...} or {message, level}
                if (payload.type === 'complete') {
                    this.handleComplete(payload);
                    source.close();
                    this.isRunning = false;
                    this.updateStatus('Ready', 'ready');
                } else if (payload.type) {
                    this.handleStreamData(payload);
                } else if (payload.message) {
                    this.addOutput(payload.message, payload.level || 'info');
                } else {
                    // Fallback
                    this.addOutput(event.data, 'info');
                }
            } catch (e) {
                // Non-JSON line
                this.addOutput(event.data, 'info');
            }
        };

        source.onerror = () => {
            this.addOutput('Connection lost to output stream', 'warning');
            try { source.close(); } catch {}
            this.isRunning = false;
            this.updateStatus('Ready', 'ready');
        };
    }

    handleStreamData(data) {
        switch (data.type) {
            case 'output':
                this.addOutput(data.message, data.level || 'info');
                break;
            case 'progress':
                this.updateProgress(data.progress);
                break;
            case 'result':
                this.handleResult(data.result);
                break;
            case 'error':
                this.addOutput(data.message, 'error');
                break;
            case 'complete':
                this.handleComplete(data);
                break;
        }
    }

    addOutput(message, level = 'info') {
        const outputContent = document.getElementById('outputContent');
        const placeholder = outputContent.querySelector('.output-placeholder');
        
        if (placeholder) {
            placeholder.remove();
        }

        const line = document.createElement('div');
        line.className = `output-line ${level}`;
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        
        outputContent.appendChild(line);
        
        if (this.settings.autoScroll) {
            outputContent.scrollTop = outputContent.scrollHeight;
        }

        this.outputBuffer.push({ message, level, timestamp: new Date() });
    }

    clearOutput() {
        const outputContent = document.getElementById('outputContent');
        outputContent.innerHTML = `
            <div class="output-placeholder">
                <i class="fas fa-play-circle"></i>
                <p>Select a tool and start scanning to see output here</p>
            </div>
        `;
        this.outputBuffer = [];
    }

    downloadOutput() {
        if (this.outputBuffer.length === 0) {
            this.addOutput('No output to download', 'warning');
            return;
        }

        const content = this.outputBuffer.map(entry => 
            `[${entry.timestamp.toISOString()}] ${entry.message}`
        ).join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ethical_hacking_output_${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    toggleOutputPanel() {
        const panel = document.getElementById('outputPanel');
        const toggleBtn = document.getElementById('toggleOutputBtn');
        const icon = toggleBtn.querySelector('i');
        
        panel.classList.toggle('collapsed');
        
        if (panel.classList.contains('collapsed')) {
            icon.className = 'fas fa-chevron-up';
        } else {
            icon.className = 'fas fa-chevron-down';
        }
    }

    updateStatus(text, status) {
        const statusText = document.getElementById('statusText');
        const statusIndicator = document.getElementById('statusIndicator');
        
        statusText.textContent = text;
        statusIndicator.className = `fas fa-circle status-indicator ${status}`;
    }

    updateTime() {
        const timeElement = document.getElementById('currentTime');
        timeElement.textContent = new Date().toLocaleTimeString();
    }

    updateTheme() {
        document.documentElement.setAttribute('data-theme', this.settings.theme);
    }

    setupToolPanels() {
        // Initialize tool-specific functionality
        this.toggleBruteForceOptions('dictionary');
        this.toggleHandshakeOptions(false);
    }

    toggleBruteForceOptions(attackType) {
        const options = document.getElementById('bruteForceOptions');
        if (attackType === 'brute_force' || attackType === 'hybrid') {
            options.style.display = 'block';
        } else {
            options.style.display = 'none';
        }
    }

    toggleHandshakeOptions(enabled) {
        const options = document.getElementById('handshakeOptions');
        if (enabled) {
            options.style.display = 'block';
        } else {
            options.style.display = 'none';
        }
    }

    openSettingsModal() {
        const modal = document.getElementById('settingsModal');
        const apiUrl = document.getElementById('apiUrl');
        const theme = document.getElementById('theme');
        const autoScroll = document.getElementById('autoScroll');
        
        apiUrl.value = this.settings.apiUrl;
        theme.value = this.settings.theme;
        autoScroll.checked = this.settings.autoScroll;
        
        modal.classList.add('active');
    }

    closeSettingsModal() {
        document.getElementById('settingsModal').classList.remove('active');
    }

    saveSettingsFromModal() {
        const apiUrl = document.getElementById('apiUrl').value;
        const theme = document.getElementById('theme').value;
        const autoScroll = document.getElementById('autoScroll').checked;
        
        this.settings = { apiUrl, theme, autoScroll };
        this.saveSettings();
        this.updateTheme();
        this.closeSettingsModal();
        
        this.addOutput('Settings saved successfully', 'success');
    }

    async stopAllTools() {
        if (!this.isRunning) {
            this.addOutput('No tools are currently running', 'warning');
            return;
        }

        try {
            const response = await fetch(`${this.settings.apiUrl}/api/stop`, {
                method: 'POST'
            });

            if (response.ok) {
                this.addOutput('All tools stopped', 'success');
                this.isRunning = false;
                this.updateStatus('Ready', 'ready');
            } else {
                throw new Error('Failed to stop tools');
            }
        } catch (error) {
            this.addOutput(`Error stopping tools: ${error.message}`, 'error');
        }
    }

    handleResult(result) {
        this.addOutput('=== SCAN RESULTS ===', 'info');
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            this.addOutput(`Found ${result.vulnerabilities.length} vulnerabilities:`, 'warning');
            result.vulnerabilities.forEach((vuln, index) => {
                this.addOutput(`${index + 1}. ${vuln.type} - ${vuln.severity}`, vuln.severity.toLowerCase());
            });
        }
        
        if (result.open_ports && result.open_ports.length > 0) {
            this.addOutput(`Found ${result.open_ports.length} open ports:`, 'success');
            result.open_ports.forEach(port => {
                this.addOutput(`Port ${port.port}/tcp - ${port.service}`, 'success');
            });
        }
        
        if (result.password) {
            this.addOutput(`PASSWORD FOUND: ${result.password}`, 'success');
        }
    }

    handleComplete(data) {
        this.addOutput('=== SCAN COMPLETED ===', 'info');
        this.addOutput(`Duration: ${data.duration || 'Unknown'}`, 'info');
        this.addOutput(`Total attempts: ${data.attempts || 'Unknown'}`, 'info');
        
        if (data.summary) {
            this.addOutput(data.summary, 'info');
        }
    }

    updateProgress(progress) {
        // Update progress indicators if needed
        console.log('Progress:', progress);
    }
}

// Utility functions
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function validateIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

function validateURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function validatePort(port) {
    const portNum = parseInt(port);
    return portNum >= 1 && portNum <= 65535;
}

function validatePortRange(portRange) {
    const rangeRegex = /^(\d+)-(\d+)$/;
    const commaRegex = /^(\d+(?:,\d+)*)$/;
    
    if (rangeRegex.test(portRange)) {
        const [, start, end] = portRange.match(rangeRegex);
        return validatePort(start) && validatePort(end) && parseInt(start) <= parseInt(end);
    } else if (commaRegex.test(portRange)) {
        const ports = portRange.split(',');
        return ports.every(port => validatePort(port.trim()));
    } else {
        return validatePort(portRange);
    }
}

// Form validation
function validateForm(form) {
    const errors = [];
    
    // Target validation
    const targetInput = form.querySelector('input[name="target"]');
    if (targetInput) {
        const target = targetInput.value.trim();
        if (!target) {
            errors.push('Target is required');
        } else if (!validateIP(target) && !validateURL(target)) {
            errors.push('Invalid target IP or URL');
        }
    }
    
    // Port validation
    const portsInput = form.querySelector('input[name="ports"]');
    if (portsInput) {
        const ports = portsInput.value.trim();
        if (ports && !validatePortRange(ports)) {
            errors.push('Invalid port range');
        }
    }
    
    // Hash validation
    const hashInput = form.querySelector('textarea[name="hash"]');
    if (hashInput) {
        const hash = hashInput.value.trim();
        if (!hash) {
            errors.push('Hash is required');
        } else if (hash.length < 8) {
            errors.push('Hash appears to be too short');
        }
    }
    
    return errors;
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    window.ethicalHackingGUI = new EthicalHackingGUI();
    
    // Add form validation
    document.querySelectorAll('.tool-form').forEach(form => {
        form.addEventListener('submit', (e) => {
            const errors = validateForm(form);
            if (errors.length > 0) {
                e.preventDefault();
                errors.forEach(error => {
                    window.ethicalHackingGUI.addOutput(`Validation Error: ${error}`, 'error');
                });
            }
        });
    });
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey || e.metaKey) {
            switch (e.key) {
                case 'k':
                    e.preventDefault();
                    window.ethicalHackingGUI.clearOutput();
                    break;
                case 's':
                    e.preventDefault();
                    window.ethicalHackingGUI.openSettingsModal();
                    break;
                case 'q':
                    e.preventDefault();
                    window.ethicalHackingGUI.stopAllTools();
                    break;
            }
        }
    });
    
    console.log('Ethical Hacking Tools Suite GUI initialized');
});
