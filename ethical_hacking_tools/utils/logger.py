#!/usr/bin/env python3
"""
Logging utilities for Ethical Hacking Tools Suite
"""

import logging
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def setup_logger(name='ethical_hacking', level=logging.INFO):
    """
    Setup logger with file and console handlers
    """
    # Create logs directory if it doesn't exist
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_handler = logging.FileHandler(
        os.path.join(log_dir, f'ethical_hacking_{timestamp}.log')
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with colored output for different log levels
    """
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

def log_activity(logger, activity, details=None):
    """
    Log specific activities with structured format
    """
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'activity': activity,
        'details': details or {}
    }
    
    logger.info(f"ACTIVITY: {activity} - {details}")
    return log_entry

def log_security_event(logger, event_type, target, result=None):
    """
    Log security-related events
    """
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'target': target,
        'result': result
    }
    
    logger.warning(f"SECURITY_EVENT: {event_type} on {target} - Result: {result}")
    return log_entry

def log_scan_result(logger, scan_type, target, ports_found=None, vulnerabilities=None):
    """
    Log scan results
    """
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'scan_type': scan_type,
        'target': target,
        'ports_found': ports_found or [],
        'vulnerabilities': vulnerabilities or []
    }
    
    logger.info(f"SCAN_RESULT: {scan_type} on {target} - Ports: {ports_found}, Vulnerabilities: {vulnerabilities}")
    return log_entry
