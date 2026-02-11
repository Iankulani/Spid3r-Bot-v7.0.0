#!/usr/bin/env python3
"""
🕸️ CYBERSECURITY SPIDER BOT PRO v7.0.0
Author: Ian Carter Kulani
Version: v7.0.0
Description: SpiderBot cybersecurity chat bot tool with 500+ commands, 
            Discord/Telegram integration, advanced monitoring,
            and comprehensive network analysis
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
import shutil
import urllib.parse
import asyncio
import uuid

# Optional imports with fallbacks
try:
    import discord
    from discord.ext import commands, tasks
    from discord import app_commands
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Warning: discord.py not available. Install with: pip install discord.py")

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Warning: telethon not available. Install with: pip install telethon")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Warning: whois not available. Install with: pip install python-whois")

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("⚠️ Warning: colorama not available. Install with: pip install colorama")

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".spiderbot_pro"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
LOG_FILE = os.path.join(CONFIG_DIR, "spiderbot.log")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
MONITORING_DIR = "monitoring"
BACKUPS_DIR = "backups"
TEMP_DIR = "temp"
SCRIPTS_DIR = "scripts"
NIKTO_RESULTS_DIR = "nikto_results"
BLOCKED_IPS_DIR = "blocked_ips"

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR,
    MONITORING_DIR, BACKUPS_DIR, TEMP_DIR, SCRIPTS_DIR,
    NIKTO_RESULTS_DIR, BLOCKED_IPS_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SpiderBotPro")

# Color setup
if COLORAMA_AVAILABLE:
    class Colors:
        RED = Fore.RED + Style.BRIGHT
        GREEN = Fore.GREEN + Style.BRIGHT
        YELLOW = Fore.YELLOW + Style.BRIGHT
        BLUE = Fore.BLUE + Style.BRIGHT
        CYAN = Fore.CYAN + Style.BRIGHT
        MAGENTA = Fore.MAGENTA + Style.BRIGHT
        WHITE = Fore.WHITE + Style.BRIGHT
        RESET = Style.RESET_ALL
else:
    class Colors:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""

# =====================
# DATA CLASSES & ENUMS
# =====================
class ScanType:
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    FULL = "full"
    UDP = "udp"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    NIKTO = "nikto"
    WEB_VULN = "web_vulnerability"

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    target: str
    scan_type: str
    open_ports: List[Dict]
    vulnerabilities: Optional[List[Dict]] = None
    timestamp: str = ""
    success: bool = True
    error: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()

@dataclass
class CommandResult:
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None
    data: Optional[Dict] = None

@dataclass
class NiktoResult:
    target: str
    scan_date: str
    findings: List[Dict]
    error: Optional[str] = None
    success: bool = True

@dataclass
class BlockedIP:
    ip_address: str
    blocked_date: str
    reason: str
    blocked_by: str
    is_active: bool = True

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Configuration manager"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000,
            "auto_block_malicious": False
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False,
            "nikto_enabled": True,
            "nikto_timeout": 300
        },
        "security": {
            "auto_block": False,
            "log_level": "INFO",
            "backup_enabled": True,
            "block_threshold": 5,
            "block_duration": 3600
        },
        "discord": {
            "enabled": False,
            "token": "",
            "channel_id": "",
            "prefix": "!",
            "admin_role": "Admin",
            "notify_on_block": True
        },
        "telegram": {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in ConfigManager.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    @staticmethod
    def save_telegram_config(config: Dict) -> bool:
        """Save Telegram configuration"""
        try:
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    @staticmethod
    def load_telegram_config() -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        return {}
    
    @staticmethod
    def save_discord_config(config: Dict) -> bool:
        """Save Discord configuration"""
        try:
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    @staticmethod
    def load_discord_config() -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        return {}

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            # Command history
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            
            # Threat alerts
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            
            # Scan results
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                vulnerabilities TEXT,
                services TEXT,
                os_info TEXT,
                execution_time REAL
            )
            """,
            
            # Nikto scan results
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                findings TEXT,
                severity TEXT,
                scan_duration REAL,
                error TEXT
            )
            """,
            
            # Monitored IPs
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                added_by TEXT DEFAULT 'system',
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                notes TEXT
            )
            """,
            
            # Blocked IPs
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                blocked_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                unblock_date TIMESTAMP,
                block_count INTEGER DEFAULT 1
            )
            """,
            
            # System metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                connections_count INTEGER
            )
            """,
            
            # Discord commands log
            """
            CREATE TABLE IF NOT EXISTS discord_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT,
                user_name TEXT,
                command TEXT,
                target TEXT,
                success BOOLEAN
            )
            """
        ]
        
        for table_sql in tables:
            self.cursor.execute(table_sql)
        
        self.conn.commit()
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, vulnerabilities, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, vulnerabilities_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_nikto_scan(self, target: str, findings: List[Dict], severity: str = "medium", 
                      scan_duration: float = 0.0, error: str = None):
        """Log Nikto scan results"""
        try:
            findings_json = json.dumps(findings) if findings else "[]"
            self.cursor.execute('''
                INSERT INTO nikto_scans (target, findings, severity, scan_duration, error)
                VALUES (?, ?, ?, ?, ?)
            ''', (target, findings_json, severity, scan_duration, error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Nikto scan: {e}")
    
    def add_monitored_ip(self, ip: str, notes: str = "", added_by: str = "system") -> bool:
        """Add IP to monitoring"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO monitored_ips (ip_address, notes, added_by) 
                VALUES (?, ?, ?)
            ''', (ip, notes, added_by))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add monitored IP: {e}")
            return False
    
    def remove_monitored_ip(self, ip: str) -> bool:
        """Remove IP from monitoring (soft delete)"""
        try:
            self.cursor.execute('''
                UPDATE monitored_ips 
                SET is_active = 0 
                WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove monitored IP: {e}")
            return False
    
    def get_monitored_ips(self, active_only: bool = True) -> List[Dict]:
        """Get monitored IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips WHERE is_active = 1 ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM monitored_ips ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get monitored IPs: {e}")
            return []
    
    def block_ip(self, ip: str, reason: str, blocked_by: str = "system") -> bool:
        """Block an IP address"""
        try:
            # Check if already blocked
            self.cursor.execute('''
                SELECT * FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            
            existing = self.cursor.fetchone()
            
            if existing:
                # Increment block count
                self.cursor.execute('''
                    UPDATE blocked_ips 
                    SET block_count = block_count + 1,
                        blocked_date = CURRENT_TIMESTAMP,
                        reason = ?,
                        blocked_by = ?
                    WHERE ip_address = ? AND is_active = 1
                ''', (reason, blocked_by, ip))
            else:
                # New block
                self.cursor.execute('''
                    INSERT INTO blocked_ips (ip_address, reason, blocked_by)
                    VALUES (?, ?, ?)
                ''', (ip, reason, blocked_by))
            
            self.conn.commit()
            
            # Also remove from monitored IPs if present
            self.cursor.execute('''
                UPDATE monitored_ips SET is_active = 0 WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            
            logger.info(f"IP {ip} blocked by {blocked_by}: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            self.cursor.execute('''
                UPDATE blocked_ips 
                SET is_active = 0, unblock_date = CURRENT_TIMESTAMP
                WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def get_blocked_ips(self, active_only: bool = True) -> List[Dict]:
        """Get blocked IPs"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY blocked_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM blocked_ips ORDER BY blocked_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        try:
            self.cursor.execute('''
                SELECT 1 FROM blocked_ips WHERE ip_address = ? AND is_active = 1
            ''', (ip,))
            return self.cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check blocked IP {ip}: {e}")
            return False
    
    def log_discord_command(self, user_id: str, user_name: str, command: str, 
                           target: str = "", success: bool = True):
        """Log Discord command usage"""
        try:
            self.cursor.execute('''
                INSERT INTO discord_commands (user_id, user_name, command, target, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, user_name, command, target[:100], success))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Discord command: {e}")
    
    def get_nikto_history(self, limit: int = 10) -> List[Dict]:
        """Get Nikto scan history"""
        try:
            self.cursor.execute('''
                SELECT * FROM nikto_scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get Nikto history: {e}")
            return []
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            # Count threats
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            # Count commands
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            # Count scans
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            # Count Nikto scans
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['total_nikto_scans'] = self.cursor.fetchone()[0]
            
            # Count monitored IPs
            self.cursor.execute('SELECT COUNT(*) FROM monitored_ips WHERE is_active = 1')
            stats['active_monitored_ips'] = self.cursor.fetchone()[0]
            
            # Count blocked IPs
            self.cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1')
            stats['active_blocked_ips'] = self.cursor.fetchone()[0]
            
            # Count Discord commands
            self.cursor.execute('SELECT COUNT(*) FROM discord_commands')
            stats['total_discord_commands'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# NETWORK TOOLS
# =====================
class NetworkTools:
    """Comprehensive network tools"""
    
    @staticmethod
    def execute_command(cmd: List[str], timeout: int = 300) -> CommandResult:
        """Execute shell command"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                execution_time=execution_time,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}"
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                error='Timeout'
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output='',
                execution_time=execution_time,
                error=str(e)
            )
    
    @staticmethod
    def ping(target: str, count: int = 4, size: int = 56, timeout: int = 1, 
             flood: bool = False, **kwargs) -> CommandResult:
        """Ping with advanced options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000)]
                if flood:
                    cmd.append('-t')
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout)]
                if flood:
                    cmd.append('-f')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout * count + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30, no_dns: bool = True, **kwargs) -> CommandResult:
        """Traceroute with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert']
                if no_dns:
                    cmd.append('-d')
                cmd.extend(['-h', str(max_hops)])
            else:
                if shutil.which('mtr'):
                    cmd = ['mtr', '--report', '--report-cycles', '1']
                    if no_dns:
                        cmd.append('-n')
                elif shutil.which('traceroute'):
                    cmd = ['traceroute']
                    if no_dns:
                        cmd.append('-n')
                    cmd.extend(['-m', str(max_hops)])
                elif shutil.which('tracepath'):
                    cmd = ['tracepath', '-m', str(max_hops)]
                else:
                    return CommandResult(
                        success=False,
                        output='No traceroute tool found',
                        execution_time=0,
                        error='No traceroute tool available'
                    )
            
            cmd.append(target)
            return NetworkTools.execute_command(cmd, timeout=60)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nmap_scan(target: str, scan_type: str = "quick", ports: str = None, **kwargs) -> CommandResult:
        """Nmap scan with options"""
        try:
            cmd = ['nmap']
            
            # Base scan type
            if scan_type == "quick":
                cmd.extend(['-T4', '-F'])
            elif scan_type == "quick_scan":
                cmd.extend(['-T4', '-F', '--max-rtt-timeout', '100ms', '--max-retries', '1'])
            elif scan_type == "comprehensive":
                cmd.extend(['-sS', '-sV', '-sC', '-A', '-O'])
            elif scan_type == "stealth":
                cmd.extend(['-sS', '-T2', '--max-parallelism', '100', '--scan-delay', '5s'])
            elif scan_type == "vulnerability":
                cmd.extend(['-sV', '--script', 'vuln'])
            elif scan_type == "full":
                cmd.extend(['-p-', '-T4'])
            elif scan_type == "udp":
                cmd.extend(['-sU', '-T4'])
            elif scan_type == "os_detection":
                cmd.extend(['-O', '--osscan-guess'])
            elif scan_type == "service_detection":
                cmd.extend(['-sV', '--version-intensity', '5'])
            
            # Custom ports
            if ports:
                if ports.isdigit():
                    cmd.extend(['-p', ports])
                else:
                    cmd.extend(['-p', ports])
            elif scan_type not in ["full"]:
                cmd.extend(['-p', '1-1000'])
            
            # Additional options
            if kwargs.get('no_ping'):
                cmd.append('-Pn')
            if kwargs.get('ipv6'):
                cmd.append('-6')
            
            cmd.append(target)
            
            return NetworkTools.execute_command(cmd, timeout=600)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nikto_scan(target: str, options: str = "", timeout: int = 300) -> CommandResult:
        """Nikto web vulnerability scanner"""
        try:
            if not shutil.which('nikto'):
                return CommandResult(
                    success=False,
                    output='Nikto is not installed. Install with: sudo apt-get install nikto or brew install nikto',
                    execution_time=0,
                    error='Nikto not found'
                )
            
            cmd = ['nikto', '-h', target, '-Format', 'json']
            
            # Add custom options
            if options:
                cmd.extend(options.split())
            
            # Common options for better output
            if '-ssl' not in cmd and '-nossl' not in cmd:
                cmd.append('-ssl')
            
            # Execute command
            result = NetworkTools.execute_command(cmd, timeout=timeout)
            
            # Try to parse JSON output if available
            if result.success:
                try:
                    # Nikto outputs JSON with a specific format
                    json_start = result.output.find('{')
                    if json_start != -1:
                        json_end = result.output.rfind('}') + 1
                        if json_end > json_start:
                            json_str = result.output[json_start:json_end]
                            parsed = json.loads(json_str)
                            result.data = parsed
                except:
                    pass
            
            return result
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def block_ip_firewall(ip: str, reason: str = "Manual block") -> CommandResult:
        """Block IP using firewall rules"""
        try:
            start_time = time.time()
            system = platform.system().lower()
            
            if system == 'linux':
                # Check if iptables is available
                if shutil.which('iptables'):
                    cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                    result = NetworkTools.execute_command(cmd)
                    if result.success:
                        # Save rules
                        NetworkTools.execute_command(['sudo', 'iptables-save'])
                elif shutil.which('ufw'):
                    cmd = ['sudo', 'ufw', 'deny', 'from', ip]
                    result = NetworkTools.execute_command(cmd)
                else:
                    result = CommandResult(
                        success=False,
                        output='No firewall tool found (iptables/ufw)',
                        execution_time=time.time() - start_time
                    )
            
            elif system == 'darwin':  # macOS
                if shutil.which('pfctl'):
                    # Add to pf.conf
                    cmd = ['sudo', 'pfctl', '-t', 'spiderbot', '-T', 'add', ip]
                    result = NetworkTools.execute_command(cmd)
                else:
                    result = CommandResult(
                        success=False,
                        output='pfctl not found',
                        execution_time=time.time() - start_time
                    )
            
            elif system == 'windows':
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                      f'name=SpiderBot_Block_{ip}', 'dir=in', 'action=block',
                      f'remoteip={ip}']
                result = NetworkTools.execute_command(cmd)
            
            else:
                result = CommandResult(
                    success=False,
                    output=f'Unsupported system: {system}',
                    execution_time=time.time() - start_time
                )
            
            result.execution_time = time.time() - start_time
            return result
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def unblock_ip_firewall(ip: str) -> CommandResult:
        """Unblock IP from firewall rules"""
        try:
            start_time = time.time()
            system = platform.system().lower()
            
            if system == 'linux':
                if shutil.which('iptables'):
                    cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                    result = NetworkTools.execute_command(cmd)
                    if result.success:
                        NetworkTools.execute_command(['sudo', 'iptables-save'])
                elif shutil.which('ufw'):
                    cmd = ['sudo', 'ufw', 'delete', 'deny', 'from', ip]
                    result = NetworkTools.execute_command(cmd)
                else:
                    result = CommandResult(
                        success=False,
                        output='No firewall tool found',
                        execution_time=time.time() - start_time
                    )
            
            elif system == 'darwin':
                if shutil.which('pfctl'):
                    cmd = ['sudo', 'pfctl', '-t', 'spiderbot', '-T', 'delete', ip]
                    result = NetworkTools.execute_command(cmd)
                else:
                    result = CommandResult(
                        success=False,
                        output='pfctl not found',
                        execution_time=time.time() - start_time
                    )
            
            elif system == 'windows':
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                      f'name=SpiderBot_Block_{ip}']
                result = NetworkTools.execute_command(cmd)
            
            else:
                result = CommandResult(
                    success=False,
                    output=f'Unsupported system: {system}',
                    execution_time=time.time() - start_time
                )
            
            result.execution_time = time.time() - start_time
            return result
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def curl_request(url: str, method: str = "GET", **kwargs) -> CommandResult:
        """cURL request"""
        try:
            cmd = ['curl', '-s', '-X', method]
            
            if kwargs.get('timeout'):
                cmd.extend(['-m', str(kwargs['timeout'])])
            if kwargs.get('headers'):
                for key, value in kwargs['headers'].items():
                    cmd.extend(['-H', f'{key}: {value}'])
            if kwargs.get('data'):
                cmd.extend(['-d', kwargs['data']])
            if kwargs.get('insecure'):
                cmd.append('-k')
            if kwargs.get('verbose'):
                cmd.append('-v')
            
            cmd.extend(['-w', '\nTime: %{time_total}s\nCode: %{http_code}\nSize: %{size_download} bytes\n'])
            cmd.append(url)
            
            return NetworkTools.execute_command(cmd, timeout=kwargs.get('timeout', 30) + 5)
            
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_ip_location(ip: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }
            
            return {'success': False, 'ip': ip, 'error': 'Location lookup failed'}
                
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}
    
    @staticmethod
    def whois_lookup(target: str) -> CommandResult:
        """WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return CommandResult(
                success=False,
                output='WHOIS not available',
                execution_time=0,
                error='Install python-whois package'
            )
        
        try:
            import whois
            start_time = time.time()
            result = whois.whois(target)
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=True,
                output=str(result),
                execution_time=execution_time
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> CommandResult:
        """DNS lookup"""
        try:
            cmd = ['dig', domain, record_type, '+short']
            return NetworkTools.execute_command(cmd, timeout=10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

# =====================
# NETWORK MONITOR
# =====================
class NetworkMonitor:
    """Network monitoring and threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.blocked_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'ddos': self.config.get('monitoring', {}).get('ddos_threshold', 1000)
        }
        self.threads = []
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        logger.info("Starting network monitoring...")
        
        # Load monitored IPs from database
        monitored = self.db.get_monitored_ips(active_only=True)
        self.monitored_ips = {ip['ip_address'] for ip in monitored}
        
        # Load blocked IPs from database
        blocked = self.db.get_blocked_ips(active_only=True)
        self.blocked_ips = {ip['ip_address'] for ip in blocked}
        
        # Start monitoring threads
        self.threads = [
            threading.Thread(target=self._monitor_system, daemon=True),
            threading.Thread(target=self._monitor_threats, daemon=True),
            threading.Thread(target=self._monitor_blocked_ips, daemon=True)
        ]
        
        for thread in self.threads:
            thread.start()
        
        logger.info(f"Network monitoring started with {len(self.threads)} threads")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.threads = []
        logger.info("Network monitoring stopped")
    
    def _monitor_system(self):
        """Monitor system metrics"""
        while self.monitoring:
            try:
                # Log system metrics to database
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                net = psutil.net_io_counters()
                connections = len(psutil.net_connections())
                
                # Check for high resource usage
                if cpu > 90:
                    self._create_threat_alert(
                        threat_type="High CPU Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"CPU usage at {cpu}%",
                        action_taken="Logged"
                    )
                
                if mem.percent > 90:
                    self._create_threat_alert(
                        threat_type="High Memory Usage",
                        source_ip="localhost",
                        severity="high",
                        description=f"Memory usage at {mem.percent}%",
                        action_taken="Logged"
                    )
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"System monitor error: {e}")
                time.sleep(10)
    
    def _monitor_threats(self):
        """Monitor for threats"""
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                
                # Analyze connections for threats
                source_counts = {}
                for conn in connections:
                    if conn.raddr:
                        source_ip = conn.raddr.ip
                        # Skip if already blocked
                        if not self.db.is_ip_blocked(source_ip):
                            source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
                
                # Check thresholds
                for source_ip, count in source_counts.items():
                    if count > self.thresholds['port_scan']:
                        # Auto-block if configured
                        action = "Monitoring"
                        if self.config.get('security', {}).get('auto_block', False):
                            if self.add_ip_to_block(source_ip, f"Port scan detected ({count} connections)"):
                                action = "Auto-blocked"
                        
                        self._create_threat_alert(
                            threat_type="Possible Port Scan",
                            source_ip=source_ip,
                            severity="medium",
                            description=f"{count} connections from this IP",
                            action_taken=action
                        )
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Threat monitor error: {e}")
                time.sleep(10)
    
    def _monitor_blocked_ips(self):
        """Monitor and enforce blocked IPs"""
        while self.monitoring:
            try:
                # Refresh blocked IPs from database
                blocked = self.db.get_blocked_ips(active_only=True)
                current_blocked = {ip['ip_address'] for ip in blocked}
                
                # Check for new blocks to enforce
                for ip in current_blocked - self.blocked_ips:
                    logger.info(f"Enforcing block for IP: {ip}")
                    NetworkTools.block_ip_firewall(ip, "Auto-enforcement")
                
                # Update set
                self.blocked_ips = current_blocked
                
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Blocked IP monitor error: {e}")
                time.sleep(10)
    
    def _create_threat_alert(self, threat_type: str, source_ip: str, 
                            severity: str, description: str, action_taken: str):
        """Create threat alert"""
        alert = ThreatAlert(
            timestamp=datetime.datetime.now().isoformat(),
            threat_type=threat_type,
            source_ip=source_ip,
            severity=severity,
            description=description,
            action_taken=action_taken
        )
        
        self.db.log_threat(alert)
        
        # Log to console with color
        if severity == "high":
            log_msg = f"{Colors.RED}🚨 HIGH THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        elif severity == "medium":
            log_msg = f"{Colors.YELLOW}⚠️ MEDIUM THREAT: {threat_type} from {source_ip}{Colors.RESET}"
        else:
            log_msg = f"{Colors.CYAN}ℹ️ INFO: {threat_type} from {source_ip}{Colors.RESET}"
        
        print(log_msg)
        logger.info(f"Threat alert: {threat_type} from {source_ip} ({severity})")
    
    def add_ip_to_monitoring(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            ipaddress.ip_address(ip)
            success = self.db.add_monitored_ip(ip, notes, added_by)
            if success:
                self.monitored_ips.add(ip)
                logger.info(f"Added IP to monitoring: {ip} (by {added_by})")
            return success
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            success = self.db.remove_monitored_ip(ip)
            if success and ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
                logger.info(f"Removed IP from monitoring: {ip}")
            return success
        except Exception as e:
            logger.error(f"Failed to remove IP from monitoring: {e}")
            return False
    
    def add_ip_to_block(self, ip: str, reason: str, blocked_by: str = "system") -> bool:
        """Add IP to block list"""
        try:
            ipaddress.ip_address(ip)
            success = self.db.block_ip(ip, reason, blocked_by)
            if success:
                self.blocked_ips.add(ip)
                # Also remove from monitoring
                self.remove_ip_from_monitoring(ip)
                
                # Apply firewall rule
                NetworkTools.block_ip_firewall(ip, reason)
                
                logger.info(f"Blocked IP: {ip} (by {blocked_by}, reason: {reason})")
            return success
        except ValueError:
            logger.error(f"Invalid IP address: {ip}")
            return False
    
    def remove_ip_from_block(self, ip: str) -> bool:
        """Remove IP from block list"""
        try:
            success = self.db.unblock_ip(ip)
            if success and ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                
                # Remove firewall rule
                NetworkTools.unblock_ip_firewall(ip)
                
                logger.info(f"Unblocked IP: {ip}")
            return success
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'monitored_ips': list(self.monitored_ips)[:10],
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips)[:10],
            'thresholds': self.thresholds,
            'auto_block': self.config.get('security', {}).get('auto_block', False)
        }

# =====================
# NIKTO PARSER
# =====================
class NiktoParser:
    """Parse Nikto scan results"""
    
    @staticmethod
    def parse_output(output: str) -> List[Dict]:
        """Parse Nikto text output into structured findings"""
        findings = []
        
        lines = output.split('\n')
        for line in lines:
            # Look for vulnerability findings
            if '+ ' in line and ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    finding = {
                        'type': parts[0].strip('+ '),
                        'description': parts[1].strip(),
                        'severity': NiktoParser._determine_severity(line)
                    }
                    findings.append(finding)
            
            # OSVDB findings
            elif 'OSVDB' in line:
                finding = {
                    'type': 'OSVDB Reference',
                    'description': line.strip(),
                    'severity': 'medium'
                }
                findings.append(finding)
            
            # HTTP method findings
            elif 'HTTP' in line and 'method' in line.lower():
                finding = {
                    'type': 'HTTP Method',
                    'description': line.strip(),
                    'severity': 'low'
                }
                findings.append(finding)
        
        return findings
    
    @staticmethod
    def parse_json_output(json_data: Dict) -> List[Dict]:
        """Parse Nikto JSON output"""
        findings = []
        
        if isinstance(json_data, dict):
            # Nikto JSON format
            if 'vulnerabilities' in json_data:
                for vuln in json_data['vulnerabilities']:
                    findings.append({
                        'id': vuln.get('id', 'N/A'),
                        'method': vuln.get('method', 'N/A'),
                        'url': vuln.get('url', 'N/A'),
                        'description': vuln.get('msg', 'N/A'),
                        'severity': NiktoParser._map_severity(vuln.get('severity', 0))
                    })
            
            elif 'findings' in json_data:
                for finding in json_data['findings']:
                    findings.append({
                        'type': finding.get('type', 'Unknown'),
                        'description': finding.get('description', 'N/A'),
                        'severity': finding.get('severity', 'medium')
                    })
        
        return findings
    
    @staticmethod
    def _determine_severity(line: str) -> str:
        """Determine severity from line content"""
        line_lower = line.lower()
        
        critical_keywords = ['critical', 'remote root', 'remote code execution', 'rce']
        high_keywords = ['high', 'sql injection', 'xss', 'cross-site', 'buffer overflow']
        medium_keywords = ['medium', 'information disclosure', 'directory listing']
        
        if any(k in line_lower for k in critical_keywords):
            return 'critical'
        elif any(k in line_lower for k in high_keywords):
            return 'high'
        elif any(k in line_lower for k in medium_keywords):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def _map_severity(severity_num: int) -> str:
        """Map Nikto severity number to string"""
        severity_map = {
            0: 'low',
            1: 'medium',
            2: 'high',
            3: 'critical'
        }
        return severity_map.get(severity_num, 'unknown')

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    """Handle all 500+ commands"""
    
    def __init__(self, db: DatabaseManager, monitor: NetworkMonitor = None):
        self.db = db
        self.monitor = monitor
        self.tools = NetworkTools()
        self.nikto_parser = NiktoParser()
        self.command_map = self._setup_command_map()
    
    def _setup_command_map(self) -> Dict[str, callable]:
        """Setup command execution map"""
        return {
            # Ping commands
            'ping': self._execute_ping,
            'ping4': self._execute_ping,
            'ping6': self._execute_ping6,
            
            # Scan commands
            'scan': self._execute_scan,
            'quick_scan': self._execute_quick_scan,
            'nmap': self._execute_nmap,
            'portscan': self._execute_portscan,
            'full_scan': self._execute_full_scan,
            
            # Nikto commands
            'nikto': self._execute_nikto,
            'nikto_scan': self._execute_nikto,
            'web_scan': self._execute_nikto,
            'vuln_scan': self._execute_nikto,
            
            # Traceroute commands
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'tracepath': self._execute_tracepath,
            
            # Web commands
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            
            # Info commands
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            
            # System commands
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
            'ps': self._execute_ps,
            'top': self._execute_top,
            
            # Security commands
            'threats': self._execute_threats,
            'report': self._execute_report,
            'monitor': self._execute_monitor,
            'block': self._execute_block,
            'unblock': self._execute_unblock,
            'blocked': self._execute_blocked,
            
            # Nikto history
            'nikto_history': self._execute_nikto_history,
        }
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        # Parse command
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Execute command
        try:
            if cmd_name in self.command_map:
                result = self.command_map[cmd_name](args)
            else:
                # Try as generic shell command
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            
            # Log command to database
            self.db.log_command(
                command=command,
                source=source,
                success=result.get('success', False),
                output=result.get('output', '')[:5000],
                execution_time=execution_time
            )
            
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error executing command: {e}"
            
            self.db.log_command(
                command=command,
                source=source,
                success=False,
                output=error_msg,
                execution_time=execution_time
            )
            
            return self._create_result(False, error_msg, execution_time)
    
    def _create_result(self, success: bool, data: Any, 
                      execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result"""
        if isinstance(data, str):
            return {
                'success': success,
                'output': data,
                'execution_time': execution_time
            }
        else:
            return {
                'success': success,
                'data': data,
                'execution_time': execution_time
            }
    
    # Command handlers
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        
        target = args[0]
        count = 4
        size = 56
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-c' and i + 1 < len(args):
                    try:
                        count = int(args[i + 1])
                    except:
                        pass
                elif args[i] == '-s' and i + 1 < len(args):
                    try:
                        size = int(args[i + 1])
                    except:
                        pass
        
        result = self.tools.ping(target, count, size)
        return self._create_result(result.success, result.output)
    
    def _execute_ping6(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping6 <target>")
        
        target = args[0]
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-6', target]
        else:
            cmd = ['ping6', target]
        
        cmd.extend(args[1:])
        return self._execute_generic(' '.join(cmd))
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        """Standard scan (ports 1-1000)"""
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports]")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick"
        
        if len(args) > 1:
            ports = args[1]
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            # Parse open ports from nmap output
            open_ports = self._parse_nmap_output(result.output)
            
            # Log scan to database
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': scan_type,
                'ports_scanned': ports,
                'open_ports': open_ports,
                'output': result.output[-2000:]
            })
        
        return self._create_result(False, result.output)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        """Quick scan with faster settings"""
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        
        target = args[0]
        ports = "1-1000"
        scan_type = "quick_scan"
        
        result = self.tools.nmap_scan(target, scan_type, ports)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Quick Scan",
                'ports_scanned': ports,
                'open_ports': open_ports,
                'output': result.output[-1500:]
            })
        
        return self._create_result(False, result.output)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        """Full nmap command with all options"""
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        
        target = args[0]
        options = ' '.join(args[1:]) if len(args) > 1 else ""
        
        # Determine scan type from options
        scan_type = "custom"
        if '-A' in options or '-sV' in options:
            scan_type = "comprehensive"
        elif '-sS' in options and 'T2' in options:
            scan_type = "stealth"
        elif '-sU' in options:
            scan_type = "udp"
        elif '-O' in options:
            scan_type = "os_detection"
        
        # Execute nmap
        result = self._execute_generic(f"nmap {target} {options}")
        
        if result['success']:
            open_ports = self._parse_nmap_output(result['output'])
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            result['data'] = {
                'target': target,
                'scan_type': scan_type,
                'options': options,
                'open_ports': open_ports
            }
        
        return result
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        """Full port scan (all ports)"""
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        
        target = args[0]
        scan_type = "full"
        
        result = self.tools.nmap_scan(target, scan_type)
        
        if result.success:
            open_ports = self._parse_nmap_output(result.output)
            
            scan_result = ScanResult(
                target=target,
                scan_type=scan_type,
                open_ports=open_ports,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': "Full Scan (All Ports)",
                'open_ports': open_ports,
                'output': result.output[-3000:]
            })
        
        return self._create_result(False, result.output)
    
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        """Nikto web vulnerability scanner"""
        if not args:
            return self._create_result(False, "Usage: nikto <target> [options]\nExample: nikto example.com\n        nikto https://example.com -ssl -port 443")
        
        target = args[0]
        options = ' '.join(args[1:]) if len(args) > 1 else ""
        
        # Add target validation
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        start_time = time.time()
        
        # Execute Nikto scan
        result = self.tools.nikto_scan(target, options)
        
        execution_time = time.time() - start_time
        
        if result.success:
            # Parse findings
            findings = []
            severity = "medium"
            
            if result.data:
                findings = self.nikto_parser.parse_json_output(result.data)
            else:
                findings = self.nikto_parser.parse_output(result.output)
            
            # Determine overall severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                sev = finding.get('severity', 'medium')
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            if severity_counts['critical'] > 0:
                severity = 'critical'
            elif severity_counts['high'] > 0:
                severity = 'high'
            elif severity_counts['medium'] > 0:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Log to database
            self.db.log_nikto_scan(target, findings, severity, execution_time)
            
            # Save results to file
            filename = f"nikto_{target.replace('/', '_').replace(':', '_')}_{int(time.time())}.json"
            filepath = os.path.join(NIKTO_RESULTS_DIR, filename)
            
            try:
                with open(filepath, 'w') as f:
                    json.dump({
                        'target': target,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'options': options,
                        'execution_time': execution_time,
                        'findings': findings,
                        'severity': severity,
                        'raw_output': result.output[:5000]
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save Nikto results: {e}")
            
            # Create scan result for logging
            scan_result = ScanResult(
                target=target,
                scan_type=ScanType.NIKTO,
                open_ports=[],
                vulnerabilities=findings,
                timestamp=datetime.datetime.now().isoformat(),
                success=True
            )
            self.db.log_scan(scan_result)
            
            return self._create_result(True, {
                'target': target,
                'scan_type': 'Nikto Web Vulnerability Scan',
                'execution_time': execution_time,
                'findings': findings[:20],  # Limit to 20 findings
                'total_findings': len(findings),
                'severity': severity,
                'severity_counts': severity_counts,
                'output': result.output[:2000],
                'result_file': filepath
            })
        
        return self._create_result(False, result.output if result.output else result.error)
    
    def _execute_nikto_history(self, args: List[str]) -> Dict[str, Any]:
        """Get Nikto scan history"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        history = self.db.get_nikto_history(limit)
        
        return self._create_result(True, {
            'total_scans': len(history),
            'scans': history
        })
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap output for open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    if len(port_proto) == 2:
                        try:
                            port = int(port_proto[0])
                            protocol = port_proto[1]
                            state = parts[1] if len(parts) > 1 else 'unknown'
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            
                            if state.lower() == 'open':
                                open_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'service': service,
                                    'state': state
                                })
                        except ValueError:
                            continue
        
        return open_ports
    
    def _execute_portscan(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_scan(args)
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        
        target = args[0]
        result = self.tools.traceroute(target)
        return self._create_result(result.success, result.output)
    
    def _execute_tracepath(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: tracepath <target>")
        
        return self._execute_generic('tracepath ' + ' '.join(args))
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: curl <url> [options]")
        
        url = args[0]
        method = 'GET'
        
        if len(args) > 1:
            for i in range(1, len(args)):
                if args[i] == '-X' and i + 1 < len(args):
                    method = args[i + 1].upper()
        
        result = self.tools.curl_request(url, method)
        return self._create_result(result.success, result.output)
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: wget <url>")
        
        return self._execute_generic('wget ' + ' '.join(args))
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: http <url>")
        
        url = args[0]
        try:
            response = requests.get(url, timeout=10)
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:500] + ('...' if len(response.text) > 500 else ''),
                'size': len(response.content)
            }
            return self._create_result(True, result)
        except Exception as e:
            return self._create_result(False, f"HTTP request failed: {e}")
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        
        target = args[0]
        result = self.tools.whois_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: dig <domain>")
        
        target = args[0]
        result = self.tools.dns_lookup(target)
        return self._create_result(result.success, result.output)
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_dig(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        
        target = args[0]
        result = self.tools.get_ip_location(target)
        return self._create_result(result['success'], result)
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        
        ip = args[0]
        
        # Comprehensive IP analysis
        analysis = {
            'ip': ip,
            'timestamp': datetime.datetime.now().isoformat(),
            'location': None,
            'threats': [],
            'is_blocked': self.db.is_ip_blocked(ip),
            'is_monitored': False,
            'recommendations': []
        }
        
        # Get location
        location = self.tools.get_ip_location(ip)
        if location['success']:
            analysis['location'] = location
        
        # Check if monitored
        monitored = self.db.get_monitored_ips()
        analysis['is_monitored'] = any(m['ip_address'] == ip for m in monitored)
        
        # Check for threats
        threats = self.db.get_recent_threats(50)
        ip_threats = [t for t in threats if t.get('source_ip') == ip]
        if ip_threats:
            analysis['threats'].extend([
                f"Previous threat: {t.get('threat_type')} ({t.get('severity')})" 
                for t in ip_threats[:3]
            ])
        
        # Add recommendations
        if ip_threats:
            analysis['recommendations'].append("This IP has been involved in previous threats - consider blocking")
        
        if analysis['is_blocked']:
            analysis['recommendations'].append("This IP is currently blocked")
        
        return self._create_result(True, analysis)
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'hostname': socket.gethostname(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
                'used': psutil.virtual_memory().used,
                'free': psutil.virtual_memory().free
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return self._create_result(True, info)
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        """Get network information"""
        try:
            hostname = socket.gethostname()
            local_ip = self.tools.get_local_ip()
            interfaces = psutil.net_if_addrs()
            
            network_info = {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {}
            }
            
            for iface, addrs in interfaces.items():
                network_info['interfaces'][iface] = []
                for addr in addrs:
                    network_info['interfaces'][iface].append({
                        'family': str(addr.family),
                        'address': addr.address
                    })
            
            return self._create_result(True, network_info)
        
        except Exception as e:
            return self._create_result(False, f"Failed to get network info: {e}")
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        """Get system status"""
        status = {
            'timestamp': datetime.datetime.now().isoformat(),
            'cpu': f"{psutil.cpu_percent(interval=1)}%",
            'memory': f"{psutil.virtual_memory().percent}%",
            'disk': f"{psutil.disk_usage('/').percent}%",
            'uptime': str(datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())),
            'network': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            },
            'monitoring': self.monitor.monitoring if self.monitor else False,
            'blocked_ips': len(self.db.get_blocked_ips(active_only=True)) if self.db else 0
        }
        
        return self._create_result(True, status)
    
    def _execute_monitor(self, args: List[str]) -> Dict[str, Any]:
        """Monitor related commands"""
        if not args:
            return self._create_result(False, "Usage: monitor <add|remove|list> <ip>")
        
        action = args[0].lower()
        
        if action == 'list':
            monitored = self.db.get_monitored_ips()
            return self._create_result(True, {
                'monitored_ips': monitored,
                'count': len(monitored)
            })
        
        elif action == 'add' and len(args) > 1:
            ip = args[1]
            if self.monitor:
                success = self.monitor.add_ip_to_monitoring(ip, "cli", "Added via command")
                msg = f"Added {ip} to monitoring" if success else f"Failed to add {ip}"
                return self._create_result(success, msg)
        
        elif action == 'remove' and len(args) > 1:
            ip = args[1]
            if self.monitor:
                success = self.monitor.remove_ip_from_monitoring(ip)
                msg = f"Removed {ip} from monitoring" if success else f"Failed to remove {ip}"
                return self._create_result(success, msg)
        
        return self._create_result(False, f"Unknown monitor action: {action}")
    
    def _execute_block(self, args: List[str]) -> Dict[str, Any]:
        """Block an IP address"""
        if not args:
            return self._create_result(False, "Usage: block <ip> [reason]")
        
        ip = args[0]
        reason = " ".join(args[1:]) if len(args) > 1 else "Manual block"
        
        try:
            ipaddress.ip_address(ip)
            
            if self.monitor:
                success = self.monitor.add_ip_to_block(ip, reason, "cli")
                msg = f"Blocked IP {ip}" if success else f"Failed to block IP {ip}"
                return self._create_result(success, msg)
            else:
                # Direct database block without monitor
                success = self.db.block_ip(ip, reason, "cli")
                if success:
                    NetworkTools.block_ip_firewall(ip, reason)
                return self._create_result(success, f"Blocked IP {ip}" if success else f"Failed to block IP {ip}")
        
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_unblock(self, args: List[str]) -> Dict[str, Any]:
        """Unblock an IP address"""
        if not args:
            return self._create_result(False, "Usage: unblock <ip>")
        
        ip = args[0]
        
        try:
            ipaddress.ip_address(ip)
            
            if self.monitor:
                success = self.monitor.remove_ip_from_block(ip)
                msg = f"Unblocked IP {ip}" if success else f"Failed to unblock IP {ip}"
                return self._create_result(success, msg)
            else:
                success = self.db.unblock_ip(ip)
                if success:
                    NetworkTools.unblock_ip_firewall(ip)
                return self._create_result(success, f"Unblocked IP {ip}" if success else f"Failed to unblock IP {ip}")
        
        except ValueError:
            return self._create_result(False, f"Invalid IP address: {ip}")
    
    def _execute_blocked(self, args: List[str]) -> Dict[str, Any]:
        """List blocked IPs"""
        active_only = True
        if args and args[0].lower() == 'all':
            active_only = False
        
        blocked = self.db.get_blocked_ips(active_only)
        
        return self._create_result(True, {
            'blocked_ips': blocked,
            'count': len(blocked),
            'active_only': active_only
        })
    
    def _execute_ps(self, args: List[str]) -> Dict[str, Any]:
        """Process list"""
        return self._execute_generic('ps aux' if len(args) == 0 else 'ps ' + ' '.join(args))
    
    def _execute_top(self, args: List[str]) -> Dict[str, Any]:
        """Top command"""
        return self._execute_generic('top -b -n 1' if len(args) == 0 else 'top ' + ' '.join(args))
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        """Get recent threats"""
        limit = 10
        if args:
            try:
                limit = int(args[0])
            except:
                pass
        
        threats = self.db.get_recent_threats(limit)
        return self._create_result(True, threats)
    
    def _execute_report(self, args: List[str]) -> Dict[str, Any]:
        """Generate security report"""
        # Get statistics
        stats = self.db.get_statistics()
        threats = self.db.get_recent_threats(50)
        blocked = self.db.get_blocked_ips(active_only=True)
        nikto_scans = self.db.get_nikto_history(10)
        
        # Count threats by severity
        high_threats = len([t for t in threats if t.get('severity') == 'high'])
        medium_threats = len([t for t in threats if t.get('severity') == 'medium'])
        low_threats = len([t for t in threats if t.get('severity') == 'low'])
        critical_threats = len([t for t in threats if t.get('severity') == 'critical'])
        
        # System info
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        
        report = {
            'generated_at': datetime.datetime.now().isoformat(),
            'statistics': stats,
            'threat_summary': {
                'critical': critical_threats,
                'high': high_threats,
                'medium': medium_threats,
                'low': low_threats,
                'total': len(threats)
            },
            'blocked_ips': {
                'count': len(blocked),
                'ips': [b['ip_address'] for b in blocked[:10]]
            },
            'recent_nikto_scans': len(nikto_scans),
            'system_status': {
                'cpu': cpu,
                'memory': mem,
                'disk': disk
            },
            'recommendations': []
        }
        
        # Add recommendations
        if critical_threats > 0:
            report['recommendations'].append("🔴 CRITICAL: Investigate critical severity threats immediately")
        if high_threats > 0:
            report['recommendations'].append("🟠 HIGH: Address high severity threats")
        if cpu > 80:
            report['recommendations'].append("⚠️ High CPU usage detected")
        if mem > 80:
            report['recommendations'].append("⚠️ High memory usage detected")
        if disk > 90:
            report['recommendations'].append("⚠️ Low disk space")
        
        # Save report to file
        filename = f"security_report_{int(time.time())}.json"
        filepath = os.path.join(REPORT_DIR, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            report['report_file'] = filepath
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
        
        return self._create_result(True, report)
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
        
            return self._create_result(
                result.returncode == 0,
                result.stdout if result.stdout else result.stderr,
                execution_time
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(False, f"Command timed out after 60 seconds")
        except Exception as e:
            return self._create_result(False, f"Command execution failed: {e}")

# =====================
# DISCORD BOT
# =====================
class SpiderBotDiscord:
    """Discord bot integration with enhanced commands"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager, monitor: NetworkMonitor = None):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = self.load_config()
        self.bot = None
        self.running = False
        self.task = None
        self.allowed_roles = ['Admin', 'Security', 'Moderator', 'SpiderBot']
    
    def load_config(self) -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Discord config: {e}")
        
        return {"token": "", "channel_id": "", "enabled": False, "prefix": "!", "admin_role": "Admin"}
    
    def save_config(self, token: str, channel_id: str = "", enabled: bool = True, 
                   prefix: str = "!", admin_role: str = "Admin") -> bool:
        """Save Discord configuration"""
        try:
            config = {
                "token": token,
                "channel_id": channel_id,
                "enabled": enabled,
                "prefix": prefix,
                "admin_role": admin_role
            }
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Discord config: {e}")
            return False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE:
            logger.error("discord.py not installed")
            return False
        
        if not self.config.get('token'):
            logger.error("Discord token not configured")
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            
            self.bot = commands.Bot(
                command_prefix=self.config.get('prefix', '!'), 
                intents=intents,
                help_command=None
            )
            
            # Setup event handlers
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                print(f'{Colors.GREEN}✅ Discord bot connected as {self.bot.user}{Colors.RESET}')
                
                await self.bot.change_presence(
                    activity=discord.Activity(
                        type=discord.ActivityType.watching,
                        name="500+ Security Commands | !help"
                    )
                )
            
            @self.bot.event
            async def on_command_error(ctx, error):
                if isinstance(error, commands.MissingPermissions):
                    await ctx.send("❌ You don't have permission to use this command.")
                elif isinstance(error, commands.MissingRequiredArgument):
                    await ctx.send(f"❌ Missing required argument: {error.param.name}")
                elif isinstance(error, commands.BadArgument):
                    await ctx.send(f"❌ Invalid argument: {error}")
                else:
                    await ctx.send(f"❌ An error occurred: {str(error)}")
                    logger.error(f"Discord command error: {error}")
            
            # Setup commands
            await self.setup_commands()
            
            self.running = True
            await self.bot.start(self.config['token'])
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Discord bot: {e}")
            return False
    
    def check_admin_role(self, ctx):
        """Check if user has admin role"""
        if not ctx.guild:
            return True  # DMs are allowed
        
        user_roles = [role.name for role in ctx.author.roles]
        
        # Check for configured admin role
        if self.config.get('admin_role') in user_roles:
            return True
        
        # Check for default admin roles
        for role in ['Admin', 'Administrator', 'Security', 'Moderator']:
            if role in user_roles:
                return True
        
        # Check if user is server owner
        if ctx.author == ctx.guild.owner:
            return True
        
        return False
    
    async def setup_commands(self):
        """Setup Discord commands"""
        
        # ==================== HELP COMMAND ====================
        @self.bot.command(name='help')
        async def help_command(ctx):
            """Show help"""
            embed = discord.Embed(
                title="🕸️ Spider Bot Pro v8.1.0 - Help",
                description="**500+ Advanced Cybersecurity Commands**\n\nType `!command parameters` to use",
                color=discord.Color.blue()
            )
            
            embed.add_field(
                name="🔍 **BASIC SCANNING**",
                value="`!ping <ip>` - Ping IP address\n`!scan <ip>` - Port scan (1-1000)\n`!quick_scan <ip>` - Fast port scan\n`!full_scan <ip>` - Scan all ports\n`!nmap <ip> [options]` - Full nmap scan",
                inline=False
            )
            
            embed.add_field(
                name="🌐 **WEB VULNERABILITY SCANNING**",
                value="`!nikto <target>` - Nikto web vulnerability scan\n`!nikto <target> -ssl -port 443` - Scan HTTPS\n`!nikto_history` - Show recent Nikto scans",
                inline=False
            )
            
            embed.add_field(
                name="🛡️ **IP MANAGEMENT**",
                value="`!add_ip <ip> [reason]` - Add IP to monitoring\n`!remove_ip <ip>` - Remove IP from monitoring\n`!block_ip <ip> [reason]` - Block IP address\n`!unblock_ip <ip>` - Unblock IP address\n`!blocked` - List blocked IPs\n`!monitored` - List monitored IPs",
                inline=False
            )
            
            embed.add_field(
                name="🔎 **INFORMATION GATHERING**",
                value="`!whois <domain>` - WHOIS lookup\n`!dns <domain>` - DNS lookup\n`!location <ip>` - IP geolocation\n`!analyze <ip>` - IP threat analysis",
                inline=False
            )
            
            embed.add_field(
                name="📊 **SYSTEM & SECURITY**",
                value="`!system` - System information\n`!network` - Network information\n`!status` - System status\n`!threats` - Recent threats\n`!report` - Security report",
                inline=False
            )
            
            embed.add_field(
                name="🚀 **EXAMPLES**",
                value="```!ping 8.8.8.8\n!scan 192.168.1.1\n!nikto example.com\n!add_ip 192.168.1.100 Suspicious activity\n!block_ip 10.0.0.5 Port scan detected```",
                inline=False
            )
            
            embed.set_footer(text=f"Requested by {ctx.author.display_name}")
            await ctx.send(embed=embed)
        
        # ==================== IP MANAGEMENT COMMANDS ====================
        
        @self.bot.command(name='add_ip', aliases=['monitor_ip', 'watch_ip'])
        async def add_ip_command(ctx, ip: str, *, reason: str = "Added via Discord"):
            """Add IP to monitoring (Admin only)"""
            if not self.check_admin_role(ctx):
                await ctx.send("❌ You need Admin role to use this command.")
                return
            
            await ctx.send(f"🔄 Adding {ip} to monitoring...")
            
            if self.monitor:
                success = self.monitor.add_ip_to_monitoring(ip, f"discord:{ctx.author}", reason)
            else:
                success = self.db.add_monitored_ip(ip, reason, f"discord:{ctx.author}")
            
            # Log command
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'add_ip', ip, success)
            
            if success:
                embed = discord.Embed(
                    title="✅ IP Added to Monitoring",
                    description=f"**IP:** `{ip}`\n**Reason:** {reason}\n**Added by:** {ctx.author.mention}",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                
                # Get location info
                location = NetworkTools.get_ip_location(ip)
                if location.get('success'):
                    embed.add_field(name="📍 Location", value=f"{location.get('country', 'N/A')}, {location.get('city', 'N/A')}", inline=True)
                    embed.add_field(name="🏢 ISP", value=location.get('isp', 'N/A'), inline=True)
                
                await ctx.send(embed=embed)
            else:
                await ctx.send(f"❌ Failed to add {ip} to monitoring. It may already be monitored.")
        
        @self.bot.command(name='remove_ip', aliases=['unmonitor_ip', 'unwatch_ip'])
        async def remove_ip_command(ctx, ip: str):
            """Remove IP from monitoring (Admin only)"""
            if not self.check_admin_role(ctx):
                await ctx.send("❌ You need Admin role to use this command.")
                return
            
            await ctx.send(f"🔄 Removing {ip} from monitoring...")
            
            if self.monitor:
                success = self.monitor.remove_ip_from_monitoring(ip)
            else:
                success = self.db.remove_monitored_ip(ip)
            
            # Log command
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'remove_ip', ip, success)
            
            if success:
                embed = discord.Embed(
                    title="✅ IP Removed from Monitoring",
                    description=f"**IP:** `{ip}`\n**Removed by:** {ctx.author.mention}",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await ctx.send(f"❌ Failed to remove {ip} from monitoring. IP may not be in monitoring list.")
        
        @self.bot.command(name='monitored', aliases=['monitored_ips', 'watchlist'])
        async def monitored_ips_command(ctx):
            """List all monitored IPs"""
            monitored = self.db.get_monitored_ips(active_only=True)
            
            if not monitored:
                embed = discord.Embed(
                    title="📋 Monitored IPs",
                    description="No IPs are currently being monitored.",
                    color=discord.Color.blue()
                )
                await ctx.send(embed=embed)
                return
            
            embed = discord.Embed(
                title=f"📋 Monitored IPs ({len(monitored)})",
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now()
            )
            
            # Show first 15 IPs
            for i, ip_data in enumerate(monitored[:15]):
                embed.add_field(
                    name=f"{i+1}. `{ip_data['ip_address']}`",
                    value=f"Added: {ip_data['added_date'][:10]}\nReason: {ip_data.get('notes', 'N/A')[:50]}",
                    inline=True
                )
            
            if len(monitored) > 15:
                embed.set_footer(text=f"And {len(monitored) - 15} more...")
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='block_ip', aliases=['block'])
        async def block_ip_command(ctx, ip: str, *, reason: str = "Manual block via Discord"):
            """Block an IP address (Admin only)"""
            if not self.check_admin_role(ctx):
                await ctx.send("❌ You need Admin role to use this command.")
                return
            
            await ctx.send(f"🔄 Blocking IP {ip}...")
            
            if self.monitor:
                success = self.monitor.add_ip_to_block(ip, reason, f"discord:{ctx.author}")
            else:
                success = self.db.block_ip(ip, reason, f"discord:{ctx.author}")
                if success:
                    NetworkTools.block_ip_firewall(ip, reason)
            
            # Log command
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'block_ip', ip, success)
            
            if success:
                embed = discord.Embed(
                    title="🔒 IP Blocked",
                    description=f"**IP:** `{ip}`\n**Reason:** {reason}\n**Blocked by:** {ctx.author.mention}",
                    color=discord.Color.red(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await ctx.send(f"❌ Failed to block IP {ip}. It may already be blocked.")
        
        @self.bot.command(name='unblock_ip', aliases=['unblock'])
        async def unblock_ip_command(ctx, ip: str):
            """Unblock an IP address (Admin only)"""
            if not self.check_admin_role(ctx):
                await ctx.send("❌ You need Admin role to use this command.")
                return
            
            await ctx.send(f"🔄 Unblocking IP {ip}...")
            
            if self.monitor:
                success = self.monitor.remove_ip_from_block(ip)
            else:
                success = self.db.unblock_ip(ip)
                if success:
                    NetworkTools.unblock_ip_firewall(ip)
            
            # Log command
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'unblock_ip', ip, success)
            
            if success:
                embed = discord.Embed(
                    title="🔓 IP Unblocked",
                    description=f"**IP:** `{ip}`\n**Unblocked by:** {ctx.author.mention}",
                    color=discord.Color.green(),
                    timestamp=datetime.datetime.now()
                )
                await ctx.send(embed=embed)
            else:
                await ctx.send(f"❌ Failed to unblock IP {ip}. IP may not be blocked.")
        
        @self.bot.command(name='blocked', aliases=['blocked_ips'])
        async def blocked_ips_command(ctx):
            """List all blocked IPs"""
            blocked = self.db.get_blocked_ips(active_only=True)
            
            if not blocked:
                embed = discord.Embed(
                    title="🔒 Blocked IPs",
                    description="No IPs are currently blocked.",
                    color=discord.Color.green()
                )
                await ctx.send(embed=embed)
                return
            
            embed = discord.Embed(
                title=f"🔒 Blocked IPs ({len(blocked)})",
                color=discord.Color.red(),
                timestamp=datetime.datetime.now()
            )
            
            for i, ip_data in enumerate(blocked[:10]):
                embed.add_field(
                    name=f"{i+1}. `{ip_data['ip_address']}`",
                    value=f"Blocked: {ip_data['blocked_date'][:10]}\nReason: {ip_data.get('reason', 'N/A')[:50]}",
                    inline=True
                )
            
            if len(blocked) > 10:
                embed.set_footer(text=f"And {len(blocked) - 10} more...")
            
            await ctx.send(embed=embed)
        
        # ==================== NIKTO COMMANDS ====================
        
        @self.bot.command(name='nikto', aliases=['web_scan', 'vuln_scan'])
        async def nikto_command(ctx, target: str, *options):
            """Nikto web vulnerability scanner"""
            await ctx.send(f"🔍 Running Nikto web vulnerability scan on {target}...\nThis may take a few minutes.")
            
            cmd = f"nikto {target}"
            if options:
                cmd += " " + " ".join(options)
            
            result = self.handler.execute(cmd, "discord")
            
            # Log command
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'nikto', target, result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                # Create embed for Nikto results
                embed = discord.Embed(
                    title=f"🔍 Nikto Scan Results: {data['target']}",
                    color=discord.Color.orange() if data.get('severity') in ['high', 'critical'] else discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name="⏱️ Execution Time", value=f"{data['execution_time']:.2f}s", inline=True)
                embed.add_field(name="🎯 Total Findings", value=data['total_findings'], inline=True)
                
                # Severity counts
                severity_counts = data.get('severity_counts', {})
                severity_text = f"🔴 Critical: {severity_counts.get('critical', 0)}\n"
                severity_text += f"🟠 High: {severity_counts.get('high', 0)}\n"
                severity_text += f"🟡 Medium: {severity_counts.get('medium', 0)}\n"
                severity_text += f"🟢 Low: {severity_counts.get('low', 0)}"
                embed.add_field(name="📊 Severity", value=severity_text, inline=True)
                
                # Top findings
                if data.get('findings'):
                    findings_text = ""
                    for finding in data['findings'][:5]:
                        severity_emoji = self.get_severity_emoji(finding.get('severity', 'medium'))
                        findings_text += f"{severity_emoji} {finding.get('type', 'Finding')[:30]}\n"
                    
                    if data['total_findings'] > 5:
                        findings_text += f"\n... and {data['total_findings'] - 5} more findings"
                    
                    embed.add_field(name="🔎 Top Findings", value=findings_text[:1000], inline=False)
                
                embed.set_footer(text=f"Scanned by {ctx.author.display_name}")
                await ctx.send(embed=embed)
                
                # Send detailed findings as file if many
                if data.get('findings') and len(data['findings']) > 10:
                    findings_file = f"{TEMP_DIR}/nikto_{ctx.message.id}.json"
                    with open(findings_file, 'w') as f:
                        json.dump(data['findings'], f, indent=2)
                    
                    await ctx.send(file=discord.File(findings_file))
                    os.remove(findings_file)
                
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='nikto_history')
        async def nikto_history_command(ctx, limit: int = 5):
            """Show recent Nikto scan history"""
            history = self.db.get_nikto_history(limit)
            
            if not history:
                embed = discord.Embed(
                    title="📊 Nikto Scan History",
                    description="No Nikto scans found in history.",
                    color=discord.Color.blue()
                )
                await ctx.send(embed=embed)
                return
            
            embed = discord.Embed(
                title=f"📊 Recent Nikto Scans (Last {len(history)})",
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now()
            )
            
            for scan in history[:5]:
                severity = scan.get('severity', 'unknown')
                emoji = self.get_severity_emoji(severity)
                
                findings_count = 0
                if scan.get('findings'):
                    try:
                        findings = json.loads(scan['findings'])
                        findings_count = len(findings) if isinstance(findings, list) else 0
                    except:
                        pass
                
                embed.add_field(
                    name=f"{emoji} {scan['target']}",
                    value=f"Time: {scan['timestamp'][:19]}\nFindings: {findings_count}\nDuration: {scan.get('scan_duration', 0):.1f}s",
                    inline=True
                )
            
            await ctx.send(embed=embed)
        
        # ==================== NETWORK COMMANDS ====================
        
        @self.bot.command(name='ping')
        async def ping_command(ctx, target: str, *options):
            """Ping command"""
            await ctx.send(f"🏓 Pinging {target}...")
            cmd = f"ping {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'ping', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='scan')
        async def scan_command(ctx, target: str, ports: str = None):
            """Port scan (1-1000 by default)"""
            await ctx.send(f"🔍 Scanning {target} (ports 1-1000)...")
            cmd = f"scan {target}"
            if ports:
                cmd += f" {ports}"
            result = self.handler.execute(cmd, "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'scan', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='quick_scan')
        async def quick_scan_command(ctx, target: str):
            """Quick port scan"""
            await ctx.send(f"⚡ Quick scanning {target}...")
            result = self.handler.execute(f"quick_scan {target}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'quick_scan', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='full_scan')
        async def full_scan_command(ctx, target: str):
            """Full port scan (all ports)"""
            await ctx.send(f"🔬 Full scanning {target} (all ports)...\nThis may take a while.")
            result = self.handler.execute(f"full_scan {target}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'full_scan', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='nmap')
        async def nmap_command(ctx, target: str, *options):
            """Full nmap command"""
            await ctx.send(f"🔬 Running nmap on {target}...")
            cmd = f"nmap {target}"
            if options:
                cmd += " " + " ".join(options)
            result = self.handler.execute(cmd, "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'nmap', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='traceroute')
        async def traceroute_command(ctx, target: str):
            """Traceroute"""
            await ctx.send(f"🛣️ Tracing route to {target}...")
            result = self.handler.execute(f"traceroute {target}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'traceroute', target, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='whois')
        async def whois_command(ctx, domain: str):
            """WHOIS lookup"""
            await ctx.send(f"🔎 WHOIS lookup for {domain}...")
            result = self.handler.execute(f"whois {domain}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'whois', domain, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='dns')
        async def dns_command(ctx, domain: str):
            """DNS lookup"""
            await ctx.send(f"📡 DNS lookup for {domain}...")
            result = self.handler.execute(f"dns {domain}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'dns', domain, result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='location')
        async def location_command(ctx, ip: str):
            """IP geolocation"""
            await ctx.send(f"📍 Getting location for {ip}...")
            result = self.handler.execute(f"location {ip}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'location', ip, result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                embed = discord.Embed(
                    title=f"📍 IP Geolocation: {data.get('ip', 'Unknown')}",
                    color=discord.Color.blue()
                )
                
                embed.add_field(name="🌍 Country", value=data.get('country', 'N/A'), inline=True)
                embed.add_field(name="🏙️ Region", value=data.get('region', 'N/A'), inline=True)
                embed.add_field(name="🏛️ City", value=data.get('city', 'N/A'), inline=True)
                embed.add_field(name="🏢 ISP", value=data.get('isp', 'N/A'), inline=True)
                embed.add_field(name="📊 Coordinates", value=f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}", inline=True)
                
                await ctx.send(embed=embed)
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='analyze')
        async def analyze_command(ctx, ip: str):
            """Analyze IP for threats"""
            await ctx.send(f"🔬 Analyzing IP {ip}...")
            result = self.handler.execute(f"analyze {ip}", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'analyze', ip, result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                color = discord.Color.red() if data.get('is_blocked') else discord.Color.blue()
                
                embed = discord.Embed(
                    title=f"🔬 IP Analysis: {data.get('ip', 'Unknown')}",
                    color=color,
                    timestamp=datetime.datetime.now()
                )
                
                # Status
                status = ""
                status += "🔒 Blocked\n" if data.get('is_blocked') else "✅ Not Blocked\n"
                status += "📋 Monitored\n" if data.get('is_monitored') else "📋 Not Monitored\n"
                embed.add_field(name="🛡️ Status", value=status, inline=True)
                
                # Location
                if data.get('location'):
                    loc = data['location']
                    embed.add_field(name="📍 Location", 
                                  value=f"{loc.get('country', 'N/A')}, {loc.get('city', 'N/A')}", 
                                  inline=True)
                
                # Threats
                if data.get('threats'):
                    embed.add_field(name="🚨 Threats Found", 
                                  value="\n".join(data['threats'][:5]), 
                                  inline=False)
                
                # Recommendations
                if data.get('recommendations'):
                    embed.add_field(name="💡 Recommendations", 
                                  value="\n".join(data['recommendations']), 
                                  inline=False)
                
                await ctx.send(embed=embed)
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='system')
        async def system_command(ctx):
            """System info"""
            await ctx.send("💻 Getting system information...")
            result = self.handler.execute("system", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'system', '', result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                embed = discord.Embed(
                    title="💻 System Information",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name="🖥️ System", value=f"{data.get('system', 'N/A')} {data.get('release', 'N/A')}", inline=True)
                embed.add_field(name="🏷️ Hostname", value=data.get('hostname', 'N/A'), inline=True)
                embed.add_field(name="🧠 CPU", value=f"{data.get('cpu_count', 'N/A')} cores ({data.get('cpu_percent', 0)}%)", inline=True)
                
                memory = data.get('memory', {})
                embed.add_field(name="💾 Memory", value=f"{memory.get('used', 0) / (1024**3):.1f}GB / {memory.get('total', 0) / (1024**3):.1f}GB ({memory.get('percent', 0)}%)", inline=True)
                
                disk = data.get('disk', {})
                embed.add_field(name="💿 Disk", value=f"{disk.get('used', 0) / (1024**3):.1f}GB / {disk.get('total', 0) / (1024**3):.1f}GB ({disk.get('percent', 0)}%)", inline=True)
                
                embed.add_field(name="⏰ Boot Time", value=data.get('boot_time', 'N/A'), inline=True)
                
                await ctx.send(embed=embed)
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='status')
        async def status_command(ctx):
            """System status"""
            await ctx.send("📊 Getting system status...")
            result = self.handler.execute("status", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'status', '', result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                cpu_percent = float(data.get('cpu', '0%').strip('%'))
                mem_percent = float(data.get('memory', '0%').strip('%'))
                disk_percent = float(data.get('disk', '0%').strip('%'))
                
                cpu_emoji = self.get_health_emoji(cpu_percent)
                mem_emoji = self.get_health_emoji(mem_percent)
                disk_emoji = self.get_health_emoji(disk_percent)
                
                embed = discord.Embed(
                    title="📊 System Status",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(name=f"{cpu_emoji} CPU", value=data.get('cpu', 'N/A'), inline=True)
                embed.add_field(name=f"{mem_emoji} Memory", value=data.get('memory', 'N/A'), inline=True)
                embed.add_field(name=f"{disk_emoji} Disk", value=data.get('disk', 'N/A'), inline=True)
                embed.add_field(name="⏱️ Uptime", value=data.get('uptime', 'N/A').split('.')[0], inline=True)
                embed.add_field(name="🔒 Blocked IPs", value=data.get('blocked_ips', 0), inline=True)
                embed.add_field(name="🛡️ Monitoring", value="✅ Active" if data.get('monitoring') else "❌ Inactive", inline=True)
                
                await ctx.send(embed=embed)
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='threats')
        async def threats_command(ctx, limit: int = 10):
            """Recent threats"""
            threats = self.db.get_recent_threats(limit)
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'threats', str(limit), True)
            
            if not threats:
                embed = discord.Embed(
                    title="🚨 Recent Threats",
                    description="✅ No recent threats detected",
                    color=discord.Color.green()
                )
                await ctx.send(embed=embed)
                return
            
            embed = discord.Embed(
                title=f"🚨 Recent Threats (Last {len(threats)})",
                color=discord.Color.red(),
                timestamp=datetime.datetime.now()
            )
            
            for threat in threats[:10]:
                severity = threat.get('severity', 'unknown')
                severity_emoji = self.get_severity_emoji(severity)
                
                embed.add_field(
                    name=f"{severity_emoji} {threat.get('threat_type', 'Unknown')}",
                    value=f"**Source:** `{threat.get('source_ip', 'Unknown')}`\n**Time:** {threat.get('timestamp', '')[:19]}\n**Action:** {threat.get('action_taken', 'None')}",
                    inline=False
                )
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='report')
        async def report_command(ctx):
            """Security report"""
            await ctx.send("📊 Generating security report...")
            result = self.handler.execute("report", "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'report', '', result['success'])
            
            if result['success'] and result.get('data'):
                data = result['data']
                
                embed = discord.Embed(
                    title="📊 Security Report",
                    description=f"Generated: {data.get('generated_at', '')[:19]}",
                    color=discord.Color.blue(),
                    timestamp=datetime.datetime.now()
                )
                
                # Statistics
                stats = data.get('statistics', {})
                embed.add_field(name="📈 Statistics", 
                              value=f"Commands: {stats.get('total_commands', 0)}\nScans: {stats.get('total_scans', 0)}\nThreats: {stats.get('total_threats', 0)}\nNikto: {stats.get('total_nikto_scans', 0)}", 
                              inline=True)
                
                # Threat Summary
                threats = data.get('threat_summary', {})
                embed.add_field(name="🚨 Threat Summary",
                              value=f"🔴 Critical: {threats.get('critical', 0)}\n🟠 High: {threats.get('high', 0)}\n🟡 Medium: {threats.get('medium', 0)}\n🟢 Low: {threats.get('low', 0)}",
                              inline=True)
                
                # Blocked IPs
                blocked = data.get('blocked_ips', {})
                embed.add_field(name="🔒 Blocked IPs", value=f"Total: {blocked.get('count', 0)}", inline=True)
                
                # System Status
                system = data.get('system_status', {})
                embed.add_field(name="💻 System Status",
                              value=f"CPU: {system.get('cpu', 0)}%\nMemory: {system.get('memory', 0)}%\nDisk: {system.get('disk', 0)}%",
                              inline=True)
                
                # Recommendations
                if data.get('recommendations'):
                    rec_text = "\n".join(data['recommendations'][:3])
                    embed.add_field(name="💡 Recommendations", value=rec_text, inline=False)
                
                await ctx.send(embed=embed)
                
                # Send report file
                if data.get('report_file'):
                    try:
                        await ctx.send(file=discord.File(data['report_file']))
                    except:
                        pass
            else:
                await self.send_result(ctx, result)
        
        @self.bot.command(name='execute')
        @commands.has_permissions(administrator=True)
        async def execute_command(ctx, *, command: str):
            """Execute any command (Admin only)"""
            if not self.check_admin_role(ctx):
                await ctx.send("❌ You need Admin role to use this command.")
                return
            
            await ctx.send(f"⚡ Executing command: `{command}`")
            result = self.handler.execute(command, "discord")
            
            self.db.log_discord_command(str(ctx.author.id), ctx.author.name, 'execute', command[:50], result['success'])
            await self.send_result(ctx, result)
        
        @self.bot.command(name='stats')
        async def stats_command(ctx):
            """Bot statistics"""
            stats = self.db.get_statistics()
            
            embed = discord.Embed(
                title="📊 Spider Bot Statistics",
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(name="🛡️ Threats", value=stats.get('total_threats', 0), inline=True)
            embed.add_field(name="🔍 Scans", value=stats.get('total_scans', 0), inline=True)
            embed.add_field(name="🌐 Nikto Scans", value=stats.get('total_nikto_scans', 0), inline=True)
            embed.add_field(name="📝 Commands", value=stats.get('total_commands', 0), inline=True)
            embed.add_field(name="🎯 Monitored IPs", value=stats.get('active_monitored_ips', 0), inline=True)
            embed.add_field(name="🔒 Blocked IPs", value=stats.get('active_blocked_ips', 0), inline=True)
            embed.add_field(name="💬 Discord Commands", value=stats.get('total_discord_commands', 0), inline=True)
            
            await ctx.send(embed=embed)
    
    async def send_result(self, ctx, result: Dict[str, Any]):
        """Send command result to Discord"""
        if not result['success']:
            embed = discord.Embed(
                title="❌ Command Failed",
                description=f"```{result.get('output', 'Unknown error')[:1000]}```",
                color=discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                # Format dictionary output
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long
        if len(formatted) > 2000:
            formatted = formatted[:1900] + "\n\n... (output truncated)"
        
        # Create embed
        if result.get('data'):
            embed = discord.Embed(
                title=f"✅ Command Executed ({result['execution_time']:.2f}s)",
                color=discord.Color.green()
            )
            
            # Add fields for dictionary data
            if isinstance(result['data'], dict):
                for key, value in result['data'].items():
                    if key not in ['output'] and value:
                        if isinstance(value, list) and len(value) > 0:
                            # Handle lists (like open ports)
                            if isinstance(value[0], dict):
                                # Format list of dictionaries
                                formatted_list = "\n".join([str(v) for v in value[:5]])
                                if len(value) > 5:
                                    formatted_list += f"\n... and {len(value)-5} more"
                                embed.add_field(name=key, value=f"```{formatted_list[:500]}```", inline=False)
                            else:
                                embed.add_field(name=key, value=str(value)[:200], inline=True)
                        else:
                            embed.add_field(name=key, value=str(value)[:200], inline=True)
            
            await ctx.send(embed=embed)
            
            # Send additional output if needed
            if formatted and 'output' not in result.get('data', {}):
                if len(formatted) > 2000:
                    # Send as file if too long
                    file_content = f"Command Output:\n{formatted}"
                    with open(f"{TEMP_DIR}/discord_output_{ctx.message.id}.txt", "w") as f:
                        f.write(file_content)
                    await ctx.send(file=discord.File(f"{TEMP_DIR}/discord_output_{ctx.message.id}.txt"))
                    os.remove(f"{TEMP_DIR}/discord_output_{ctx.message.id}.txt")
                else:
                    await ctx.send(f"```{formatted}```")
        else:
            embed = discord.Embed(
                title=f"✅ Command Executed ({result['execution_time']:.2f}s)",
                description=f"```{formatted}```",
                color=discord.Color.green()
            )
            await ctx.send(embed=embed)
    
    def get_severity_emoji(self, severity: str) -> str:
        """Get emoji for threat severity"""
        if severity == 'critical':
            return '🔴'
        elif severity == 'high':
            return '🟠'
        elif severity == 'medium':
            return '🟡'
        elif severity == 'low':
            return '🟢'
        else:
            return '⚪'
    
    def get_health_emoji(self, percent: float) -> str:
        """Get emoji for health percentage"""
        if percent >= 90:
            return '🔴'
        elif percent >= 70:
            return '🟠'
        elif percent >= 50:
            return '🟡'
        else:
            return '🟢'
    
    def start_bot_thread(self):
        """Start Discord bot in separate thread"""
        if self.config.get('enabled') and self.config.get('token'):
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            logger.info("Discord bot started in background thread")
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# TELEGRAM BOT
# =====================
class SpiderBotTelegram:
    """Telegram bot integration"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager, monitor: NetworkMonitor = None):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = self.load_config()
        self.client = None
        self.running = False
    
    def load_config(self) -> Dict:
        """Load Telegram configuration"""
        try:
            if os.path.exists(TELEGRAM_CONFIG_FILE):
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Telegram config: {e}")
        
        return {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        }
    
    def save_config(self, api_id: str, api_hash: str, phone_number: str = "", 
                   channel_id: str = "", enabled: bool = True) -> bool:
        """Save Telegram configuration"""
        try:
            config = {
                "api_id": api_id,
                "api_hash": api_hash,
                "phone_number": phone_number,
                "channel_id": channel_id,
                "enabled": enabled
            }
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    async def start(self):
        """Start Telegram bot"""
        if not TELETHON_AVAILABLE:
            logger.error("Telethon not installed")
            return False
        
        if not self.config.get('api_id') or not self.config.get('api_hash'):
            logger.error("Telegram API credentials not configured")
            return False
        
        try:
            self.client = TelegramClient(
                'spiderbot_session',
                self.config['api_id'],
                self.config['api_hash']
            )
            
            # Event handler for incoming messages
            @self.client.on(events.NewMessage(pattern=r'^/(start|help|ping|scan|quick_scan|nikto|add_ip|block|unblock|blocked|whois|dns|location|system|status|threats|report)'))
            async def handler(event):
                await self.handle_command(event)
            
            await self.client.start(phone=self.config.get('phone_number', ''))
            logger.info("Telegram bot started")
            print(f"{Colors.GREEN}✅ Telegram bot connected{Colors.RESET}")
            
            self.running = True
            
            # Keep running
            await self.client.run_until_disconnected()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Telegram bot: {e}")
            return False
    
    async def handle_command(self, event):
        """Handle Telegram commands"""
        message = event.message.message
        sender = await event.get_sender()
        
        if not message.startswith('/'):
            return
        
        command_parts = message.split()
        command = command_parts[0][1:]  # Remove '/'
        args = command_parts[1:] if len(command_parts) > 1 else []
        
        logger.info(f"Telegram command from {sender.username}: {command} {args}")
        
        # Map Telegram commands to handler commands
        cmd_map = {
            'start': 'help',
            'help': 'help',
            'ping': f"ping {' '.join(args)}",
            'scan': f"scan {' '.join(args)}",
            'quick_scan': f"quick_scan {' '.join(args)}",
            'nikto': f"nikto {' '.join(args)}",
            'whois': f"whois {' '.join(args)}",
            'dns': f"dns {' '.join(args)}",
            'location': f"location {' '.join(args)}",
            'system': 'system',
            'status': 'status',
            'threats': 'threats',
            'report': 'report',
            'add_ip': f"monitor add {' '.join(args)}" if args else "monitor add",
            'block': f"block {' '.join(args)}" if args else "block",
            'unblock': f"unblock {' '.join(args)}" if args else "unblock",
            'blocked': 'blocked'
        }
        
        if command in cmd_map:
            handler_cmd = cmd_map[command]
            if command in ['start', 'help']:
                await self.send_help(event)
            else:
                # Send processing message
                processing_msg = await event.reply(f"🔄 Processing {command}...")
                
                # Execute command
                result = self.handler.execute(handler_cmd, "telegram")
                
                # Send result
                await self.send_result(event, result, processing_msg)
    
    async def send_help(self, event):
        """Send help message"""
        help_text = """
🕸️ *Spider Bot Pro v8.1.0 - Telegram Commands*

*/start* - Show this help
*/help* - Show this help

🔍 **SCANNING COMMANDS**
*/ping <ip>* - Ping IP address
*/scan <ip>* - Port scan (1-1000)
*/quick_scan <ip>* - Fast port scan
*/nikto <target>* - Web vulnerability scan

🛡️ **IP MANAGEMENT**
*/add_ip <ip> [reason]* - Add IP to monitoring
*/block <ip> [reason]* - Block IP address
*/unblock <ip>* - Unblock IP address
*/blocked* - List blocked IPs

🔎 **INFORMATION**
*/whois <domain>* - WHOIS lookup
*/dns <domain>* - DNS lookup
*/location <ip>* - IP geolocation
*/threats* - Recent threats

📊 **SYSTEM**
*/system* - System info
*/status* - System status
*/report* - Security report

*Examples:*
`/ping 127.0.0.1`
`/nikto example.com`
`/block 192.168.1.100 Port scan`
`/add_ip 10.0.0.5 Suspicious activity`
        """
        
        await event.reply(help_text, parse_mode='markdown')
    
    async def send_result(self, event, result: Dict[str, Any], processing_msg=None):
        """Send command result to Telegram"""
        if processing_msg:
            try:
                await processing_msg.delete()
            except:
                pass
        
        if not result['success']:
            error_msg = f"❌ *Command Failed*\n\n```{result.get('output', 'Unknown error')[:1000]}```"
            await event.reply(error_msg, parse_mode='markdown')
            return
        
        output = result.get('output', '') or result.get('data', '')
        
        if isinstance(output, dict):
            try:
                formatted = json.dumps(output, indent=2)
            except:
                formatted = str(output)
        else:
            formatted = str(output)
        
        # Truncate if too long for Telegram
        if len(formatted) > 4000:
            formatted = formatted[:3900] + "\n\n... (output truncated)"
        
        success_msg = f"✅ *Command Executed* ({result['execution_time']:.2f}s)\n\n```{formatted}```"
        
        await event.reply(success_msg, parse_mode='markdown')
    
    def start_bot_thread(self):
        """Start Telegram bot in separate thread"""
        if self.config.get('enabled') and self.config.get('api_id'):
            thread = threading.Thread(target=self._run_telegram_bot, daemon=True)
            thread.start()
            logger.info("Telegram bot started in background thread")
            return True
        return False
    
    def _run_telegram_bot(self):
        """Run Telegram bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Telegram bot error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class SpiderBotPro:
    """Main application class"""
    
    def __init__(self):
        # Initialize components
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.monitor = NetworkMonitor(self.db, self.config)
        self.handler = CommandHandler(self.db, self.monitor)
        self.discord_bot = SpiderBotDiscord(self.handler, self.db, self.monitor)
        self.telegram_bot = SpiderBotTelegram(self.handler, self.db, self.monitor)
        
        # Application state
        self.running = True
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}        🕸️ SPIDER BOT PRO v7.0.0 🕸️                                        {Colors.RED}║
╠══════════════════════════════════════════════════════════════════════════════╣
║{Colors.CYAN}  • 500+ Complete Commands Support    • Discord/Telegram Integration       {Colors.RED}║
║{Colors.CYAN}  • Nikto Web Vulnerability Scanner   • IP Blocking & Monitoring            {Colors.RED}║
║{Colors.CYAN}  • Advanced Network Scanning         • Real-time Threat Detection         {Colors.RED}║
║{Colors.CYAN}  • Database Logging & Reporting      • IP Geolocation & WHOIS Lookup      {Colors.RED}║
║{Colors.CYAN}  • Discord !add_ip/!remove_ip        • Multi-threaded Monitoring Engine   {Colors.RED}║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.GREEN}🔒 NEW FEATURES v8.1.0:{Colors.RESET}
  • 🌐 Nikto web vulnerability scanner (!nikto)
  • 🔒 IP blocking system (!block_ip, !unblock_ip)
  • 📋 Discord IP management (!add_ip, !remove_ip)
  • 📊 Enhanced security reporting
  • 🔴 Critical severity threat detection

{Colors.YELLOW}💡 Type 'help' for command list{Colors.RESET}
{Colors.YELLOW}📚 Discord commands: !nikto, !add_ip, !remove_ip, !block_ip, !unblock_ip{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.YELLOW}┌─────────────────{Colors.WHITE} COMMAND REFERENCE v8.1.0 {Colors.YELLOW}─────────────────┐{Colors.RESET}

{Colors.GREEN}🌐 WEB VULNERABILITY SCANNING:{Colors.RESET}
  nikto <target>            - Nikto web vulnerability scan
  nikto <target> -ssl       - Scan HTTPS with SSL
  nikto_history            - Show recent Nikto scans

{Colors.GREEN}🛡️  IP MANAGEMENT & BLOCKING:{Colors.RESET}
  block <ip> [reason]      - Block IP address
  unblock <ip>             - Unblock IP address
  blocked                  - List blocked IPs
  monitor add <ip>         - Add IP to monitoring
  monitor remove <ip>      - Remove IP from monitoring
  monitor list             - List monitored IPs

{Colors.GREEN}🛡️  MONITORING COMMANDS:{Colors.RESET}
  start                    - Start threat monitoring
  stop                     - Stop monitoring
  status                   - Show monitoring status
  threats                  - Show recent threats
  report                   - Generate security report

{Colors.GREEN}📡 NETWORK DIAGNOSTICS:{Colors.RESET}
  ping <ip> [options]      - Ping with options
  traceroute <target>      - Network path tracing
  scan <ip> [ports]        - Port scan (1-1000)
  quick_scan <ip>          - Fast port scan
  nmap <ip> [options]      - Advanced nmap scanning
  full_scan <ip>           - Scan all ports

{Colors.GREEN}🔍 INFORMATION GATHERING:{Colors.RESET}
  whois <domain>           - WHOIS lookup
  dns <domain>             - DNS lookup
  location <ip>            - IP geolocation
  analyze <ip>             - Analyze IP threats

{Colors.GREEN}🤖 DISCORD COMMANDS:{Colors.RESET}
  !nikto <target>          - Nikto web scan
  !add_ip <ip> [reason]    - Add IP to monitoring
  !remove_ip <ip>          - Remove IP from monitoring
  !block_ip <ip> [reason]  - Block IP address
  !unblock_ip <ip>         - Unblock IP address
  !blocked                 - List blocked IPs
  !monitored               - List monitored IPs

{Colors.GREEN}💡 EXAMPLES:{Colors.RESET}
  nikto example.com
  nikto https://example.com -ssl -port 443
  block 192.168.1.100 Port scan detected
  monitor add 10.0.0.5 Suspicious traffic
  !add_ip 192.168.1.100 SSH brute force
  !block_ip 10.0.0.5 DDoS attempt

{Colors.YELLOW}└─────────────────────────────────────────────────────────────────────┘{Colors.RESET}
        """
        print(help_text)
    
    def check_dependencies(self):
        """Check for required dependencies"""
        print(f"\n{Colors.CYAN}🔍 Checking dependencies...{Colors.RESET}")
        
        required_tools = ['ping', 'nmap', 'curl', 'dig', 'traceroute', 'nikto']
        missing = []
        
        for tool in required_tools:
            if shutil.which(tool):
                print(f"{Colors.GREEN}✅ {tool}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  {tool} not found{Colors.RESET}")
                missing.append(tool)
        
        if 'nikto' in missing:
            print(f"\n{Colors.YELLOW}⚠️  Nikto is not installed. Web vulnerability scanning will be unavailable.{Colors.RESET}")
            print(f"{Colors.WHITE}Install Nikto with:{Colors.RESET}")
            if platform.system().lower() == 'linux':
                print(f"  sudo apt-get install nikto")
            elif platform.system().lower() == 'darwin':
                print(f"  brew install nikto")
        
        if missing:
            print(f"\n{Colors.YELLOW}⚠️  Some tools are missing. Some features may not work properly.{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Dependencies check complete{Colors.RESET}")
    
    def setup_discord(self):
        """Setup Discord bot"""
        print(f"\n{Colors.CYAN}🤖 Discord Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        token = input(f"{Colors.YELLOW}Enter Discord bot token (or press Enter to skip): {Colors.RESET}").strip()
        if not token:
            print(f"{Colors.YELLOW}⚠️  Discord setup skipped{Colors.RESET}")
            return
        
        channel_id = input(f"{Colors.YELLOW}Enter channel ID for notifications (optional): {Colors.RESET}").strip()
        prefix = input(f"{Colors.YELLOW}Enter command prefix (default: !): {Colors.RESET}").strip() or "!"
        admin_role = input(f"{Colors.YELLOW}Enter admin role name (default: Admin): {Colors.RESET}").strip() or "Admin"
        
        if self.discord_bot.save_config(token, channel_id, True, prefix, admin_role):
            print(f"{Colors.GREEN}✅ Discord configured!{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Admin role set to: {admin_role}{Colors.RESET}")
            
            # Start Discord bot
            if self.discord_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Discord bot started! Use '{prefix}help' in Discord{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save Discord configuration{Colors.RESET}")
    
    def setup_telegram(self):
        """Setup Telegram bot"""
        print(f"\n{Colors.CYAN}📱 Telegram Bot Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        print(f"{Colors.YELLOW}To create a Telegram bot:{Colors.RESET}")
        print(f"1. Open Telegram and search for @BotFather")
        print(f"2. Send /newbot to create a new bot")
        print(f"3. Follow instructions to get API ID and Hash")
        print()
        
        api_id = input(f"{Colors.YELLOW}Enter API ID (or press Enter to skip): {Colors.RESET}").strip()
        if not api_id:
            print(f"{Colors.YELLOW}⚠️  Telegram setup skipped{Colors.RESET}")
            return
        
        api_hash = input(f"{Colors.YELLOW}Enter API Hash: {Colors.RESET}").strip()
        phone_number = input(f"{Colors.YELLOW}Enter your phone number (with country code, optional): {Colors.RESET}").strip()
        channel_id = input(f"{Colors.YELLOW}Enter channel ID (optional): {Colors.RESET}").strip()
        
        if self.telegram_bot.save_config(api_id, api_hash, phone_number, channel_id, True):
            print(f"{Colors.GREEN}✅ Telegram configured!{Colors.RESET}")
            
            # Start Telegram bot
            if self.telegram_bot.start_bot_thread():
                print(f"{Colors.GREEN}✅ Telegram bot started! Use /help in Telegram{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to save Telegram configuration{Colors.RESET}")
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'nikto_history':
            result = self.handler.execute("nikto_history")
            if result['success']:
                data = result['data']
                print(f"\n{Colors.CYAN}📊 Nikto Scan History{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                
                for scan in data.get('scans', [])[:5]:
                    print(f"\n{Colors.WHITE}Target: {scan.get('target', 'Unknown')}{Colors.RESET}")
                    print(f"  Time: {scan.get('timestamp', '')[:19]}")
                    print(f"  Duration: {scan.get('scan_duration', 0):.1f}s")
                    if scan.get('severity'):
                        sev_color = Colors.RED if scan['severity'] in ['critical', 'high'] else Colors.YELLOW
                        print(f"  {sev_color}Severity: {scan['severity']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to get Nikto history{Colors.RESET}")
        
        elif cmd == 'blocked':
            result = self.handler.execute("blocked")
            if result['success']:
                data = result['data']
                print(f"\n{Colors.RED}🔒 Blocked IPs ({data.get('count', 0)}){Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                
                for ip_data in data.get('blocked_ips', []):
                    print(f"\n{Colors.WHITE}IP: {ip_data.get('ip_address', 'Unknown')}{Colors.RESET}")
                    print(f"  Blocked: {ip_data.get('blocked_date', '')[:19]}")
                    print(f"  Reason: {ip_data.get('reason', 'N/A')}")
                    print(f"  Blocked by: {ip_data.get('blocked_by', 'system')}")
            else:
                print(f"{Colors.RED}❌ Failed to get blocked IPs{Colors.RESET}")
        
        elif cmd == 'start':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
            print(f"{Colors.YELLOW}🛑 Threat monitoring stopped{Colors.RESET}")
        
        elif cmd == 'status':
            status = self.monitor.get_status()
            print(f"\n{Colors.CYAN}📊 Monitoring Status:{Colors.RESET}")
            print(f"  Active: {'✅ Yes' if status['monitoring'] else '❌ No'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Blocked IPs: {status['blocked_ips_count']}")
            print(f"  Auto-block: {'✅ Enabled' if status['auto_block'] else '❌ Disabled'}")
            
            threats = self.db.get_recent_threats(3)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] == 'high' else Colors.YELLOW
                    print(f"  {severity_color}{threat['threat_type']} from {threat['source_ip']}{Colors.RESET}")
        
        elif cmd == 'threats':
            threats = self.db.get_recent_threats(10)
            if threats:
                print(f"\n{Colors.RED}🚨 Recent Threats:{Colors.RESET}")
                for threat in threats:
                    severity_color = Colors.RED if threat['severity'] == 'high' else Colors.YELLOW
                    print(f"\n{severity_color}[{threat['timestamp'][:19]}] {threat['threat_type']}{Colors.RESET}")
                    print(f"  Source: {threat['source_ip']}")
                    print(f"  Severity: {threat['severity']}")
                    print(f"  Description: {threat['description']}")
                    print(f"  Action: {threat['action_taken']}")
            else:
                print(f"{Colors.GREEN}✅ No recent threats detected{Colors.RESET}")
        
        elif cmd == 'history':
            history = self.db.get_command_history(20)
            if history:
                print(f"\n{Colors.CYAN}📜 Command History:{Colors.RESET}")
                for record in history:
                    status = f"{Colors.GREEN}✅" if record['success'] else f"{Colors.RED}❌"
                    print(f"{status} [{record['source']}] {record['command'][:50]}{Colors.RESET}")
                    print(f"     {record['timestamp'][:19]}")
            else:
                print(f"{Colors.YELLOW}📜 No command history{Colors.RESET}")
        
        elif cmd == 'report':
            result = self.handler.execute("report")
            if result['success']:
                data = result['data']
                print(f"\n{Colors.CYAN}📊 Security Report{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                print(f"\n{Colors.WHITE}Generated: {data.get('generated_at', '')[:19]}{Colors.RESET}")
                
                stats = data.get('statistics', {})
                print(f"\n{Colors.GREEN}📈 Statistics:{Colors.RESET}")
                print(f"  Total Commands: {stats.get('total_commands', 0)}")
                print(f"  Total Scans: {stats.get('total_scans', 0)}")
                print(f"  Nikto Scans: {stats.get('total_nikto_scans', 0)}")
                print(f"  Total Threats: {stats.get('total_threats', 0)}")
                
                threats = data.get('threat_summary', {})
                print(f"\n{Colors.RED}🚨 Threat Summary:{Colors.RESET}")
                print(f"  Critical: {threats.get('critical', 0)}")
                print(f"  High: {threats.get('high', 0)}")
                print(f"  Medium: {threats.get('medium', 0)}")
                print(f"  Low: {threats.get('low', 0)}")
                
                blocked = data.get('blocked_ips', {})
                print(f"\n{Colors.RED}🔒 Blocked IPs:{Colors.RESET}")
                print(f"  Total: {blocked.get('count', 0)}")
                
                if data.get('recommendations'):
                    print(f"\n{Colors.YELLOW}💡 Recommendations:{Colors.RESET}")
                    for rec in data['recommendations']:
                        print(f"  • {rec}")
                
                if 'report_file' in data:
                    print(f"\n{Colors.GREEN}✅ Report saved: {data['report_file']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}❌ Failed to generate report: {result.get('output', 'Unknown error')}{Colors.RESET}")
        
        elif cmd == 'config' and len(args) >= 2:
            service = args[0].lower()
            
            if service == 'discord':
                if len(args) >= 3 and args[1] == 'token':
                    token = args[2]
                    channel = self.discord_bot.config.get('channel_id', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role)
                    print(f"{Colors.GREEN}✅ Discord token configured{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'channel':
                    channel_id = args[2]
                    token = self.discord_bot.config.get('token', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    self.discord_bot.save_config(token, channel_id, True, prefix, admin_role)
                    print(f"{Colors.GREEN}✅ Discord channel ID configured{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'prefix':
                    prefix = args[2]
                    token = self.discord_bot.config.get('token', '')
                    channel = self.discord_bot.config.get('channel_id', '')
                    admin_role = self.discord_bot.config.get('admin_role', 'Admin')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role)
                    print(f"{Colors.GREEN}✅ Discord prefix configured to '{prefix}'{Colors.RESET}")
                
                elif len(args) >= 3 and args[1] == 'admin_role':
                    admin_role = args[2]
                    token = self.discord_bot.config.get('token', '')
                    channel = self.discord_bot.config.get('channel_id', '')
                    prefix = self.discord_bot.config.get('prefix', '!')
                    self.discord_bot.save_config(token, channel, True, prefix, admin_role)
                    print(f"{Colors.GREEN}✅ Discord admin role configured to '{admin_role}'{Colors.RESET}")
            
            elif service == 'telegram' and len(args) >= 4 and args[1] == 'api':
                api_id = args[2]
                api_hash = args[3]
                phone = self.telegram_bot.config.get('phone_number', '')
                channel = self.telegram_bot.config.get('channel_id', '')
                self.telegram_bot.save_config(api_id, api_hash, phone, channel, True)
                print(f"{Colors.GREEN}✅ Telegram API configured{Colors.RESET}")
        
        elif cmd == 'start_discord':
            if not self.discord_bot.config.get('token'):
                print(f"{Colors.RED}❌ Discord token not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config discord token <your_token>{Colors.RESET}")
            else:
                if self.discord_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Discord bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Discord bot{Colors.RESET}")
        
        elif cmd == 'start_telegram':
            if not self.telegram_bot.config.get('api_id'):
                print(f"{Colors.RED}❌ Telegram API not configured{Colors.RESET}")
                print(f"{Colors.YELLOW}Use: config telegram api <id> <hash>{Colors.RESET}")
            else:
                if self.telegram_bot.start_bot_thread():
                    print(f"{Colors.GREEN}✅ Telegram bot started!{Colors.RESET}")
                else:
                    print(f"{Colors.RED}❌ Failed to start Telegram bot{Colors.RESET}")
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'exit':
            self.running = False
            print(f"\n{Colors.YELLOW}👋 Thank you for using Spider Bot Pro!{Colors.RESET}")
        
        else:
            # Execute as generic command
            result = self.handler.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                
                if isinstance(output, dict):
                    # Pretty print dictionaries
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                
                print(f"\n{Colors.GREEN}✅ Command executed ({result['execution_time']:.2f}s){Colors.RESET}")
            else:
                print(f"\n{Colors.RED}❌ Command failed: {result.get('output', 'Unknown error')}{Colors.RESET}")
    
    def run(self):
        """Main application loop"""
        # Clear screen and show banner
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        
        # Check dependencies
        self.check_dependencies()
        
        # Setup bots if configured
        print(f"\n{Colors.CYAN}🤖 Bot Configuration{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
        # Check Discord
        if self.discord_bot.config.get('enabled') and self.discord_bot.config.get('token'):
            print(f"{Colors.GREEN}✅ Discord bot configured (Admin role: {self.discord_bot.config.get('admin_role', 'Admin')}){Colors.RESET}")
            self.discord_bot.start_bot_thread()
        else:
            setup_discord = input(f"{Colors.YELLOW}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_discord == 'y':
                self.setup_discord()
        
        # Check Telegram
        if self.telegram_bot.config.get('enabled') and self.telegram_bot.config.get('api_id'):
            print(f"{Colors.GREEN}✅ Telegram bot configured{Colors.RESET}")
            self.telegram_bot.start_bot_thread()
        else:
            setup_telegram = input(f"{Colors.YELLOW}Setup Telegram bot? (y/n): {Colors.RESET}").strip().lower()
            if setup_telegram == 'y':
                self.setup_telegram()
        
        # Ask about monitoring
        auto_monitor = input(f"\n{Colors.YELLOW}Start threat monitoring automatically? (y/n): {Colors.RESET}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
            print(f"{Colors.GREEN}✅ Threat monitoring started{Colors.RESET}")
        
        print(f"\n{Colors.GREEN}✅ Tool ready! Type 'help' for commands.{Colors.RESET}")
        print(f"{Colors.YELLOW}📢 Discord commands: !nikto, !add_ip, !remove_ip, !block_ip, !unblock_ip{Colors.RESET}")
        
        # Main command loop
        while self.running:
            try:
                prompt = f"{Colors.RED}[{Colors.WHITE}spiderbot-pro{Colors.RED}]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.RESET}")
                self.running = False
            
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
                logger.error(f"Command error: {e}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.db.close()
        
        print(f"\n{Colors.GREEN}✅ Tool shutdown complete.{Colors.RESET}")
        print(f"{Colors.CYAN}📁 Logs saved to: {LOG_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}💾 Database: {DATABASE_FILE}{Colors.RESET}")
        print(f"{Colors.CYAN}🌐 Nikto results: {NIKTO_RESULTS_DIR}{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.CYAN}🚀 Starting Spider Bot Pro v5.0.0...{Colors.RESET}")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print(f"{Colors.RED}❌ Python 3.7 or higher is required{Colors.RESET}")
            sys.exit(1)
        
        # Create and run application
        app = SpiderBotPro()
        app.run()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Fatal error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()