import os
import sys
import socket
import psutil
import requests
import hashlib
import time
import json
import threading
import platform
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import queue
import traceback
import ctypes
from urllib.parse import urlparse
import logging

# Platform-specific imports with error handling
try:
    if platform.system() == 'Windows':
        import winreg
        WINDOWS_AVAILABLE = True
    else:
        WINDOWS_AVAILABLE = False
except ImportError:
    WINDOWS_AVAILABLE = False

try:
    if platform.system() == 'Windows':
        import win32api, win32process, win32con
        PYWIN32_AVAILABLE = True
    else:
        PYWIN32_AVAILABLE = False
except ImportError:
    PYWIN32_AVAILABLE = False

# Configuration
THREAT_DATABASE_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt"
MALWARE_HASH_DB = "https://virusshare.com/hashfiles/VirusShare_00497.md5"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
BLACKLIST_CACHE = "threat_blacklist.txt"
HASH_DB_CACHE = "malware_hashes.txt"
LOG_FILE = "security_scan.log"
CONFIG_FILE = "security_config.json"

SUSPICIOUS_KEYWORDS = [
    "spy", "track", "monitor", "keylog", "stalk", "remote", "admin", "hidden",
    "hack", "stealer", "rat", "exploit", "inject", "backdoor", "rootkit",
    "trojan", "virus", "malware", "spyware", "adware"
]

# File extensions to scan in fast mode
EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.msi', '.scr', '.com', '.pif', '.application', '.gadget', '.msp', '.mst'
}

# Initialize global state
scan_results = []
last_scan_time = None
monitoring_active = False
config = {
    "remote_logging": False,
    "log_location": LOG_FILE,
    "scan_interval": 300,
    "virustotal_api_key": "",
    "email_settings": {},
    "discord_webhook": "",
    "fast_scan": False,
    "scan_depth": 3,
    "max_file_size": 100 * 1024 * 1024,  # 100MB
    "api_rate_limit": 4,  # requests per minute for VirusTotal
    "excluded_dirs": [
        "C:\\Windows\\WinSxS",
        "C:\\Windows\\Temp",
        "C:\\System Volume Information",
        "C:\\$Recycle.Bin",
        "C:\\ProgramData\\Microsoft\\Crypto",
        "C:\\hiberfil.sys",
        "C:\\pagefile.sys",
        "C:\\swapfile.sys"
    ]
}

# For cross-thread communication
scan_queue = queue.Queue()
log_queue = queue.Queue()

def is_admin():
    """Check if the current process has administrator privileges."""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def setup_logging():
    """Setup proper logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(config["log_location"]),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

class RateLimiter:
    """Simple rate limiter for API calls."""
    def __init__(self, max_calls, time_window):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded."""
        with self.lock:
            now = time.time()
            # Remove old calls
            self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
            
            if len(self.calls) >= self.max_calls:
                sleep_time = self.time_window - (now - self.calls[0]) + 1
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    self.calls = []
            
            self.calls.append(now)

class SecurityScanner:
    def __init__(self):
        self.known_hashes = set()
        self.known_processes = set()
        self.startup_items = set()
        self.file_hash_cache = {}
        self.scanned_files = 0
        self.malicious_files = 0
        self.scan_cancelled = False
        self.vt_rate_limiter = RateLimiter(config["api_rate_limit"], 60)  # 4 calls per minute
        
        self.load_config()
        self.update_threat_database()
        self.update_malware_hashes()
        self.baseline_system()
        self.log("Security Scanner initialized")

    def load_config(self):
        """Load configuration from file with error handling."""
        global config
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    config.update(loaded_config)
                self.log("Configuration loaded successfully")
        except Exception as e:
            self.log(f"Config load error: {str(e)}", level="ERROR")
            logger.exception("Failed to load configuration")

    def save_config(self):
        """Save configuration to file with error handling."""
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            self.log("Configuration saved successfully")
        except Exception as e:
            self.log(f"Config save error: {str(e)}", level="ERROR")
            logger.exception("Failed to save configuration")

    def log(self, message, level="INFO"):
        """Enhanced logging with queue support for GUI updates."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Add to log queue for GUI updates
        try:
            log_queue.put_nowait(log_entry)
        except queue.Full:
            pass  # Don't block if queue is full
        
        # Log using Python's logging module
        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "DEBUG":
            logger.debug(message)
        else:
            logger.info(message)
        
        return log_entry

    def safe_request(self, url, timeout=30):
        """Make a safe HTTP request with proper error handling."""
        try:
            headers = {
                'User-Agent': 'SecurityScanner/1.0',
                'Accept': 'text/plain, application/json'
            }
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            self.log(f"Request timeout for {url}", level="WARNING")
            return None
        except requests.exceptions.ConnectionError:
            self.log(f"Connection error for {url}", level="WARNING")
            return None
        except requests.exceptions.HTTPError as e:
            self.log(f"HTTP error for {url}: {e}", level="WARNING")
            return None
        except Exception as e:
            self.log(f"Unexpected error requesting {url}: {e}", level="ERROR")
            return None

    def update_threat_database(self):
        """Update threat database with improved error handling."""
        try:
            # Check if cached file is recent (less than 24 hours old)
            if os.path.exists(BLACKLIST_CACHE):
                file_age = time.time() - os.path.getmtime(BLACKLIST_CACHE)
                if file_age < 86400:  # 24 hours
                    with open(BLACKLIST_CACHE, 'r', encoding='utf-8') as f:
                        domains = set(line.strip() for line in f if line.strip())
                        self.log(f"Using cached threat database ({len(domains)} entries)")
                        return domains
            
            # Download fresh data
            self.log("Updating threat database...")
            response = self.safe_request(THREAT_DATABASE_URL)
            if response:
                domains = set(line.strip() for line in response.text.splitlines() if line.strip())
                
                # Save to cache
                with open(BLACKLIST_CACHE, 'w', encoding='utf-8') as f:
                    for domain in domains:
                        f.write(domain + '\n')
                
                self.log(f"Updated threat database ({len(domains)} entries)")
                return domains
            else:
                self.log("Failed to download threat database", level="ERROR")
                
        except Exception as e:
            self.log(f"Database update failed: {str(e)}", level="ERROR")
            logger.exception("Threat database update failed")
        
        # Fallback to cached version if available
        if os.path.exists(BLACKLIST_CACHE):
            try:
                with open(BLACKLIST_CACHE, 'r', encoding='utf-8') as f:
                    domains = set(line.strip() for line in f if line.strip())
                    self.log(f"Using cached threat database ({len(domains)} entries)")
                    return domains
            except Exception as e:
                self.log(f"Failed to read cached database: {e}", level="ERROR")
        
        return set()

    def update_malware_hashes(self):
        """Update malware hash database with improved error handling."""
        try:
            # Check if cached file is recent
            if os.path.exists(HASH_DB_CACHE):
                file_age = time.time() - os.path.getmtime(HASH_DB_CACHE)
                if file_age < 86400:  # 24 hours
                    with open(HASH_DB_CACHE, 'r', encoding='utf-8') as f:
                        self.known_hashes = set(line.strip().lower() for line in f if line.strip())
                        self.log(f"Using cached malware hashes ({len(self.known_hashes)} entries)")
                        return
            
            # Download fresh data
            self.log("Updating malware hashes...")
            response = self.safe_request(MALWARE_HASH_DB)
            if response:
                hashes = set(line.strip().lower() for line in response.text.splitlines() if line.strip())
                
                # Save to cache
                with open(HASH_DB_CACHE, 'w', encoding='utf-8') as f:
                    for hash_val in hashes:
                        f.write(hash_val + '\n')
                
                self.known_hashes = hashes
                self.log(f"Updated malware hashes ({len(self.known_hashes)} entries)")
            else:
                self.log("Failed to download malware hashes", level="ERROR")
                
        except Exception as e:
            self.log(f"Hash update failed: {str(e)}", level="ERROR")
            logger.exception("Malware hash update failed")
        
        # Fallback to cached version
        if os.path.exists(HASH_DB_CACHE):
            try:
                with open(HASH_DB_CACHE, 'r', encoding='utf-8') as f:
                    self.known_hashes = set(line.strip().lower() for line in f if line.strip())
                    self.log(f"Using cached malware hashes ({len(self.known_hashes)} entries)")
            except Exception as e:
                self.log(f"Failed to read cached hashes: {e}", level="ERROR")

    def baseline_system(self):
        """Create system baseline with error handling."""
        try:
            # Capture initial running processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    process_name = proc.info['name']
                    if process_name:
                        self.known_processes.add(process_name.lower())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.log(f"Error reading process info: {e}", level="DEBUG")
                    continue
            
            # Capture startup items
            self.startup_items = self.get_startup_items()
            self.log(f"System baseline created: {len(self.known_processes)} processes, {len(self.startup_items)} startup items")
            
        except Exception as e:
            self.log(f"Baseline creation failed: {str(e)}", level="ERROR")
            logger.exception("System baseline creation failed")

    def get_startup_items(self):
        """Get startup items with proper error handling."""
        startup_items = set()
        
        if not WINDOWS_AVAILABLE:
            return startup_items
            
        registries = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        ]
        
        for hive, path in registries:
            try:
                with winreg.OpenKey(hive, path) as key:
                    idx = 0
                    while True:
                        try:
                            name, value, reg_type = winreg.EnumValue(key, idx)
                            if name:
                                startup_items.add(name.lower())
                            idx += 1
                        except OSError:
                            break
                        except Exception as e:
                            self.log(f"Error reading registry value: {e}", level="DEBUG")
                            idx += 1
                            continue
            except FileNotFoundError:
                continue
            except Exception as e:
                self.log(f"Error reading registry key {path}: {e}", level="DEBUG")
                continue
                
        return startup_items

    def is_safe_file(self, file_path):
        """Check if file is safe to access."""
        try:
            # Skip system files that commonly cause access issues
            unsafe_files = {
                'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
                'ntuser.dat', 'ntuser.dat.log', 'usrclass.dat'
            }
            
            filename = os.path.basename(file_path).lower()
            if filename in unsafe_files:
                return False
            
            # Skip temporary files and logs
            if filename.endswith(('.tmp', '.log.tmp', '.dmp')):
                return False
            
            # Skip files in system directories that are known to cause issues
            system_paths = [
                'C:\\System Volume Information',
                'C:\\Windows\\WinSxS',
                'C:\\Windows\\Temp',
                'C:\\$Recycle.Bin',
                'C:\\ProgramData\\Microsoft\\Crypto'
            ]
            
            for sys_path in system_paths:
                if file_path.startswith(sys_path):
                    return False
            
            return True
            
        except Exception:
            return False

    def calculate_file_hash(self, file_path):
        """Calculate file hash with improved error handling."""
        if not self.is_safe_file(file_path):
            return None
        
        # Check cache first
        if file_path in self.file_hash_cache:
            return self.file_hash_cache[file_path]
        
        try:
            # Check file size first
            file_size = os.path.getsize(file_path)
            if file_size > config["max_file_size"]:
                return None
            
            # Skip empty files
            if file_size == 0:
                return None
                
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
                    
                hash_value = file_hash.hexdigest().lower()
                self.file_hash_cache[file_path] = hash_value
                return hash_value
                
        except (PermissionError, OSError) as e:
            # Only log unexpected errors
            if e.errno not in (13, 32, 2):  # Permission denied, sharing violation, file not found
                self.log(f"Hash calculation error for {file_path}: {str(e)}", level="DEBUG")
            return None
        except Exception as e:
            self.log(f"Unexpected hash calculation error for {file_path}: {str(e)}", level="DEBUG")
            return None

    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal with rate limiting."""
        if not config.get("virustotal_api_key") or config.get("fast_scan", False):
            return False
        
        try:
            # Rate limiting
            self.vt_rate_limiter.wait_if_needed()
            
            headers = {"x-apikey": config["virustotal_api_key"]}
            url = f"{VIRUSTOTAL_API_URL}{file_hash}"
            
            response = self.safe_request(url)
            if response and response.status_code == 200:
                result = response.json()
                attributes = result.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                
                if malicious_count > 0:
                    self.log(f"VirusTotal detected malicious file: {file_hash} ({malicious_count} engines)")
                    return True
                    
        except Exception as e:
            self.log(f"VirusTotal check failed for {file_hash}: {str(e)}", level="DEBUG")
        
        return False

    def scan_file_hash(self, file_path):
        """Scan file hash against known malware databases."""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
        
        # Check local hash database first
        if file_hash in self.known_hashes:
            self.malicious_files += 1
            self.log(f"Malicious file detected (local DB): {file_path}")
            return True
        
        # Check VirusTotal if enabled
        if self.check_virustotal(file_hash):
            self.malicious_files += 1
            return True
        
        return False

    def scan_file_system(self):
        """Scan file system with improved error handling and progress tracking."""
        suspicious = []
        self.log("Starting file system scan...")
        
        # Get available drives
        drives = []
        if platform.system() == 'Windows':
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
                     if os.path.exists(f"{d}:")]
        else:
            drives = ['/']
        
        total_drives = len(drives)
        
        for drive_idx, drive in enumerate(drives):
            if self.scan_cancelled:
                break
                
            self.log(f"Scanning drive: {drive} ({drive_idx + 1}/{total_drives})")
            
            try:
                for root, dirs, files in os.walk(drive):
                    if self.scan_cancelled:
                        break
                    
                    # Skip excluded directories
                    if any(excluded in root for excluded in config["excluded_dirs"]):
                        dirs.clear()  # Don't descend into subdirectories
                        continue
                    
                    # Skip hidden directories and system directories
                    if (os.path.basename(root).startswith('.') or 
                        os.path.basename(root).startswith('$')):
                        dirs.clear()
                        continue
                    
                    # Limit recursion depth
                    current_depth = root.replace(drive, '').count(os.sep)
                    if current_depth > config["scan_depth"]:
                        dirs.clear()
                        continue
                    
                    # Remove hidden/system directories from dirs list
                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('$')]
                    
                    for file in files:
                        if self.scan_cancelled:
                            break
                            
                        file_path = os.path.join(root, file)
                        
                        # Skip files that are likely to cause issues
                        if not self.is_safe_file(file_path):
                            continue
                        
                        # In fast mode, only scan executable files
                        if config.get("fast_scan", False):
                            file_ext = os.path.splitext(file)[1].lower()
                            if file_ext not in EXECUTABLE_EXTENSIONS:
                                continue
                        
                        try:
                            # Check for suspicious keywords in filename
                            if any(kw in file.lower() for kw in SUSPICIOUS_KEYWORDS):
                                suspicious.append(("Suspicious File", file_path))
                            
                            # Scan file hash
                            if self.scan_file_hash(file_path):
                                suspicious.append(("Malicious File", file_path))
                            
                            self.scanned_files += 1
                            
                            # Update progress every 50 files
                            if self.scanned_files % 50 == 0:
                                try:
                                    scan_queue.put_nowait(("file_progress", (self.scanned_files, self.malicious_files)))
                                except queue.Full:
                                    pass
                                    
                        except Exception as e:
                            self.log(f"Error scanning file {file_path}: {e}", level="DEBUG")
                            continue
                            
            except Exception as e:
                self.log(f"Error scanning drive {drive}: {e}", level="ERROR")
                continue
        
        return suspicious

    def scan_processes(self):
        """Scan running processes with error handling."""
        suspicious = []
        current_processes = set()
        
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
            total_processes = len(processes)
            processed = 0
            
            for proc in processes:
                if self.scan_cancelled:
                    break
                    
                try:
                    name = proc.info['name']
                    if not name:
                        continue
                        
                    name_lower = name.lower()
                    current_processes.add(name_lower)
                    
                    # Check for unknown processes
                    if name_lower not in self.known_processes:
                        suspicious.append(("New Process", f"{name} (PID: {proc.pid})"))
                        self.known_processes.add(name_lower)
                    
                    # Check process name for suspicious keywords
                    if any(kw in name_lower for kw in SUSPICIOUS_KEYWORDS):
                        suspicious.append(("Suspicious Process", f"{name} (PID: {proc.pid})"))
                    
                    # Check command line
                    cmdline = proc.info.get('cmdline')
                    if cmdline:
                        cmdline_str = " ".join(cmdline).lower()
                        if any(kw in cmdline_str for kw in SUSPICIOUS_KEYWORDS):
                            suspicious.append(("Suspicious Command", f"{name}: {cmdline_str[:200]}"))
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.log(f"Error scanning process: {e}", level="DEBUG")
                    continue
                
                processed += 1
                if processed % 25 == 0:
                    try:
                        scan_queue.put_nowait(("progress_update", f"Scanned {processed}/{total_processes} processes"))
                    except queue.Full:
                        pass
                        
        except Exception as e:
            self.log(f"Process scan failed: {e}", level="ERROR")
            logger.exception("Process scanning failed")
        
        return suspicious

    def scan_network_connections(self):
        """Scan network connections with improved error handling."""
        suspicious = []
        
        try:
            blacklist = self.update_threat_database()
            connections = psutil.net_connections(kind='inet')
            total_connections = len(connections)
            processed = 0
            
            for conn in connections:
                if self.scan_cancelled:
                    break
                    
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        ip = conn.raddr.ip
                        
                        # Skip local and private IPs
                        if (ip.startswith(('127.', '10.', '192.168.', '172.')) or
                            ip.startswith('169.254.')):  # Link-local
                            continue
                        
                        # Check if IP is in blacklist
                        if ip in blacklist:
                            suspicious.append(("Malicious Connection", f"{ip}:{conn.raddr.port} (PID: {conn.pid})"))
                        
                        # Reverse DNS lookup with timeout
                        try:
                            socket.settimeout(2)
                            host = socket.gethostbyaddr(ip)[0]
                            if host in blacklist:
                                suspicious.append(("Malicious Host", f"{host} ({ip})"))
                        except (socket.herror, socket.timeout, OSError):
                            pass
                        finally:
                            socket.settimeout(None)
                            
                except Exception as e:
                    self.log(f"Error checking connection: {e}", level="DEBUG")
                    continue
                
                processed += 1
                if processed % 50 == 0:
                    try:
                        scan_queue.put_nowait(("progress_update", f"Scanned {processed}/{total_connections} connections"))
                    except queue.Full:
                        pass
                        
        except Exception as e:
            self.log(f"Network scan failed: {e}", level="ERROR")
            logger.exception("Network scanning failed")
        
        return suspicious

    def scan_startup_items(self):
        """Scan startup items with error handling."""
        suspicious = []
        
        try:
            current_startup = self.get_startup_items()
            
            # Check for new startup items
            new_items = current_startup - self.startup_items
            for item in new_items:
                suspicious.append(("New Startup Item", item))
                self.startup_items.add(item)
            
            # Check existing items for suspicious keywords
            for item in current_startup:
                if any(kw in item.lower() for kw in SUSPICIOUS_KEYWORDS):
                    suspicious.append(("Suspicious Startup", item))
                    
        except Exception as e:
            self.log(f"Startup scan failed: {e}", level="ERROR")
            logger.exception("Startup item scanning failed")
        
        return suspicious

    def scan_installed_software(self):
        """Scan installed software with error handling."""
        suspicious = []
        
        if not WINDOWS_AVAILABLE:
            return suspicious
            
        try:
            registries = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            ]
            
            for hive, path in registries:
                if self.scan_cancelled:
                    break
                    
                try:
                    with winreg.OpenKey(hive, path) as key:
                        idx = 0
                        while True:
                            if self.scan_cancelled:
                                break
                                
                            try:
                                subkey_name = winreg.EnumKey(key, idx)
                                with winreg.OpenKey(key, subkey_name) as subkey:
                                    try:
                                        name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                        
                                        # Check for suspicious keywords
                                        if any(kw in name.lower() for kw in SUSPICIOUS_KEYWORDS):
                                            suspicious.append(("Suspicious Software", name))
                                            
                                    except OSError:
                                        pass  # DisplayName not found
                                idx += 1
                            except OSError:
                                break  # No more subkeys
                            except Exception as e:
                                self.log(f"Error reading software registry: {e}", level="DEBUG")
                                idx += 1
                                continue
                                
                except FileNotFoundError:
                    continue
                except Exception as e:
                    self.log(f"Error accessing registry {path}: {e}", level="DEBUG")
                    continue
                    
        except Exception as e:
            self.log(f"Software scan failed: {e}", level="ERROR")
            logger.exception("Software scanning failed")
        
        return suspicious

    def cancel_scan(self):
        """Cancel the current scan."""
        self.scan_cancelled = True
        self.log("Scan cancellation requested")

    def full_scan(self):
        """Perform a full system scan with proper error handling."""
        global last_scan_time
        
        self.log("Starting full system scan")
        self.scan_cancelled = False
        results = []
        self.scanned_files = 0
        self.malicious_files = 0
        
        # Set lower process priority if possible
        try:
            if PYWIN32_AVAILABLE:
                handle = win32api.GetCurrentProcess()
                win32process.SetPriorityClass(handle, win32process.BELOW_NORMAL_PRIORITY_CLASS)
                self.log("Reduced process priority for scanning")
        except Exception as e:
            self.log(f"Could not reduce process priority: {e}", level="DEBUG")
        
        # Define scan steps
        scan_steps = [
            ("Scanning running processes", self.scan_processes),
            ("Scanning network connections", self.scan_network_connections),
            ("Scanning startup items", self.scan_startup_items),
            ("Scanning installed software", self.scan_installed_software),
            ("Scanning file system", self.scan_file_system),
        ]
        
        # Perform scans with progress tracking
        for i, (step_name, scan_func) in enumerate(scan_steps):
            if self.scan_cancelled:
                self.log("Scan cancelled by user")
                break
                
            self.log(step_name)
            try:
                scan_queue.put_nowait(("progress", (i + 1, len(scan_steps), step_name)))
            except queue.Full:
                pass
                
            try:
                step_results = scan_func()
                results.extend(step_results)
                self.log(f"{step_name} completed: found {len(step_results)} items")
            except Exception as e:
                self.log(f"Error during {step_name}: {str(e)}", level="ERROR")
                logger.exception(f"Error in {step_name}")
        
        if not self.scan_cancelled:
            last_scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.log(f"Scan completed. Scanned {self.scanned_files} files, found {self.malicious_files} malicious files and {len(results)} potential threats")
        else:
            self.log("Scan was cancelled before completion")
            
        return results


class SecurityDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Initialize scanner
        try:
            self.scanner = SecurityScanner()
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Failed to initialize scanner: {e}")
            self.destroy()
            return
            
        self.title("Advanced Security Scanner Dashboard")
        self.geometry("1200x800")
        self.minsize(800, 600)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Threading control
        self.monitoring_thread = None
        self.scan_thread = None
        self.scan_in_progress = False
        
        # Create interface
        self.create_widgets()
        self.load_config()
        
        # Start dashboard updates
        self.update_dashboard()
        
    def create_widgets(self):
        """Create the main GUI interface."""
        # Create main notebook for tabs
        self.tab_control = ttk.Notebook(self)
        
        # Create tabs
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.scan_tab = ttk.Frame(self.tab_control)
        self.config_tab = ttk.Frame(self.tab_control)
        self.logs_tab = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.dashboard_tab, text='Dashboard')
        self.tab_control.add(self.scan_tab, text='Scan & Monitor')
        self.tab_control.add(self.config_tab, text='Configuration')
        self.tab_control.add(self.logs_tab, text='Logs')
        self.tab_control.pack(expand=1, fill="both", padx=5, pady=5)
        
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_config_tab()
        self.create_logs_tab()
        
    def create_dashboard_tab(self):
        """Create the dashboard tab."""
        # Main status frame
        status_frame = ttk.LabelFrame(self.dashboard_tab, text="System Security Status")
        status_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(status_frame)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.status_text = tk.Text(text_frame, height=25, wrap="word", font=("Consolas", 10))
        status_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=status_scrollbar.set)
        
        status_scrollbar.pack(side="right", fill="y")
        self.status_text.pack(fill="both", expand=True)
        self.status_text.config(state=tk.DISABLED)
        
        # Quick actions frame
        actions_frame = ttk.LabelFrame(self.dashboard_tab, text="Quick Actions")
        actions_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ttk.Button(actions_frame, text="Quick Scan", command=self.run_quick_scan).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(actions_frame, text="Full Scan", command=self.run_full_scan).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(actions_frame, text="Update Databases", command=self.update_databases).pack(side=tk.LEFT, padx=5, pady=5)
        
    def create_scan_tab(self):
        """Create the scan and monitoring tab."""
        # Control buttons frame
        control_frame = ttk.LabelFrame(self.scan_tab, text="Scan Controls")
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # First row of buttons
        button_frame1 = ttk.Frame(control_frame)
        button_frame1.pack(fill="x", padx=5, pady=5)
        
        self.scan_button = ttk.Button(button_frame1, text="Run Full Scan", command=self.run_full_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.quick_scan_button = ttk.Button(button_frame1, text="Quick Scan", command=self.run_quick_scan)
        self.quick_scan_button.pack(side=tk.LEFT, padx=5)
        
        self.cancel_scan_button = ttk.Button(button_frame1, text="Cancel Scan", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_scan_button.pack(side=tk.LEFT, padx=5)
        
        # Second row of buttons
        button_frame2 = ttk.Frame(control_frame)
        button_frame2.pack(fill="x", padx=5, pady=5)
        
        self.monitor_start_button = ttk.Button(button_frame2, text="Start Monitoring", command=self.start_monitoring)
        self.monitor_start_button.pack(side=tk.LEFT, padx=5)
        
        self.monitor_stop_button = ttk.Button(button_frame2, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.monitor_stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(self.scan_tab, text="Scan Progress")
        progress_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to scan")
        self.progress_label.pack(fill="x", padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill="x", padx=5, pady=5)
        
        self.task_label = ttk.Label(progress_frame, text="")
        self.task_label.pack(fill="x", padx=5, pady=5)
        
        self.file_status = ttk.Label(progress_frame, text="")
        self.file_status.pack(fill="x", padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.scan_tab, text="Scan Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.scan_results = ttk.Treeview(tree_frame, columns=("Type", "Details"), show="headings")
        self.scan_results.heading("Type", text="Threat Type")
        self.scan_results.heading("Details", text="Details")
        self.scan_results.column("Type", width=150, minwidth=100)
        self.scan_results.column("Details", width=600, minwidth=400)
        
        # Scrollbars for results
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.scan_results.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.scan_results.xview)
        self.scan_results.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        self.scan_results.pack(fill="both", expand=True)
        
        # Results buttons
        results_button_frame = ttk.Frame(results_frame)
        results_button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(results_button_frame, text="Export Results", command=self.export_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(results_button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
    def create_config_tab(self):
        """Create the configuration tab."""
        # Create scrollable frame
        canvas = tk.Canvas(self.config_tab)
        scrollbar = ttk.Scrollbar(self.config_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Scan Configuration
        scan_config_frame = ttk.LabelFrame(scrollable_frame, text="Scan Configuration")
        scan_config_frame.pack(fill="x", padx=10, pady=10)
        
        # Fast scan option
        self.fast_scan_var = tk.BooleanVar()
        fast_scan_check = ttk.Checkbutton(
            scan_config_frame, 
            text="Enable Fast Scan (executable files only)",
            variable=self.fast_scan_var
        )
        fast_scan_check.pack(anchor="w", padx=10, pady=5)
        
        # Max file size
        size_frame = ttk.Frame(scan_config_frame)
        size_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(size_frame, text="Max file size (MB):").pack(side="left")
        self.max_file_size_var = tk.StringVar(value="100")
        size_entry = ttk.Entry(size_frame, textvariable=self.max_file_size_var, width=10)
        size_entry.pack(side="left", padx=(10, 0))
        
        # Scan depth
        depth_frame = ttk.Frame(scan_config_frame)
        depth_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(depth_frame, text="Scan depth (directory levels):").pack(side="left")
        self.scan_depth_var = tk.StringVar(value="3")
        depth_entry = ttk.Entry(depth_frame, textvariable=self.scan_depth_var, width=10)
        depth_entry.pack(side="left", padx=(10, 0))
        
        # Excluded directories
        excluded_frame = ttk.LabelFrame(scan_config_frame, text="Excluded Directories")
        excluded_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        excluded_text_frame = ttk.Frame(excluded_frame)
        excluded_text_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.excluded_dirs_text = tk.Text(excluded_text_frame, height=6, wrap="word")
        excluded_scroll = ttk.Scrollbar(excluded_text_frame, orient="vertical", command=self.excluded_dirs_text.yview)
        self.excluded_dirs_text.configure(yscrollcommand=excluded_scroll.set)
        
        excluded_scroll.pack(side="right", fill="y")
        self.excluded_dirs_text.pack(fill="both", expand=True)
        
        # VirusTotal Configuration
        vt_frame = ttk.LabelFrame(scrollable_frame, text="VirusTotal API Configuration")
        vt_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(vt_frame, text="API Key:").pack(anchor="w", padx=10, pady=5)
        self.vt_api_key_var = tk.StringVar()
        vt_entry = ttk.Entry(vt_frame, textvariable=self.vt_api_key_var, width=60, show="*")
        vt_entry.pack(fill="x", padx=10, pady=5)
        
        rate_frame = ttk.Frame(vt_frame)
        rate_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(rate_frame, text="Rate limit (requests/minute):").pack(side="left")
        self.rate_limit_var = tk.StringVar(value="4")
        rate_entry = ttk.Entry(rate_frame, textvariable=self.rate_limit_var, width=10)
        rate_entry.pack(side="left", padx=(10, 0))
        
        # Logging Configuration
        log_frame = ttk.LabelFrame(scrollable_frame, text="Logging Configuration")
        log_frame.pack(fill="x", padx=10, pady=10)
        
        # Log level
        level_frame = ttk.Frame(log_frame)
        level_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(level_frame, text="Log Level:").pack(side="left")
        self.log_level_var = tk.StringVar(value="INFO")
        log_level_combo = ttk.Combobox(level_frame, textvariable=self.log_level_var, 
                                      values=["DEBUG", "INFO", "WARNING", "ERROR"], 
                                      state="readonly", width=10)
        log_level_combo.pack(side="left", padx=(10, 0))
        
        # Log location
        loc_frame = ttk.Frame(log_frame)
        loc_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(loc_frame, text="Log Location:").pack(anchor="w")
        
        loc_entry_frame = ttk.Frame(loc_frame)
        loc_entry_frame.pack(fill="x", pady=5)
        self.log_location_var = tk.StringVar()
        log_entry = ttk.Entry(loc_entry_frame, textvariable=self.log_location_var, state="readonly")
        log_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(loc_entry_frame, text="Browse...", command=self.select_log_location).pack(side="right", padx=(5, 0))
        
        # Monitoring Configuration
        monitor_frame = ttk.LabelFrame(scrollable_frame, text="Monitoring Configuration")
        monitor_frame.pack(fill="x", padx=10, pady=10)
        
        interval_frame = ttk.Frame(monitor_frame)
        interval_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(interval_frame, text="Scan interval (seconds):").pack(side="left")
        self.scan_interval_var = tk.StringVar(value="300")
        interval_entry = ttk.Entry(interval_frame, textvariable=self.scan_interval_var, width=10)
        interval_entry.pack(side="left", padx=(10, 0))
        
        # Save configuration button
        save_frame = ttk.Frame(scrollable_frame)
        save_frame.pack(fill="x", padx=10, pady=20)
        ttk.Button(save_frame, text="Save Configuration", command=self.save_config).pack(pady=10)
        ttk.Button(save_frame, text="Reset to Defaults", command=self.reset_config).pack(pady=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_logs_tab(self):
        """Create the logs tab."""
        log_frame = ttk.Frame(self.logs_tab)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Log controls
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill="x", pady=(0, 10))
        
        ttk.Button(log_controls, text="Refresh Logs", command=self.load_logs).pack(side="left", padx=5)
        ttk.Button(log_controls, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)
        ttk.Button(log_controls, text="Export Logs", command=self.export_logs).pack(side="left", padx=5)
        
        # Log display
        log_display_frame = ttk.Frame(log_frame)
        log_display_frame.pack(fill="both", expand=True)
        
        self.logs_text = tk.Text(log_display_frame, wrap="word", font=("Consolas", 9))
        log_scrollbar_v = ttk.Scrollbar(log_display_frame, orient="vertical", command=self.logs_text.yview)
        log_scrollbar_h = ttk.Scrollbar(log_display_frame, orient="horizontal", command=self.logs_text.xview)
        self.logs_text.configure(yscrollcommand=log_scrollbar_v.set, xscrollcommand=log_scrollbar_h.set)
        
        log_scrollbar_v.pack(side="right", fill="y")
        log_scrollbar_h.pack(side="bottom", fill="x")
        self.logs_text.pack(fill="both", expand=True)
        
        self.load_logs()
    
    def load_config(self):
        """Load configuration into GUI elements."""
        self.fast_scan_var.set(config.get("fast_scan", False))
        self.max_file_size_var.set(str(config.get("max_file_size", 100 * 1024 * 1024) // (1024 * 1024)))
        self.scan_depth_var.set(str(config.get("scan_depth", 3)))
        self.vt_api_key_var.set(config.get("virustotal_api_key", ""))
        self.rate_limit_var.set(str(config.get("api_rate_limit", 4)))
        self.log_location_var.set(config.get("log_location", LOG_FILE))
        self.scan_interval_var.set(str(config.get("scan_interval", 300)))
        
        # Load excluded directories
        self.excluded_dirs_text.delete("1.0", tk.END)
        self.excluded_dirs_text.insert("1.0", "\n".join(config.get("excluded_dirs", [])))
    
    def save_config(self):
        """Save configuration from GUI elements."""
        try:
            # Update config dictionary
            config["fast_scan"] = self.fast_scan_var.get()
            config["max_file_size"] = int(self.max_file_size_var.get()) * 1024 * 1024
            config["scan_depth"] = int(self.scan_depth_var.get())
            config["virustotal_api_key"] = self.vt_api_key_var.get().strip()
            config["api_rate_limit"] = int(self.rate_limit_var.get())
            config["log_location"] = self.log_location_var.get()
            config["scan_interval"] = int(self.scan_interval_var.get())
            
            # Save excluded directories
            excluded_text = self.excluded_dirs_text.get("1.0", tk.END)
            config["excluded_dirs"] = [line.strip() for line in excluded_text.splitlines() if line.strip()]
            
            # Save to file
            self.scanner.save_config()
            
            # Update scanner's rate limiter
            self.scanner.vt_rate_limiter = RateLimiter(config["api_rate_limit"], 60)
            
            messagebox.showinfo("Configuration", "Configuration saved successfully!")
            
        except ValueError as e:
            messagebox.showerror("Configuration Error", f"Invalid numeric value: {e}")
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to save configuration: {e}")
    
    def reset_config(self):
        """Reset configuration to defaults."""
        if messagebox.askyesno("Reset Configuration", "Reset all settings to defaults?"):
            global config
            config = {
                "remote_logging": False,
                "log_location": LOG_FILE,
                "scan_interval": 300,
                "virustotal_api_key": "",
                "email_settings": {},
                "discord_webhook": "",
                "fast_scan": False,
                "scan_depth": 3,
                "max_file_size": 100 * 1024 * 1024,
                "api_rate_limit": 4,
                "excluded_dirs": [
                    "C:\\Windows\\WinSxS",
                    "C:\\Windows\\Temp",
                    "C:\\System Volume Information",
                    "C:\\$Recycle.Bin",
                    "C:\\ProgramData\\Microsoft\\Crypto",
                    "C:\\hiberfil.sys",
                    "C:\\pagefile.sys",
                    "C:\\swapfile.sys"
                ]
            }
            self.load_config()
            self.scanner.save_config()
            messagebox.showinfo("Configuration", "Configuration reset to defaults!")
    
    def select_log_location(self):
        """Select log file location."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Select Log File Location"
        )
        if file_path:
            self.log_location_var.set(file_path)
    
    def load_logs(self):
        """Load logs into the text widget."""
        try:
            log_file = config.get("log_location", LOG_FILE)
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.logs_text.delete(1.0, tk.END)
                    self.logs_text.insert(tk.END, content)
                    self.logs_text.see(tk.END)
            else:
                self.logs_text.delete(1.0, tk.END)
                self.logs_text.insert(tk.END, "No log file found.")
        except Exception as e:
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, f"Error loading logs: {str(e)}")
    
    def clear_logs(self):
        """Clear the log file."""
        if messagebox.askyesno("Clear Logs", "Clear all log entries?"):
            try:
                log_file = config.get("log_location", LOG_FILE)
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write("")
                self.logs_text.delete(1.0, tk.END)
                self.scanner.log("Log file cleared by user")
                messagebox.showinfo("Logs", "Logs cleared successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {e}")
    
    def export_logs(self):
        """Export logs to a file."""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Logs"
            )
            if file_path:
                content = self.logs_text.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Export", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")
    
    def run_quick_scan(self):
        """Run a quick scan (fast mode enabled)."""
        # Temporarily enable fast scan
        original_fast_scan = config.get("fast_scan", False)
        config["fast_scan"] = True
        
        try:
            self.run_full_scan()
        finally:
            # Restore original setting
            config["fast_scan"] = original_fast_scan
    
    def run_full_scan(self):
        """Run a full system scan."""
        if self.scan_in_progress:
            messagebox.showinfo("Scan", "A scan is already in progress")
            return
            
        # Check for admin rights
        if not is_admin():
            result = messagebox.askyesno(
                "Administrator Privileges Required", 
                "Full system scan requires administrator privileges for deep file access.\n\n"
                "Would you like to restart the application as administrator?\n\n"
                "(Select 'No' to continue with limited scanning capabilities)"
            )
            if result:
                try:
                    if platform.system() == 'Windows':
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                    self.destroy()
                    return
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to restart as administrator: {e}")
            
        self.start_scan()
    
    def start_scan(self):
        """Start the scanning process."""
        global scan_queue
        
        self.scan_in_progress = True
        
        # Update button states
        self.scan_button.config(state=tk.DISABLED)
        self.quick_scan_button.config(state=tk.DISABLED)
        self.cancel_scan_button.config(state=tk.NORMAL)
        self.monitor_start_button.config(state=tk.DISABLED)
        
        # Reset progress indicators
        self.progress_label.config(text="Preparing scan...")
        self.progress_var.set(0)
        self.task_label.config(text="")
        self.file_status.config(text="")
        
        # Clear previous results
        self.clear_results()
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        self.scan_thread.start()
        
        # Start progress monitoring
        self.check_scan_progress()
    
    def _perform_scan(self):
        """Perform the actual scan in a separate thread."""
        global scan_queue
        try:
            results = self.scanner.full_scan()
            scan_queue.put(("complete", results))
        except Exception as e:
            logger.exception("Scan failed")
            scan_queue.put(("error", str(e)))
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if self.scan_in_progress:
            self.scanner.cancel_scan()
            self.cancel_scan_button.config(state=tk.DISABLED)
            self.progress_label.config(text="Cancelling scan...")
    
    def check_scan_progress(self):
        """Check scan progress and update GUI."""
        try:
            while not scan_queue.empty():
                msg_type, data = scan_queue.get_nowait()
                
                if msg_type == "progress":
                    current_step, total_steps, task_name = data
                    progress = (current_step / total_steps) * 100
                    self.progress_var.set(progress)
                    self.progress_label.config(text=f"Progress: {int(progress)}%")
                    self.task_label.config(text=f"Current Task: {task_name}")
                    
                elif msg_type == "file_progress":
                    scanned, malicious = data
                    self.file_status.config(text=f"Files scanned: {scanned:,} | Malicious found: {malicious}")
                    
                elif msg_type == "progress_update":
                    self.file_status.config(text=data)
                    
                elif msg_type == "complete":
                    self.scan_completed(data)
                    return
                    
                elif msg_type == "error":
                    self.scan_error(data)
                    return
                    
        except queue.Empty:
            pass
        
        # Continue checking if scan is still in progress
        if self.scan_in_progress:
            self.after(100, self.check_scan_progress)
    
    def scan_completed(self, results):
        """Handle scan completion."""
        self.scan_in_progress = False
        
        # Update button states
        self.scan_button.config(state=tk.NORMAL)
        self.quick_scan_button.config(state=tk.NORMAL)
        self.cancel_scan_button.config(state=tk.DISABLED)
        self.monitor_start_button.config(state=tk.NORMAL)
        
        # Update progress
        self.progress_label.config(text="Scan completed")
        self.progress_var.set(100)
        self.task_label.config(text="")
        
        # Update results
        self.update_scan_results(results)
        self.update_dashboard()
        
        # Show completion message
        threat_count = len(results)
        if threat_count > 0:
            messagebox.showwarning("Scan Complete", f"Scan completed with {threat_count} potential threats detected!")
        else:
            messagebox.showinfo("Scan Complete", "Scan completed successfully. No threats detected.")
    
    def scan_error(self, error_msg):
        """Handle scan error."""
        self.scan_in_progress = False
        
        # Update button states
        self.scan_button.config(state=tk.NORMAL)
        self.quick_scan_button.config(state=tk.NORMAL)
        self.cancel_scan_button.config(state=tk.DISABLED)
        self.monitor_start_button.config(state=tk.NORMAL)
        
        # Update progress
        self.progress_label.config(text=f"Scan failed: {error_msg}")
        self.progress_var.set(0)
        self.task_label.config(text="")
        self.file_status.config(text="")
        
        messagebox.showerror("Scan Error", f"Scan failed:\n{error_msg}")
    
    def start_monitoring(self):
        """Start background monitoring."""
        global monitoring_active
        
        if monitoring_active:
            return
        
        monitoring_active = True
        self.monitor_start_button.config(state=tk.DISABLED)
        self.monitor_stop_button.config(state=tk.NORMAL)
        
        self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.scanner.log("Background monitoring started")
        messagebox.showinfo("Monitoring", "Background monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        global monitoring_active
        
        monitoring_active = False
        self.monitor_start_button.config(state=tk.NORMAL)
        self.monitor_stop_button.config(state=tk.DISABLED)
        
        self.scanner.log("Background monitoring stopped")
        messagebox.showinfo("Monitoring", "Background monitoring stopped")
    
    def monitoring_loop(self):
        """Background monitoring loop."""
        global monitoring_active
        
        while monitoring_active:
            try:
                # Wait for the specified interval
                for _ in range(config.get("scan_interval", 300)):
                    if not monitoring_active:
                        return
                    time.sleep(1)
                
                # Run a quick scan during monitoring
                if monitoring_active and not self.scan_in_progress:
                    self.scanner.log("Running scheduled background scan")
                    
                    # Temporarily enable fast scan for monitoring
                    original_fast_scan = config.get("fast_scan", False)
                    config["fast_scan"] = True
                    
                    try:
                        results = self.scanner.full_scan()
                        if results:
                            self.scanner.log(f"Background scan detected {len(results)} potential threats")
                            # Update GUI in main thread
                            self.after(0, lambda: self.update_scan_results(results))
                    finally:
                        config["fast_scan"] = original_fast_scan
                        
            except Exception as e:
                self.scanner.log(f"Monitoring error: {e}", level="ERROR")
                logger.exception("Monitoring loop error")
    
    def update_databases(self):
        """Update threat databases."""
        def update_thread():
            try:
                self.scanner.log("Updating threat databases...")
                self.scanner.update_threat_database()
                self.scanner.update_malware_hashes()
                self.after(0, lambda: messagebox.showinfo("Update", "Threat databases updated successfully!"))
            except Exception as e:
                self.scanner.log(f"Database update failed: {e}", level="ERROR")
                self.after(0, lambda: messagebox.showerror("Update Error", f"Failed to update databases: {e}"))
        
        threading.Thread(target=update_thread, daemon=True).start()
    
    def update_scan_results(self, results=None):
        """Update the scan results display."""
        global scan_results
        
        if results is not None:
            scan_results = results
        
        # Clear previous results
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)
        
        # Add new results with color coding
        for result_type, details in scan_results:
            item = self.scan_results.insert("", "end", values=(result_type, details))
            
            # Color code based on threat type
            if "Malicious" in result_type:
                self.scan_results.set(item, "Type", result_type)
                # Note: Treeview styling would need additional configuration
    
    def clear_results(self):
        """Clear scan results."""
        global scan_results
        scan_results = []
        for item in self.scan_results.get_children():
            self.scan_results.delete(item)
    
    def export_results(self):
        """Export scan results to a file."""
        if not scan_results:
            messagebox.showinfo("Export", "No results to export.")
            return
        
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Scan Results"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    if file_path.lower().endswith('.csv'):
                        import csv
                        writer = csv.writer(f)
                        writer.writerow(["Threat Type", "Details"])
                        writer.writerows(scan_results)
                    else:
                        f.write("Scan Results Export\n")
                        f.write("=" * 50 + "\n")
                        f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Threats: {len(scan_results)}\n\n")
                        
                        for result_type, details in scan_results:
                            f.write(f"Type: {result_type}\n")
                            f.write(f"Details: {details}\n")
                            f.write("-" * 50 + "\n")
                
                messagebox.showinfo("Export", f"Results exported to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")
    
    def update_dashboard(self):
        """Update the dashboard display."""
        # Process log entries for GUI
        try:
            while not log_queue.empty():
                log_entry = log_queue.get_nowait()
                self.logs_text.insert(tk.END, log_entry + "\n")
                self.logs_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Update status text
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        
        # System information
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network interfaces
            net_if = psutil.net_if_addrs()
            active_connections = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
            
        except Exception as e:
            logger.exception("Error getting system information")
            cpu_percent = "N/A"
            memory = None
            disk = None
            active_connections = "N/A"
        
        status_lines = [
            "SECURITY SCANNER DASHBOARD",
            "=" * 50,
            "",
            "SCAN STATUS:",
            f"  Last Scan: {last_scan_time or 'Never'}",
            f"  Threats Detected: {len(scan_results)}",
            f"  Files Scanned: {self.scanner.scanned_files:,}",
            f"  Malicious Files Found: {self.scanner.malicious_files}",
            f"  Monitoring: {'Active' if monitoring_active else 'Inactive'}",
            "",
            "CONFIGURATION:",
            f"  Fast Scan Mode: {'Enabled' if config.get('fast_scan', False) else 'Disabled'}",
            f"  VirusTotal API: {'Configured' if config.get('virustotal_api_key') else 'Not configured'}",
            f"  Log Location: {config.get('log_location', 'N/A')}",
            f"  Scan Interval: {config.get('scan_interval', 300)} seconds",
            "",
            "SYSTEM INFORMATION:",
            f"  OS: {platform.platform()}",
            f"  Python: {platform.python_version()}",
            f"  Admin Privileges: {'Yes' if is_admin() else 'No'}",
            "",
            "SYSTEM RESOURCES:",
            f"  CPU Usage: {cpu_percent}%",
            f"  Memory Usage: {memory.percent if memory else 'N/A'}%",
            f"  Memory Available: {memory.available // (1024**3) if memory else 'N/A'} GB",
            f"  Disk Usage: {disk.percent if disk else 'N/A'}%",
            f"  Disk Free: {disk.free // (1024**3) if disk else 'N/A'} GB",
            "",
            "NETWORK:",
            f"  Active Connections: {active_connections}",
            f"  Network Interfaces: {len(net_if) if net_if else 'N/A'}",
            "",
            "THREAT DATABASE STATUS:",
            f"  Known Malware Hashes: {len(self.scanner.known_hashes):,}",
            f"  Known Processes: {len(self.scanner.known_processes):,}",
            f"  Startup Items: {len(self.scanner.startup_items):,}",
        ]
        
        # Add recent threats if any
        if scan_results:
            status_lines.extend([
                "",
                "RECENT THREATS:",
                "-" * 30
            ])
            
            # Show last 5 threats
            for result_type, details in scan_results[-5:]:
                status_lines.append(f"  {result_type}: {details[:80]}{'...' if len(details) > 80 else ''}")
        
        self.status_text.insert(tk.END, "\n".join(status_lines))
        self.status_text.config(state=tk.DISABLED)
        
        # Schedule next update
        self.after(2000, self.update_dashboard)  # Update every 2 seconds
    
    def on_close(self):
        """Handle application closing."""
        try:
            # Stop monitoring
            if monitoring_active:
                self.stop_monitoring()
            
            # Cancel any running scan
            if self.scan_in_progress:
                self.scanner.cancel_scan()
                # Wait briefly for scan to cancel
                for _ in range(10):
                    if not self.scan_in_progress:
                        break
                    time.sleep(0.1)
            
            # Save configuration
            self.save_config()
            
            self.scanner.log("Security Scanner application closing")
            
        except Exception as e:
            logger.exception("Error during application shutdown")
        finally:
            self.destroy()


def main():
    """Main application entry point."""
    try:
        # Check if running on Windows for admin check
        if platform.system() == 'Windows' and not is_admin():
            result = messagebox.askyesno(
                "Administrator Privileges", 
                "This application works best with administrator privileges for deep system scanning.\n\n"
                "Would you like to restart as administrator?\n\n"
                "(You can continue without admin rights, but some features will be limited)"
            )
            
            if result:
                try:
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                    sys.exit(0)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to restart as administrator: {e}")
        
        # Create and run the application
        app = SecurityDashboard()
        
        # Configure logging level based on config
        log_level = config.get("log_level", "INFO")
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        logger.info("Security Scanner application started")
        app.mainloop()
        
    except Exception as e:
        logger.exception("Fatal error in main application")
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()