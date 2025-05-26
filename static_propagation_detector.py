"""
Static Hash-Based Propagation Detector

This module implements a static approach to detecting malware propagation:
1. When encryption is detected, store hashes of suspicious files
2. Continuously monitor propagation folders for files matching these hashes
3. Automatically delete files that match suspicious hashes
4. No network process monitoring - purely file-based detection
"""

import os
import time
import threading
import subprocess
import logging
import hashlib
import socket
from pathlib import Path
import concurrent.futures

# Set up a dedicated logger for propagation detection
propagation_logger = logging.getLogger('propagation_detector')
propagation_logger.setLevel(logging.INFO)
handler = logging.FileHandler('propagation_detector.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
if not propagation_logger.hasHandlers():
    propagation_logger.addHandler(handler)

# Global dictionary to store suspicious file hashes
# Format: {hash: {'file_type': 'exe'|'dll', 'original_path': str, 'detected_time': timestamp}}
suspicious_hashes = {}

class StaticPropagationDetector:
    def __init__(self, suspicious_processes, sysinternals_dir):
        self.suspicious_processes = suspicious_processes
        self.sysinternals_dir = sysinternals_dir
        self.propagation_folders = []
        self.last_hash_update = 0
        self.last_folder_discovery = 0
        self.is_running = False
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            propagation_logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def add_suspicious_hash(self, file_path, file_type):
        """Add a file hash to the suspicious hashes dictionary"""
        file_hash = self.calculate_file_hash(file_path)
        if file_hash:
            suspicious_hashes[file_hash] = {
                'file_type': file_type,
                'original_path': file_path,
                'detected_time': time.time()
            }
            propagation_logger.critical(f"Added suspicious {file_type} hash: {file_hash} from {file_path}")
            return file_hash
        return None
    
    def update_suspicious_hashes(self):
        """Update suspicious hashes from tracked processes"""
        try:
            current_time = time.time()
            new_hashes_added = False
            
            for pid, info in self.suspicious_processes.items():
                # Add executable hash
                exe_path = info['exe_path']
                if os.path.exists(exe_path):
                    exe_hash = self.calculate_file_hash(exe_path)
                    if exe_hash and exe_hash not in suspicious_hashes:
                        self.add_suspicious_hash(exe_path, 'exe')
                        new_hashes_added = True
                
                # Add suspicious DLL hashes
                for dll_info in info['suspicious_dlls']:
                    dll_path = dll_info['dll_path']
                    if os.path.exists(dll_path):
                        dll_hash = self.calculate_file_hash(dll_path)
                        if dll_hash and dll_hash not in suspicious_hashes:
                            self.add_suspicious_hash(dll_path, 'dll')
                            new_hashes_added = True
            
            if new_hashes_added:
                propagation_logger.info(f"Updated suspicious hashes. Total: {len(suspicious_hashes)} hashes")
            
            self.last_hash_update = current_time
            
        except Exception as e:
            propagation_logger.error(f"Error updating suspicious hashes: {e}")
    
    def discover_propagation_folders(self):
        """Discover potential propagation folders (network shares, USB drives, etc.)"""
        import ipaddress
        
        propagation_folders = []
        
        try:
            # 1. Find network shares
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            
            def check_host_shares(ip):
                host_shares = []
                try:
                    # Check if SMB port is open
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((str(ip), 445))
                    sock.close()
                    
                    if result == 0:
                        # Enumerate shares using net view
                        cmd = f"net view \\\\{ip}"
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                        
                        if result.returncode == 0:
                            lines = result.stdout.splitlines()
                            for line in lines:
                                if line.strip() and not line.startswith('Share name') and not line.startswith('-'):
                                    parts = line.split()
                                    if parts and not parts[0].endswith('$'):
                                        share_path = f"\\\\{ip}\\{parts[0]}"
                                        if os.path.exists(share_path):
                                            host_shares.append(share_path)
                
                except Exception:
                    pass  # Ignore individual host errors
                
                return host_shares
            
            propagation_logger.info(f"Scanning network {network} for SMB shares...")
            
            # Use threading to scan network faster
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_host_shares, ip) for ip in list(network.hosts())[:50]]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        host_shares = future.result()
                        propagation_folders.extend(host_shares)
                    except:
                        pass
            
            # 2. Find USB/removable drives
            try:
                import win32file
                drives = win32file.GetLogicalDrives()
                drive_letters = []
                for i in range(26):
                    if drives & (1 << i):
                        drive_letter = chr(ord('A') + i) + ":\\"
                        drive_letters.append(drive_letter)
                
                for drive in drive_letters:
                    try:
                        drive_type = win32file.GetDriveType(drive)
                        # Check for removable drives (USB, etc.) - type 2
                        if drive_type == 2 and os.path.exists(drive):
                            propagation_folders.append(drive)
                            propagation_logger.info(f"Found removable drive: {drive}")
                    except:
                        pass
            except ImportError:
                # Fallback method without win32file
                for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        propagation_folders.append(drive)
            
            # 3. Common shared folders
            common_shares = [
                "C:\\Users\\Public",
                "C:\\Users\\Public\\Documents",
                "C:\\Users\\Public\\Downloads"
            ]
            
            for share in common_shares:
                if os.path.exists(share) and os.access(share, os.W_OK):
                    propagation_folders.append(share)
            
            # propagation_logger.info(f"Found {len(propagation_folders)} propagation folders: {propagation_folders}")
            self.propagation_folders = propagation_folders
            self.last_folder_discovery = time.time()
            return propagation_folders
            
        except Exception as e:
            propagation_logger.error(f"Error discovering propagation folders: {e}")
            return []
    
    def scan_folder_for_suspicious_hashes(self, folder_path):
        """Scan a folder for files matching suspicious hashes"""
        try:
            if not os.path.exists(folder_path) or not suspicious_hashes:
                return []
            
            found_malware = []
            
            # Recursively scan folder
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Skip if file is too large (> 100MB) for performance
                        if os.path.getsize(file_path) > 100 * 1024 * 1024:
                            continue
                        
                        # Skip system files and directories
                        if any(sys_path in file_path.lower() for sys_path in ['windows', 'system32', 'syswow64']):
                            continue
                        
                        # Calculate file hash
                        file_hash = self.calculate_file_hash(file_path)
                        if file_hash and file_hash in suspicious_hashes:
                            hash_info = suspicious_hashes[file_hash]
                            found_malware.append({
                                'path': file_path,
                                'hash': file_hash,
                                'type': hash_info['file_type'],
                                'original': hash_info['original_path']
                            })
                            propagation_logger.critical(f"Found suspicious {hash_info['file_type']} with matching hash in {folder_path}: {file_path}")
                    
                    except Exception as e:
                        # Continue with other files if one fails
                        propagation_logger.debug(f"Error checking file {file_path}: {e}")
                        continue
            
            return found_malware
            
        except Exception as e:
            propagation_logger.error(f"Error scanning folder {folder_path}: {e}")
            return []
    
    def delete_suspicious_files(self, malware_files):
        """Delete files that match suspicious hashes"""
        deleted_count = 0
        
        for malware_info in malware_files:
            try:
                file_path = malware_info['path']
                
                # Try to delete the file
                os.remove(file_path)
                deleted_count += 1
                propagation_logger.critical(f"Deleted suspicious {malware_info['type']} file: {file_path} (hash: {malware_info['hash'][:16]}...)")
                
                # Also look for and delete related files
                base_dir = os.path.dirname(file_path)
                base_name = os.path.splitext(os.path.basename(file_path))[0]
                
                # Delete autorun.inf if it exists
                autorun_path = os.path.join(base_dir, "autorun.inf")
                if os.path.exists(autorun_path):
                    try:
                        os.remove(autorun_path)
                        propagation_logger.critical(f"Deleted associated autorun.inf: {autorun_path}")
                        deleted_count += 1
                    except:
                        pass
                
            except Exception as e:
                propagation_logger.error(f"Failed to delete {malware_info['path']}: {e}")
        
        return deleted_count
    
    def monitor_propagation_folders(self):
        """Monitor propagation folders for suspicious files using static hash detection"""
        propagation_logger.info("Starting static hash-based propagation monitoring")
        self.is_running = True
        
        while self.is_running:
            try:
                current_time = time.time()
                
                # Update suspicious hashes if needed
                if current_time - self.last_hash_update > 30:  # Update every 30 seconds
                    self.update_suspicious_hashes()
                
                # Discover propagation folders periodically
                if not self.propagation_folders or current_time - self.last_folder_discovery > 300:  # Re-discover every 5 minutes
                    self.discover_propagation_folders()
                
                if suspicious_hashes and self.propagation_folders:
                    total_deleted = 0
                    
                    # Scan each propagation folder
                    for folder in self.propagation_folders:
                        try:
                            # Test folder access first
                            if not os.access(folder, os.R_OK):
                                continue
                            
                            propagation_logger.debug(f"Scanning propagation folder: {folder}")
                            malware_files = self.scan_folder_for_suspicious_hashes(folder)
                            
                            if malware_files:
                                deleted_count = self.delete_suspicious_files(malware_files)
                                total_deleted += deleted_count
                                propagation_logger.critical(f"Cleaned {deleted_count} malware files from {folder}")
                        
                        except Exception as folder_error:
                            propagation_logger.debug(f"Error accessing folder {folder}: {folder_error}")
                            continue
                    
                    if total_deleted > 0:
                        propagation_logger.critical(f"Total malware files deleted this scan: {total_deleted}")
                
                # Sleep before next scan
                time.sleep(10)  # Scan every 10 seconds for faster detection
                
            except Exception as e:
                propagation_logger.error(f"Error in propagation monitoring: {e}")
                time.sleep(30)  # Wait longer on error
    
    def start_monitoring(self):
        """Start static propagation monitoring"""
        propagation_logger.info("Starting static propagation detector")
        
        # Start monitoring in a separate thread
        monitor_thread = threading.Thread(target=self.monitor_propagation_folders, daemon=True)
        monitor_thread.start()
        
        return monitor_thread
    
    def stop_monitoring(self):
        """Stop static propagation monitoring"""
        propagation_logger.info("Stopping static propagation detector")
        self.is_running = False

def start_static_propagation_detector(suspicious_processes, sysinternals_dir):
    """Helper function to start static propagation detection"""
    detector = StaticPropagationDetector(suspicious_processes, sysinternals_dir)
    return detector.start_monitoring()

def add_suspicious_file_hash(file_path, file_type):
    """Global function to add a suspicious file hash from main detector"""
    try:
        file_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                file_hash.update(chunk)
        
        hash_value = file_hash.hexdigest()
        suspicious_hashes[hash_value] = {
            'file_type': file_type,
            'original_path': file_path,
            'detected_time': time.time()
        }
        propagation_logger.critical(f"Added suspicious {file_type} hash: {hash_value} from {file_path}")
        return hash_value
    except Exception as e:
        propagation_logger.error(f"Error adding suspicious hash for {file_path}: {e}")
        return None

def get_suspicious_hashes():
    """Get the current suspicious hashes dictionary"""
    return suspicious_hashes.copy()

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('static_propagation_detector')


class ImproveStaticPropagationDetector(StaticPropagationDetector):
    def __init__(self, suspicious_processes, sysinternals_dir, suspicious_hashes):
        super().__init__(suspicious_processes, sysinternals_dir)
        self.propagation_folders = self.discover_propagation_folders()
        self.suspicious_hashes = suspicious_hashes

    def discover_network_hosts(self):
        """Discover hosts in the local network"""
        import ipaddress
        import concurrent.futures
        
        # Get local IP and subnet
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        logger.info(f"Local IP: {local_ip}")
        
        # Generate IP range for local network (assuming /24)
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        hosts = []
        
        def check_host(ip):
            try:
                # Try to connect to SMB port (445)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), 445))
                sock.close()
                if result == 0:
                    return str(ip)
            except:
                pass
            return None
        
        logger.info(f"Scanning network {network} for SMB hosts...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_host, ip) for ip in network.hosts()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    hosts.append(result)
                    logger.info(f"Found SMB host: {result}")
        
        return hosts
    
    def enumerate_shares(self, host):
        """Enumerate SMB shares on a host using net view"""
        try:
            cmd = f"net view \\\\{host}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            shares = []
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    if line.strip() and not line.startswith('Share name') and not line.startswith('-'):
                        parts = line.split()
                        if parts and not parts[0].endswith('$'):  # Skip admin shares
                            share_name = parts[0]
                            share_path = f"\\\\{host}\\{share_name}"
                            shares.append(share_path)
                            logger.info(f"Found share: {share_path}")
            
            return shares
        except Exception as e:
            logger.error(f"Error enumerating shares on {host}: {e}")
            return []
    
    def test_write_access(self, share_path):
        """Test if we have write access to a share"""
        try:
            test_file = os.path.join(share_path, "test_write_access.tmp")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            return True
        except:
            return False
        
    def propagate_to_share(self, share_path):
        """Detect if share path contains suspicious files from hashes and delete them"""
        try:
            if not self.test_write_access(share_path):
                logger.warning(f"No write access to share {share_path}")
                return False
            
            # Walk through the share
            for root, dirs, files in os.walk(share_path):
                for file in files:
                    logger.debug(f"Checking file: {file} in {root}")
                    file_path = os.path.join(root, file)
                    try:
                        # Skip if file is too large (> 100MB) for performance
                        if os.path.getsize(file_path) > 100 * 1024 * 1024:
                            continue
                        
                        # Calculate file hash
                        file_hash = self.calculate_file_hash(file_path)
                        logger.debug(f"Calculated hash for {file_path}: {file_hash}")
                        logger.debug(f"Checking against suspicious hashes: {self.suspicious_hashes}")
                        # DEBUG - Checking against suspicious hashes: dict_keys(['C:\\Users\\JakeClark\\Downloads\\unikey46RC2-230919-win64\\UniKeyNT.exe', 'C:\\Users\\JakeClark\\Downloads\\unikey46RC2-230919-win64\\USERENV.dll'])
                        # Check if file hash matches any suspicious hashes
                        for suspicious_hash_path, info in self.suspicious_hashes.items():
                            suspicious_hash_path_hash = self.calculate_file_hash(suspicious_hash_path)
                            if file_hash and file_hash == suspicious_hash_path_hash:
                                os.remove(file_path)
                                logger.critical(f"Deleted suspicious file: {file_path} (hash: {file_hash[:16]}...)")
                    
                    except Exception as e:
                        logger.error(f"Error processing file {file_path}: {e}")

            return True
        
        except Exception as e:
            logger.error(f"Error propagating to share {share_path}: {e}")
            return False
        
    def start_propagation(self):
        """Start the propagation process"""
        logger.info("Starting SMB propagation...")
        
        # Discover network hosts
        hosts = self.discover_network_hosts()
        
        if not hosts:
            logger.warning("No SMB hosts found on network")
            return
        
        # Enumerate shares on each host
        all_shares = []
        for host in hosts:
            shares = self.enumerate_shares(host)
            all_shares.extend(shares)
        
        logger.info(f"Found {len(all_shares)} total shares")
        
        # Attempt to propagate to each writable share
        successful_propagations = 0
        for share in all_shares:
            if self.propagate_to_share(share):
                successful_propagations += 1
                time.sleep(1)  # Small delay between propagations
        
        logger.info(f"Successfully propagated to {successful_propagations}/{len(all_shares)} shares")

def start_improved_static_propagation_detector(suspicious_processes, sysinternals_dir, suspicious_hashes):
    """Helper function to start improved static propagation detection"""
    detector = ImproveStaticPropagationDetector(suspicious_processes, sysinternals_dir, suspicious_hashes)
    return detector.start_propagation()