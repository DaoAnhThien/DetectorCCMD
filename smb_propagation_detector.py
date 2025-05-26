import os
import time
import threading
import subprocess
import logging
import psutil
import socket
import winreg
from pathlib import Path
import concurrent.futures

# Set up a dedicated logger for SMB propagation detection
smb_logger = logging.getLogger('smb_propagation_detector')
smb_logger.setLevel(logging.INFO)
handler = logging.FileHandler('smb_propagation_detector.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
if not smb_logger.hasHandlers():
    smb_logger.addHandler(handler)

class SMBPropagationDetector:
    def __init__(self, suspicious_processes, sysinternals_dir):
        self.suspicious_processes = suspicious_processes
        self.sysinternals_dir = sysinternals_dir
        self.monitored_pids = set()
        self.blocked_processes = set()
        self.netstat_path = self._find_netstat()
        
    def _find_netstat(self):
        """Find netstat executable"""
        # netstat is usually in System32
        netstat_path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'netstat.exe')
        if os.path.exists(netstat_path):
            return netstat_path
        return 'netstat'  # Fallback to PATH
    
    def get_smb_connections(self, pid):
        """Get SMB connections for a specific process"""
        try:
            # Use netstat to find connections on SMB ports (445, 139)
            result = subprocess.run([
                self.netstat_path, '-ano'
            ], capture_output=True, text=True, shell=True)
            
            connections = []
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    if str(pid) in line and (':445' in line or ':139' in line):
                        parts = line.split()
                        if len(parts) >= 5:
                            protocol = parts[0]
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            state = parts[3]
                            process_id = parts[4]
                            
                            if process_id == str(pid):
                                connections.append({
                                    'protocol': protocol,
                                    'local': local_addr,
                                    'remote': remote_addr,
                                    'state': state
                                })
            
            return connections
        except Exception as e:
            smb_logger.error(f"Error getting SMB connections for PID {pid}: {e}")
            return []
    
    def block_process_network_access(self, pid):
        """Block network access for a process using Windows Firewall"""
        try:
            # Get process executable path
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            
            # Create firewall rule to block the executable
            rule_name = f"Block_Malware_PID_{pid}"
            
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=out',
                'action=block',
                f'program={exe_path}',
                'protocol=any'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                smb_logger.critical(f"Blocked network access for PID {pid} ({exe_path})")
                self.blocked_processes.add(pid)
                return True
            else:
                smb_logger.error(f"Failed to block network access for PID {pid}: {result.stderr}")
                return False
                
        except Exception as e:
            smb_logger.error(f"Error blocking network access for PID {pid}: {e}")
            return False
    
    def discover_network_shares(self):
        """Discover writable network shares"""
        import ipaddress
        
        try:
            # Get local IP and network
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            
            shares = []
            
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
                                        host_shares.append(share_path)
                
                except Exception as e:
                    pass  # Ignore individual host errors
                
                return host_shares
            
            smb_logger.info(f"Scanning network {network} for SMB shares...")
            
            # Use threading to scan network faster
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_host_shares, ip) for ip in list(network.hosts())[:50]]  # Limit to first 50 IPs
                for future in concurrent.futures.as_completed(futures):
                    try:
                        host_shares = future.result()
                        shares.extend(host_shares)
                    except:
                        pass
            
            smb_logger.info(f"Found {len(shares)} network shares")
            return shares
            
        except Exception as e:
            smb_logger.error(f"Error discovering network shares: {e}")
            return []
    
    def check_share_for_malware(self, share_path, suspicious_exe_names, suspicious_dll_names):
        """Check if a network share contains suspicious files"""
        try:
            # Test if we can access the share
            if not os.path.exists(share_path):
                return False
            
            found_malware = False
            malware_files = []
            
            # Look for suspicious executables and DLLs
            try:
                for item in os.listdir(share_path):
                    item_path = os.path.join(share_path, item)
                    if os.path.isfile(item_path):
                        item_lower = item.lower()
                        
                        # Check for suspicious executables
                        for exe_name in suspicious_exe_names:
                            if exe_name.lower() in item_lower and item_lower.endswith('.exe'):
                                malware_files.append(item_path)
                                found_malware = True
                                smb_logger.critical(f"Found suspicious executable in share: {item_path}")
                        
                        # Check for suspicious DLLs
                        for dll_name in suspicious_dll_names:
                            if dll_name.lower() in item_lower and item_lower.endswith('.dll'):
                                malware_files.append(item_path)
                                found_malware = True
                                smb_logger.critical(f"Found suspicious DLL in share: {item_path}")
                        
                        # Check for autorun.inf
                        if item_lower == 'autorun.inf':
                            malware_files.append(item_path)
                            found_malware = True
                            smb_logger.critical(f"Found autorun.inf in share: {item_path}")
            
            except PermissionError:
                smb_logger.warning(f"No access to list contents of {share_path}")
                return False
            
            # Attempt to delete malware files
            if found_malware:
                deleted_files = []
                for malware_file in malware_files:
                    try:
                        os.remove(malware_file)
                        deleted_files.append(malware_file)
                        smb_logger.critical(f"Deleted malware file from share: {malware_file}")
                    except Exception as delete_error:
                        smb_logger.error(f"Failed to delete {malware_file}: {delete_error}")
                
                if deleted_files:
                    smb_logger.critical(f"Successfully cleaned {len(deleted_files)} malware files from {share_path}")
            
            return found_malware
            
        except Exception as e:
            smb_logger.error(f"Error checking share {share_path} for malware: {e}")
            return False
    
    def monitor_process_smb_activity(self, pid, exe_path):
        """Monitor a specific process for SMB activity"""
        smb_logger.info(f"Starting SMB monitoring for PID {pid} ({exe_path})")
        
        try:
            while True:
                # Check if process still exists
                try:
                    proc = psutil.Process(pid)
                    if not proc.is_running():
                        break
                except psutil.NoSuchProcess:
                    break
                
                # Get SMB connections
                smb_connections = self.get_smb_connections(pid)
                
                if smb_connections:
                    smb_logger.warning(f"SMB activity detected for PID {pid}:")
                    for conn in smb_connections:
                        smb_logger.warning(f"  {conn['protocol']} {conn['local']} -> {conn['remote']} ({conn['state']})")
                    
                    # Block the process if it's making SMB connections
                    if pid not in self.blocked_processes:
                        smb_logger.critical(f"Blocking SMB propagation attempt by PID {pid}")
                        self.block_process_network_access(pid)
                
                time.sleep(2)  # Check every 2 seconds
                
        except Exception as e:
            smb_logger.error(f"Error monitoring SMB activity for PID {pid}: {e}")
        finally:
            smb_logger.info(f"Stopped SMB monitoring for PID {pid}")
    
    def cleanup_network_shares(self):
        """Periodically scan and clean network shares"""
        smb_logger.info("Starting network share cleanup monitoring")
        
        while True:
            try:
                # Get suspicious file names from tracked processes
                suspicious_exe_names = set()
                suspicious_dll_names = set()
                
                for pid, info in self.suspicious_processes.items():
                    exe_name = os.path.basename(info['exe_path'])
                    suspicious_exe_names.add(exe_name)
                    
                    for dll_info in info['suspicious_dlls']:
                        dll_name = os.path.basename(dll_info['dll_path'])
                        suspicious_dll_names.add(dll_name)
                
                if suspicious_exe_names or suspicious_dll_names:
                    # Discover network shares
                    shares = self.discover_network_shares()
                    
                    # Check each share for malware
                    cleaned_shares = 0
                    for share in shares:
                        if self.check_share_for_malware(share, suspicious_exe_names, suspicious_dll_names):
                            cleaned_shares += 1
                    
                    if cleaned_shares > 0:
                        smb_logger.critical(f"Cleaned malware from {cleaned_shares} network shares")
                
                # Sleep for 5 minutes before next scan
                time.sleep(300)
                
            except Exception as e:
                smb_logger.error(f"Error in network share cleanup: {e}")
                time.sleep(60)  # Wait 1 minute on error
    
    def start_monitoring(self):
        """Start SMB propagation monitoring"""
        smb_logger.info("Starting SMB propagation detector")
        
        # Start network share cleanup in separate thread
        cleanup_thread = threading.Thread(target=self.cleanup_network_shares, daemon=True)
        cleanup_thread.start()
        
        # Monitor suspicious processes for SMB activity
        while True:
            try:
                # Check for new suspicious processes to monitor
                for pid, info in self.suspicious_processes.items():
                    if pid not in self.monitored_pids:
                        self.monitored_pids.add(pid)
                        
                        # Start monitoring this process in a separate thread
                        monitor_thread = threading.Thread(
                            target=self.monitor_process_smb_activity,
                            args=(pid, info['exe_path']),
                            daemon=True
                        )
                        monitor_thread.start()
                
                # Clean up monitoring for dead processes
                dead_pids = []
                for pid in self.monitored_pids:
                    try:
                        psutil.Process(pid)
                    except psutil.NoSuchProcess:
                        dead_pids.append(pid)
                
                for pid in dead_pids:
                    self.monitored_pids.discard(pid)
                    self.blocked_processes.discard(pid)
                
                time.sleep(5)  # Check for new processes every 5 seconds
                
            except Exception as e:
                smb_logger.error(f"Error in SMB monitoring loop: {e}")
                time.sleep(10)

def start_smb_propagation_detector(suspicious_processes, sysinternals_dir):
    """Helper function to start SMB propagation detection"""
    detector = SMBPropagationDetector(suspicious_processes, sysinternals_dir)
    detector.start_monitoring()
