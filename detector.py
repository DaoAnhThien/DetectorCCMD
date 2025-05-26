import os
import time
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import threading
import psutil
import win32api
import subprocess
import winreg
import subprocess
import winreg
import sys
import pandas as pd
import io
import hashlib
import tempfile
import shutil
import socket
import ipaddress
import concurrent.futures
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import importlib
file_encryption_detector = importlib.import_module('file-encryption-detector')
#smb_propagation_detector = importlib.import_module('smb_propagation_detector')
static_propagation_detector = importlib.import_module('static_propagation_detector')
# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

# Global dictionary to track suspicious processes
# Format: {pid: {'exe_path': str, 'suspicious_dlls': [{'dll_path': str, 'original_dll': str}]}}
suspicious_processes = {}

# Global dictionary to track suspicious file hashes
# Format: {'file_path': {'hash': 'sha256_hash', 'type': 'exe'|'dll'}}
suspicious_hashes = {}

class FolderCreationHandler(FileSystemEventHandler):
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir
        self.initial_folders = {f for f in os.listdir(watch_dir) if os.path.isdir(os.path.join(watch_dir, f))}

    def on_created(self, event):
        # Ignore file creation events, only handle directories
        if event.is_directory:
            folder_name = os.path.basename(event.src_path)
            logger.info(f"New folder detected: {folder_name}")
            # Wait briefly to ensure extraction completes
            time.sleep(2)  # Adjust delay if needed
            # Check for a subfolder with the same name and .exe files
            check_for_exe_files(event.src_path, folder_name)

def check_for_exe_files(folder_path, folder_name):
    """Check for a subfolder with the same name and .exe files, then analyze their DLL dependencies."""
    try:
        # Check for a subfolder with the same name with retries
        subfolder_path = os.path.join(folder_path, folder_name)
        retries = 3
        for attempt in range(retries):
            if os.path.isdir(subfolder_path):
                logger.info(f"Found subfolder with same name: {subfolder_path}")
                break
            else:
                logger.info(f"Attempt {attempt + 1}/{retries}: No subfolder named {folder_name} found in {folder_path}")
                if attempt < retries - 1:
                    time.sleep(1)  # Wait before retrying
        else:
            logger.warning(f"After {retries} attempts, no subfolder named {folder_name} found in {folder_path}")

        # Walk through the folder to find .exe files
        exe_found = False
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.lower().endswith('.exe'):
                    exe_found = True
                    exe_path = os.path.join(root, file)
                    logger.info(f"Found .exe file: {exe_path}")
                    # Analyze DLL dependencies for the .exe file
                    analyze_exe_dependencies(exe_path)

        if not exe_found:
            logger.info(f"No .exe files found in {folder_path}")
            logger.info(f"No .exe files found in {folder_path}")

    except Exception as e:
        logger.error(f"Error checking for .exe files in {folder_path}: {str(e)}")

def analyze_exe_dependencies(exe_path):
    """Analyze the DLL dependencies of an .exe file using pefile and check if each DLL is signed."""
    import subprocess
    try:
        pe = pefile.PE(exe_path)
        exe_dir = os.path.dirname(exe_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            logger.info(f"DLL dependencies for {exe_path}:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                dll_path = os.path.join(exe_dir, dll_name)
                signed_status = "Unknown (file not found)"
                if os.path.isfile(dll_path):
                    # Try to check signature using signtool
                    try:
                        result = subprocess.run([
                            'signtool', 'verify', '/pa', dll_path
                        ], capture_output=True, text=True, shell=True)
                        if 'Successfully verified' in result.stdout:
                            signed_status = "Signed"
                        elif 'No signature found' in result.stdout or 'not signed' in result.stdout:
                            signed_status = "Not signed"
                        else:
                            signed_status = "Unknown (see output)"
                    except Exception as sig_e:
                        signed_status = f"Signature check error: {sig_e}"
                logger.info(f"  - {dll_name} | Signed: {signed_status}")
        else:
            logger.info(f"No DLL dependencies found for {exe_path}.")
    except Exception as e:
        logger.error(f"Error analyzing {exe_path}: {str(e)}")

def get_dll_exports(dll_path):
    """Return a set of exported function names and their ordinals from a DLL using pefile."""
    try:
        pe = pefile.PE(dll_path)
        exports = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    # Include both name and ordinal for more precise comparison
                    exports.add((exp.name.decode('utf-8', errors='ignore'), exp.ordinal))
                else:
                    # Include unnamed exports by ordinal only
                    exports.add(('', exp.ordinal))
        return exports
    except Exception as e:
        logger.error(f"Error reading exports from {dll_path}: {e}")
        return set()

def get_dll_metadata(dll_path):
    """Return metadata (file size, version, creation time) for a DLL."""
    try:
        file_info = win32api.GetFileVersionInfo(dll_path, '\\')
        version = f"{file_info['FileVersionMS'] >> 16}.{file_info['FileVersionMS'] & 0xFFFF}.{file_info['FileVersionLS'] >> 16}.{file_info['FileVersionLS'] & 0xFFFF}"
        file_size = os.path.getsize(dll_path)
        creation_time = time.ctime(os.path.getctime(dll_path))
        return {
            'version': version,
            'file_size': file_size,
            'creation_time': creation_time
        }
    except Exception as e:
        logger.error(f"Error retrieving metadata for {dll_path}: {e}")
        return {'version': 'Unknown', 'file_size': 0, 'creation_time': 'Unknown'}

def compare_dll_metadata(dll_path, system32_path):
    """Compare metadata between a DLL and its System32 counterpart."""
    try:
        dll_meta = get_dll_metadata(dll_path)
        system_meta = get_dll_metadata(system32_path)

        differences = []
        if dll_meta['version'] != system_meta['version']:
            differences.append(f"Version mismatch: {dll_meta['version']} vs {system_meta['version']}")
        if abs(dll_meta['file_size'] - system_meta['file_size']) > 1024:  # Allow 1KB difference
            differences.append(f"File size mismatch: {dll_meta['file_size']} bytes vs {system_meta['file_size']} bytes")
        if dll_meta['creation_time'] != system_meta['creation_time']:
            differences.append(f"Creation time mismatch: {dll_meta['creation_time']} vs {system_meta['creation_time']}")

        if differences:
            logger.critical(f"DLL metadata mismatch: {dll_path} - {'; '.join(differences)}")
        return differences
    except Exception as e:
        logger.error(f"Error comparing metadata for {dll_path} and {system32_path}: {e}")
        return []

# Track running encryption detectors by pid
active_encryption_detectors = {}

def monitor_encryption_for_process(watch_dir, pid, exe_path):
    """Monitor encryption activity for a specific process in a separate thread."""
    def on_encryption_detected(sus_pid):
        logger.critical(f"ENCRYPTION DETECTED: Process {sus_pid} ({exe_path}) is encrypting files!")
        
        # Record hashes for static propagation detection BEFORE killing the process
        add_suspicious_hashes_from_process(sus_pid)
        logger.critical(f"Recorded suspicious file hashes for propagation detection")
        
        kill_process_by_pid(sus_pid)
        # Clean up the detector
        if sus_pid in active_encryption_detectors:
            del active_encryption_detectors[sus_pid]
    
    try:
        detector = file_encryption_detector.monitor_encryption_activity(
            watch_dir, pid, on_encryption_detected, extensions=['.notwncry'], interval=0.5, threshold=1
        )
        active_encryption_detectors[pid] = detector
        logger.info(f"Started encryption monitoring for PID {pid}")
    except Exception as e:
        logger.error(f"Failed to start encryption monitoring for PID {pid}: {e}")

def cleanup_dead_processes():
    """Clean up encryption detectors for processes that no longer exist."""
    dead_pids = []
    for pid in active_encryption_detectors.keys():
        try:
            psutil.Process(pid)
        except psutil.NoSuchProcess:
            dead_pids.append(pid)
    
    for pid in dead_pids:
        del active_encryption_detectors[pid]
        if pid in suspicious_processes:
            del suspicious_processes[pid]
        logger.info(f"Cleaned up monitoring for dead process PID {pid}")

def add_suspicious_process(pid, exe_path, dll_path, original_dll=None):
    """Add a suspicious process to the tracking dictionary."""
    if pid not in suspicious_processes:
        suspicious_processes[pid] = {
            'exe_path': exe_path,
            'suspicious_dlls': []
        }
    
    suspicious_processes[pid]['suspicious_dlls'].append({
        'dll_path': dll_path,
        'original_dll': original_dll
    })
    logger.critical(f"Added suspicious process tracking: PID {pid}, EXE: {exe_path}, DLL: {dll_path}, Original: {original_dll}")

def kill_process_by_pid(pid):
    """Kill a process by PID using pskill64.exe from needed-sysinternal."""
    import subprocess
    pskill_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'needed-sysinternal', 'pskill64.exe')
    try:
        result = subprocess.run([
            pskill_path, str(pid)
        ], capture_output=True, text=True, shell=True)
        logger.critical(f"Process {pid} killed using pskill64.exe. Output: {result.stdout}")
    except Exception as e:
        logger.error(f"Failed to kill process {pid} with pskill64.exe: {e}")

def monitor_processes(watch_dir, sysinternals_dir):
    """Continuously monitor for new processes whose EXE is inside watch_dir, and use Listdlls to list runtime DLLs."""
    seen_pids = set()
    listdlls_path = os.path.join(sysinternals_dir, 'Listdlls.exe' if os.name == 'nt' and os.environ.get('PROCESSOR_ARCHITECTURE', '').endswith('64') else 'Listdlls.exe')
    logger.info(f"Using Listdlls: {listdlls_path}")
    cleanup_counter = 0
    
    while True:
        try:
            # Periodic cleanup of dead processes (every 30 iterations)
            cleanup_counter += 1
            if cleanup_counter >= 30:
                cleanup_dead_processes()
                cleanup_counter = 0
            
            for proc in psutil.process_iter(['pid', 'exe', 'name']):
                pid = proc.info['pid']
                exe = proc.info['exe']
                if not exe or pid in seen_pids:
                    continue
                try:
                    if os.path.commonpath([os.path.abspath(exe), os.path.abspath(watch_dir)]) == os.path.abspath(watch_dir):
                        seen_pids.add(pid)
                        logger.info(f"New process detected: {exe} (PID {pid})")
                        
                        # First run Listdlls to analyze DLLs
                        try:
                            import subprocess
                            result = subprocess.run([
                                listdlls_path, '-u', str(pid)
                            ], capture_output=True, text=True, shell=True)
                            output = result.stdout
                            suspicious_blocks = []
                            current_block = []
                            for line in output.splitlines():
                                if line.strip().startswith('0x') and 'dll' in line.lower():
                                    if current_block:
                                        suspicious_blocks.append(current_block)
                                    current_block = [line]
                                elif current_block:
                                    current_block.append(line)
                            if current_block:
                                suspicious_blocks.append(current_block)
                            for block in suspicious_blocks:
                                block_text = '\n'.join(block)
                                if 'Verified:' in block_text and 'Unsigned' in block_text:
                                    path = block[0].split()[-1] if block else ''
                                    publisher = ''
                                    description = ''
                                    product = ''
                                    file_version = 'Unknown'
                                    create_time = 'Unknown'
                                    for l in block:
                                        if l.strip().startswith('Publisher:'):
                                            publisher = l.split(':',1)[-1].strip()
                                        elif l.strip().startswith('Description:'):
                                            description = l.split(':',1)[-1].strip()
                                        elif l.strip().startswith('Product:'):
                                            product = l.split(':',1)[-1].strip()
                                        elif l.strip().startswith('File version:'):
                                            file_version = l.split(':',1)[-1].strip()
                                        elif l.strip().startswith('Create time:'):
                                            create_time = l.split(':',1)[-1].strip()
                                    info_line = f"{path} | unsigned | publisher: {publisher} | description: {description} | product: {product}"
                                    if (not publisher or publisher.lower() == 'n/a') and (not description or description.lower() == 'n/a'):
                                        logger.critical(f"Suspicious DLL found: {info_line}")
                                        # Track the suspicious process
                                        add_suspicious_process(pid, exe, path)
                                    else:
                                        logger.warning(f"Unsigned DLL: {info_line}")
                                    # DLL proxying detection: compare exports and metadata with original
                                    dll_name = os.path.basename(path)
                                    system32_path = os.path.join(os.environ.get('SystemRoot', r'C:\\Windows'), 'System32', dll_name)
                                    if os.path.isfile(system32_path) and os.path.isfile(path):
                                        # Compare exports
                                        unsigned_exports = get_dll_exports(path)
                                        original_exports = get_dll_exports(system32_path)
                                        if unsigned_exports != original_exports:
                                            logger.critical(f"DLL proxying detected: {path} exports differ from {system32_path}")
                                            # Track the suspicious process with DLL proxying info
                                            add_suspicious_process(pid, exe, path, system32_path)
                                        # Compare metadata
                                        compare_dll_metadata(path, system32_path)
                        except Exception as e:
                            logger.error(f"Error running Listdlls for PID {pid}: {e}")
                        
                        # After DLL analysis, start monitoring for encryption-like activity in separate thread
                        threading.Thread(
                            target=monitor_encryption_for_process, 
                            args=(watch_dir, pid, exe), 
                            daemon=True
                        ).start()
                except Exception:
                    continue
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error in process monitor: {e}")
            time.sleep(5)

def monitor_persistence(sysinternals_dir):
    """Monitor autorun persistence using autorunsc.exe and delete suspicious entries."""
    autorunsc_path = os.path.join(sysinternals_dir, 'autorunsc.exe')
    logger.info(f"Starting persistence monitor using: {autorunsc_path}")
    
    while True:
        try:
            # Run autorunsc.exe to get autorun entries in CSV format
            result = subprocess.run([
                autorunsc_path, '-accepteula', '-c', '-h', '-s'
            ], capture_output=True, shell=True)
            
            if result.returncode != 0:
                logger.error(f"Autorunsc failed with return code {result.returncode}")
                time.sleep(30)
                continue
            
            # Handle Unicode BOM and decode output properly
            try:
                # First try UTF-16 with BOM handling
                raw_output = result.stdout
                if raw_output.startswith(b'\xff\xfe'):  # UTF-16 LE BOM
                    output_text = raw_output.decode('utf-16')
                elif raw_output.startswith(b'\xfe\xff'):  # UTF-16 BE BOM
                    output_text = raw_output.decode('utf-16')
                else:
                    # Try UTF-8 first, fallback to latin-1
                    try:
                        output_text = raw_output.decode('utf-8')
                    except UnicodeDecodeError:
                        output_text = raw_output.decode('latin-1')
                
                # Remove BOM if present
                if output_text.startswith('\ufeff'):
                    output_text = output_text[1:]
                
                # Find the start of CSV data by looking for header with "Time" and "Entry Location"
                output_lines = output_text.splitlines()
                csv_start_index = -1
                
                for i, line in enumerate(output_lines):
                    line_clean = line.strip()
                    # Look for CSV header containing the key columns
                    if ('Time' in line_clean and 'Entry Location' in line_clean and 
                        'Entry' in line_clean and 'Image Path' in line_clean):
                        csv_start_index = i
                        break
                
                if csv_start_index == -1:
                    logger.warning("Could not find CSV header in autorunsc output")
                    time.sleep(10)
                    continue
                
                # Extract only the CSV portion (header + data)
                csv_lines = output_lines[csv_start_index:]
                csv_content = '\n'.join(csv_lines)
                
                # Use pandas to parse CSV with proper error handling
                csv_data = io.StringIO(csv_content)
                df = pd.read_csv(csv_data, sep=',', on_bad_lines='skip', encoding='utf-8')
                
                # logger.info(f"Parsed {len(df)} autorun entries. Columns: {list(df.columns)}")
                
                # Check if we have the expected columns (handle different column name variations)
                image_path_col = None
                entry_location_col = None
                entry_col = None
                launch_string_col = None
                
                for col in df.columns:
                    col_lower = col.lower().strip()
                    if 'image path' in col_lower or 'imagepath' in col_lower:
                        image_path_col = col
                    elif 'entry location' in col_lower or 'entrylocation' in col_lower:
                        entry_location_col = col
                    elif col_lower == 'entry':
                        entry_col = col
                    elif 'launch string' in col_lower or 'launchstring' in col_lower:
                        launch_string_col = col
                
                if not image_path_col:
                    logger.warning("Image Path column not found in autorunsc output")
                    time.sleep(10)
                    continue
                
                # Filter rows that have valid image paths
                df = df.dropna(subset=[image_path_col])
                
                # Create corrected image path column using Launch String when Image Path is invalid
                def get_correct_path(row):
                    image_path = row[image_path_col]
                    if pd.isna(image_path) or 'file not found:' in str(image_path).lower():
                        # Use Launch String as fallback
                        if launch_string_col and not pd.isna(row[launch_string_col]):
                            return str(row[launch_string_col]).lower()
                    return str(image_path).lower()
                
                df['Image_Path_Lower'] = df.apply(get_correct_path, axis=1)
                
                # Create Launch_String_Lower column for consistent searching
                if launch_string_col:
                    df['Launch_String_Lower'] = df[launch_string_col].str.lower()
                else:
                    df['Launch_String_Lower'] = None

                

                # Define a clear path comparison function
                def compare_paths_with_exe(row, target_exe_path):
                    """
                    Compare Image Path and Launch String against target exe path.
                    Returns True if either path contains the target exe path.
                    """
                    target_exe_lower = target_exe_path.lower().replace('\\', '\\\\')
                    # logger.debug(f"Comparing row: {repr(target_exe_path)}")
                    # Check Image Path (already processed with fallback lo
                    image_path_lower = row['Image_Path_Lower'].lower().replace('\\', '\\\\')
                    # Log the comparison for debugging
                    # logger.debug(f"Comparing Image Path: {image_path_lower} with target exe: {target_exe_lower}")
                    # If Image Path is valid and contains the target exe path
                    if pd.notna(image_path_lower) and target_exe_lower in str(image_path_lower):
                        return True
                    
                    # Check Launch String if available
                    # Log the comparison for debugging
                    # logger.debug(f"Comparing Launch String: {row['Launch_String_Lower']} with target exe: {target_exe_lower}")
                    # If Launch String is available and contains the target exe path
                    if launch_string_col and pd.notna(row['Launch_String_Lower']):
                        launch_string_lower = row['Launch_String_Lower'].lower().replace('\\', '\\\\')
                        if target_exe_lower in str(launch_string_lower):
                            return True
                    
                    return False
                
                # Check against suspicious processes
                # logger.info(f"Checking autorun entries against suspicious processes...{suspicious_processes.items()}")
                for pid, info in suspicious_processes.items():
                    exe_path = info['exe_path']
                    exe_dir = os.path.dirname(exe_path.lower())
                    
                    # Apply the comparison function to the DataFrame
                    df['path_matches'] = df.apply(compare_paths_with_exe, target_exe_path=exe_path, axis=1)
                    
                    # Log results with index and boolean outcome
                    for idx, row in df.iterrows():
                        if row['path_matches']:
                            logger.debug(f"Index {idx}: Path comparison result = {row['path_matches']} for exe_path: {exe_path}")
                    
                    # Print last few autorun entries for debugging
                    # logger.debug(f"Last few autorun entries:\n{df.iloc[-1].to_dict()}")

                    # Get matching entries using the new function results
                    matching_entries = df[df['path_matches']]
                    logger.info(f"Found {len(matching_entries)} matching autorun entries for PID {pid} ({exe_path})")
                    
                    for _, row in matching_entries.iterrows():
                        # Check if suspicious DLL exists in same folder
                        suspicious_dll_in_folder = False
                        for dll_info in info['suspicious_dlls']:
                            dll_path = dll_info['dll_path'].lower()
                            dll_dir = os.path.dirname(dll_path)
                            if dll_dir == exe_dir:
                                suspicious_dll_in_folder = True
                                break
                        
                        if suspicious_dll_in_folder:
                                logger.critical(f"Suspicious autorun entry detected: {row[entry_col] if entry_col else 'Unknown'} at {row[entry_location_col] if entry_location_col else 'Unknown'} pointing to {row[image_path_col]}")
                                
                                # Attempt to delete the registry entry
                                if entry_location_col and entry_col:
                                    try:
                                        location = row[entry_location_col]
                                        entry_name = row[entry_col]
                                        
                                        if location.startswith('HKLM'):
                                            root_key = winreg.HKEY_LOCAL_MACHINE
                                            subkey_path = location[5:]  # Remove 'HKLM\'
                                        elif location.startswith('HKCU'):
                                            root_key = winreg.HKEY_CURRENT_USER
                                            subkey_path = location[5:]  # Remove 'HKCU\'
                                        else:
                                            logger.warning(f"Unknown registry root in {location}")
                                            continue
                                        
                                        # Try to delete the registry value
                                        try:
                                            with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_SET_VALUE) as key:
                                                winreg.DeleteValue(key, entry_name)
                                            logger.critical(f"Successfully deleted autorun registry entry: {entry_name} from {location}")
                                        except FileNotFoundError:
                                            logger.warning(f"Registry key or value not found: {location}\\{entry_name}")
                                        except PermissionError:
                                            logger.error(f"Permission denied deleting registry entry: {location}\\{entry_name}")
                                        except Exception as reg_e:
                                            logger.error(f"Error deleting registry entry {location}\\{entry_name}: {reg_e}")
                                            
                                    except Exception as e:
                                        logger.error(f"Error processing autorun entry {location}: {e}")
                
            except Exception as csv_e:
                logger.error(f"Error parsing autorunsc CSV output: {csv_e}")
                # Log first few lines of output for debugging
                if 'output_text' in locals():
                    lines_preview = output_text.splitlines()[:10]
                    logger.debug(f"First 10 lines of autorunsc output: {lines_preview}")
            
            time.sleep(10)  # Check every 10 seconds
        except Exception as e:
            logger.error(f"Error in persistence monitor: {e}")
            time.sleep(30)

def monitor_directory(watch_dir):
    # Ensure the directory exists
    if not os.path.isdir(watch_dir):
        logger.error(f"Directory {watch_dir} does not exist.")
        return

    # Initialize the event handler and observer
    event_handler = FolderCreationHandler(watch_dir)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=False)
    observer.start()

    try:
        logger.info(f"Monitoring directory {watch_dir} for new folders. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)  # Keep the script running to monitor events
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user.")
    finally:
        observer.stop()
        observer.join()

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def add_suspicious_hashes_from_process(pid):
    """Add exe and suspicious DLL hashes for a process to suspicious_hashes."""
    proc_info = suspicious_processes.get(pid)
    if not proc_info:
        return
    
    exe_path = proc_info.get('exe_path')
    if exe_path and os.path.isfile(exe_path):
        h = calculate_file_hash(exe_path)
        if h:
            suspicious_hashes[exe_path] = {'hash': h, 'type': 'exe'}
            logger.critical(f"Added suspicious exe hash: {h} for {exe_path}")
    
    for dll in proc_info.get('suspicious_dlls', []):
        dll_path = dll.get('dll_path')
        if dll_path and os.path.isfile(dll_path):
            h = calculate_file_hash(dll_path)
            if h:
                suspicious_hashes[dll_path] = {'hash': h, 'type': 'dll'}
                logger.critical(f"Added suspicious dll hash: {h} for {dll_path}")

def discover_network_shares():
    """Discover network shares using multiple methods."""
    shares = []
    
    # Method 1: Check mounted drives that could be network shares
    for drive in 'DEFGHIJKLMNOPQRSTUVWXYZ':
        path = f"{drive}:\\"
        if os.path.exists(path):
            try:
                # Check if it's a network drive
                drive_type = win32api.GetDriveType(path)
                if drive_type == 4:  # DRIVE_REMOTE
                    shares.append(path)
                    logger.info(f"Found network drive: {path}")
            except Exception:
                continue
    
    # Method 2: Discover hosts and enumerate their shares
    try:
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
                                if parts and not parts[0].endswith('$') and 'Disk' in line:
                                    share_name = parts[0]
                                    share_path = f"\\\\{ip}\\{share_name}"
                                    host_shares.append(share_path)
            except Exception:
                pass
            return host_shares
        
        # Use thread pool to check hosts in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_host_shares, ip) for ip in list(network.hosts())[:50]]  # Limit to first 50 IPs
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    host_shares = future.result()
                    shares.extend(host_shares)
                except:
                    continue
    except Exception as e:
        logger.error(f"Error discovering network shares: {e}")
    
    # Method 3: Add common public folders that malware might target
    public_folders = [
        os.path.expandvars(r'%PUBLIC%'),
        os.path.expanduser('~/Desktop'),
        os.path.expanduser('~/Documents')
    ]
    
    for folder in public_folders:
        if os.path.isdir(folder):
            shares.append(folder)
    
    logger.info(f"Discovered {len(shares)} potential propagation targets")
    return shares

def scan_and_delete_suspicious_files(sysinternals_dir):
    """Continuously scan network shares and propagation folders for files matching suspicious hashes and delete them."""
    logger.info("Starting static hash-based propagation detection")
    
    while True:
        try:
            if not suspicious_hashes:
                time.sleep(10)
                continue
            
            # Get all suspicious hashes
            hash_set = {info['hash'] for info in suspicious_hashes.values()}
            logger.info(f"Scanning for {len(hash_set)} suspicious file hashes")
            
            threading.Thread(target=static_propagation_detector.start_improved_static_propagation_detector, args=(suspicious_processes, sysinternals_dir, suspicious_hashes), daemon=True).start()

            # # Discover propagation targets
            # target_folders = discover_network_shares()
            
            # files_deleted = 0
            # for folder in target_folders:
            #     try:
            #         logger.debug(f"Scanning folder: {folder}")
                    
            #         # Walk through all files in the folder
            #         for root, dirs, files in os.walk(folder):
            #             for file in files:
            #                 file_path = os.path.join(root, file)
                            
            #                 try:
            #                     # Try to calculate hash directly
            #                     file_hash = calculate_file_hash(file_path)
                                
            #                     # If direct access fails, try copying to temp and calculating hash
            #                     if not file_hash:
            #                         try:
            #                             with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            #                                 shutil.copy2(file_path, tmp_file.name)
            #                                 file_hash = calculate_file_hash(tmp_file.name)
            #                                 os.unlink(tmp_file.name)
            #                         except Exception:
            #                             continue
                                
            #                     # Check if hash matches any suspicious hash
            #                     if file_hash and file_hash in hash_set:
            #                         try:
            #                             # Try to delete the file
            #                             os.remove(file_path)
            #                             files_deleted += 1
            #                             logger.critical(f"DELETED PROPAGATED MALWARE: {file_path} (hash: {file_hash})")
                                        
            #                             # Also try to delete any associated autorun.inf
            #                             autorun_path = os.path.join(os.path.dirname(file_path), "autorun.inf")
            #                             if os.path.exists(autorun_path):
            #                                 try:
            #                                     os.remove(autorun_path)
            #                                     logger.critical(f"DELETED AUTORUN.INF: {autorun_path}")
            #                                 except Exception:
            #                                     pass
                                                
            #                         except Exception as e:
            #                             logger.error(f"Failed to delete suspicious file {file_path}: {e}")
                                        
            #                 except Exception as e:
            #                     logger.debug(f"Error processing file {file_path}: {e}")
            #                     continue
                                
            #     except Exception as e:
            #         logger.error(f"Error scanning folder {folder}: {e}")
            #         continue
            
            # if files_deleted > 0:
            #     logger.critical(f"PROPAGATION CLEANUP COMPLETE: Deleted {files_deleted} malicious files")
            
            time.sleep(15)  # Check every 15 seconds
            
        except Exception as e:
            logger.error(f"Error in static propagation detection: {e}")
            time.sleep(30)

def main():
    # Specify the directory to monitor
    watch_dir = "C:\\Users\\JakeClark\\Downloads"
    sysinternals_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'needed-sysinternal')
    logger.info(f"Starting to monitor directory: {watch_dir}")
    # Start monitoring processes in a separate thread
    threading.Thread(target=monitor_processes, args=(watch_dir, sysinternals_dir), daemon=True).start()
    # Start monitoring persistence in a separate thread
    threading.Thread(target=monitor_persistence, args=(sysinternals_dir,), daemon=True).start()
    # Start SMB propagation detection in a separate thread
    
    # Start static hash-based propagation detection in a separate thread
    threading.Thread(target=scan_and_delete_suspicious_files, args=(sysinternals_dir,), daemon=True).start()
    # Start monitoring the directory
    monitor_directory(watch_dir)

if __name__ == "__main__":
    main()
