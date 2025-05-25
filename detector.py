import os
import time
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import threading
import psutil
import win32api
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import importlib
file_encryption_detector = importlib.import_module('file-encryption-detector')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

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
            logger.info(f"Scanning directory: {root}")
            for file in files:
                if file.lower().endswith('.exe'):
                    exe_found = True
                    exe_path = os.path.join(root, file)
                    logger.info(f"Found .exe file: {exe_path}")
                    # Analyze DLL dependencies for the .exe file
                    analyze_exe_dependencies(exe_path)

        if not exe_found:
            logger.info(f"No .exe files found in {folder_path} or its subfolders.")

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
            logger.critical(f"DLL metadata differences detected for {dll_path}: {'; '.join(differences)}")
        return differences
    except Exception as e:
        logger.error(f"Error comparing metadata for {dll_path} and {system32_path}: {e}")
        return []

# Track running encryption detectors by pid
active_encryption_detectors = {}

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
    while True:
        try:
            for proc in psutil.process_iter(['pid', 'exe', 'name']):
                pid = proc.info['pid']
                exe = proc.info['exe']
                if not exe or pid in seen_pids:
                    continue
                try:
                    if os.path.commonpath([os.path.abspath(exe), os.path.abspath(watch_dir)]) == os.path.abspath(watch_dir):
                        seen_pids.add(pid)
                        logger.info(f"New process detected: {exe} (PID {pid})")
                        # Start monitoring for encryption-like activity
                        def on_encryption_detected(sus_pid):
                            kill_process_by_pid(sus_pid)
                        detector = file_encryption_detector.monitor_encryption_activity(
                            watch_dir, pid, on_encryption_detected, extensions=['.notwncry'], interval=1, threshold=1
                        )
                        active_encryption_detectors[pid] = detector
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
                                    info_line = f"{path} | unsigned | publisher: {publisher} | description: {description} | product: {product} | file version: {file_version} | create time: {create_time}"
                                    if (not publisher or publisher.lower() == 'n/a') and (not description or description.lower() == 'n/a'):
                                        logger.critical(f"Suspicious DLL found: {info_line}")
                                    else:
                                        logger.warning(f"Caution with this unsigned DLL: {info_line}")
                                    # DLL proxying detection: compare exports and metadata with original
                                    dll_name = os.path.basename(path)
                                    system32_path = os.path.join(os.environ.get('SystemRoot', r'C:\\Windows'), 'System32', dll_name)
                                    if os.path.isfile(system32_path) and os.path.isfile(path):
                                        # Compare exports
                                        unsigned_exports = get_dll_exports(path)
                                        original_exports = get_dll_exports(system32_path)
                                        if unsigned_exports != original_exports:
                                            # Log specific differences
                                            unsigned_names = {name for name, ordinal in unsigned_exports}
                                            original_names = {name for name, ordinal in original_exports}
                                            missing_in_unsigned = original_names - unsigned_names
                                            extra_in_unsigned = unsigned_names - original_names
                                            ordinal_mismatches = {
                                                name for name, ordinal in unsigned_exports
                                                for orig_name, orig_ordinal in original_exports
                                                if name == orig_name and ordinal != orig_ordinal
                                            }
                                            diff_log = []
                                            if missing_in_unsigned:
                                                diff_log.append(f"Missing exports: {sorted(missing_in_unsigned)}")
                                            if extra_in_unsigned:
                                                diff_log.append(f"Extra exports: {sorted(extra_in_unsigned)}")
                                            if ordinal_mismatches:
                                                diff_log.append(f"Ordinal mismatches: {sorted(ordinal_mismatches)}")
                                            logger.critical(f"DLL proxying detected: {path} exports differ from {system32_path}. {'; '.join(diff_log)}")
                                        # Compare metadata
                                        compare_dll_metadata(path, system32_path)
                        except Exception as e:
                            logger.error(f"Error running Listdlls for PID {pid}: {e}")
                except Exception:
                    continue
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error in process monitor: {e}")
            time.sleep(5)

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

def main():
    # Specify the directory to monitor
    watch_dir = "D:\\Downloads\\HK6\\NT230CCMD\\Detector\\test"
    sysinternals_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'needed-sysinternal')
    logger.info(f"Starting to monitor directory: {watch_dir}")
    # Start monitoring processes in a separate thread
    threading.Thread(target=monitor_processes, args=(watch_dir, sysinternals_dir), daemon=True).start()
    # Start monitoring the directory
    monitor_directory(watch_dir)

if __name__ == "__main__":
    main()
