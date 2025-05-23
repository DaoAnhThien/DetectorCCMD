import os
import time
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import threading
import psutil

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
                                    # DLL proxying detection: compare exports with original
                                    dll_name = os.path.basename(path)
                                    system32_path = os.path.join(os.environ.get('SystemRoot', r'C:\\Windows'), 'System32', dll_name)
                                    if os.path.isfile(system32_path) and os.path.isfile(path):
                                        unsigned_exports = get_dll_exports(path)
                                        original_exports = get_dll_exports(system32_path)
                                        if unsigned_exports != original_exports:
                                            logger.critical(f"DLL proxying detected: {path} exports differ from {system32_path}. Unsigned exports: {sorted(unsigned_exports)}. Original exports: {sorted(original_exports)}")
                        except Exception as e:
                            logger.error(f"Error running Listdlls for PID {pid}: {e}")
                except Exception:
                    continue
            time.sleep(2)
        except Exception as e:
            logger.error(f"Error in process monitor: {e}")
            time.sleep(5)

def get_dll_exports(dll_path):
    """Return a set of exported function names from a DLL using pefile."""
    try:
        import pefile
        pe = pefile.PE(dll_path)
        exports = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.add(exp.name.decode('utf-8', errors='ignore'))
        return exports
    except Exception as e:
        logger.error(f"Error reading exports from {dll_path}: {e}")
        return set()

def main():
    # Specify the directory to monitor, 
    watch_dir = "C:\\Users\\JakeClark\\Downloads"  # Change this to your target directory
    sysinternals_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'needed-sysinternal')
    logger.info(f"Starting to monitor directory: {watch_dir}")  
    # Start monitoring the directory
    threading.Thread(target=monitor_processes, args=(watch_dir, sysinternals_dir), daemon=True).start()
    monitor_directory(watch_dir)
    # Start monitoring processes
    #monitor_processes(watch_dir, sysinternals_dir)

if __name__ == "__main__":
    main()