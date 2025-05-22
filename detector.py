import os
import time
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

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
    """Analyze the DLL dependencies of an .exe file using pefile."""
    try:
        pe = pefile.PE(exe_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            logger.info(f"DLL dependencies for {exe_path}:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                logger.info(f"  - {dll_name}")
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

def main():
    # Specify the directory to monitor
    watch_dir = r"D:\Downloads\HK6\NT230CCMD\Detector\test"  
    monitor_directory(watch_dir)

if __name__ == "__main__":
    main()