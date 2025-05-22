import os
import time
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