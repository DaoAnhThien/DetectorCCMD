import os
import time
import threading
import logging

logger = logging.getLogger(__name__)

class EncryptionActivityDetector:
    """
    Monitors a directory for rapid file changes that match typical ransomware/encryption behavior.
    If a process is detected to be rapidly overwriting/deleting/creating files (especially with new extensions),
    it is flagged as suspicious.
    """
    def __init__(self, watch_dir, pid, callback_on_detect, extensions=None, interval=2, threshold=5):
        self.watch_dir = watch_dir
        self.pid = pid
        self.callback_on_detect = callback_on_detect
        self.extensions = extensions or ['.notwncry']
        self.interval = interval
        self.threshold = threshold
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._monitor)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._thread.join()

    def _monitor(self):
        while not self._stop_event.is_set():
            suspicious_count = 0
            for root, dirs, files in os.walk(self.watch_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    if ext in self.extensions:
                        suspicious_count += 1
            if suspicious_count >= self.threshold:
                logger.critical(f"Encryption-like activity detected in {self.watch_dir} by PID {self.pid}")
                self.callback_on_detect(self.pid)
                break
            time.sleep(self.interval)

def monitor_encryption_activity(watch_dir, pid, callback_on_detect, extensions=None, interval=2, threshold=5):
    """
    Helper to start the encryption activity detector in a thread.
    """
    detector = EncryptionActivityDetector(watch_dir, pid, callback_on_detect, extensions, interval, threshold)
    detector.start()
    return detector
