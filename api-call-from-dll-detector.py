import os
import subprocess
import logging
import pefile

# Set up a dedicated logger for API call detection
api_logger = logging.getLogger('api_call_detector')
api_logger.setLevel(logging.INFO)
handler = logging.FileHandler('api_call_detector.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
if not api_logger.hasHandlers():
    api_logger.addHandler(handler)

# Suspicious API names (Crypto, memory, network, process injection, etc.)
SUSPICIOUS_APIS = [
    b'CryptEncrypt', b'CryptAcquireContext', b'CryptGenRandom', b'CryptDeriveKey',
    b'VirtualAlloc', b'VirtualAllocEx', b'VirtualProtect', b'VirtualProtectEx',
    b'CreateThread', b'CreateRemoteThread', b'WriteProcessMemory',
    b'WinHttpOpen', b'WinHttpConnect', b'WinHttpOpenRequest', b'WinHttpSendRequest', b'WinHttpReceiveResponse',
    b'URLDownloadToFile', b'InternetOpen', b'InternetOpenUrl', b'InternetReadFile',
    b'LoadLibrary', b'GetProcAddress', b'NtMapViewOfSection', b'RtlMoveMemory',
]

# Helper: Use Listdlls to enumerate loaded DLLs for a process

def get_loaded_dlls(pid, listdlls_path):
    try:
        result = subprocess.run([
            listdlls_path, '-u', str(pid)
        ], capture_output=True, text=True, shell=True)
        dlls = []
        for line in result.stdout.splitlines():
            if line.strip().startswith('0x') and '.dll' in line.lower():
                parts = line.split()
                if parts:
                    dlls.append(parts[-1])
        return dlls
    except Exception as e:
        api_logger.error(f"Failed to get loaded DLLs for PID {pid}: {e}")
        return []

# Helper: Scan DLL exports for suspicious APIs

def scan_dll_for_suspicious_apis(dll_path):
    try:
        pe = pefile.PE(dll_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and any(api in exp.name for api in SUSPICIOUS_APIS):
                    api_logger.warning(f"Suspicious API {exp.name.decode()} found in {dll_path}")
                    return True
        return False
    except Exception as e:
        api_logger.error(f"Error scanning {dll_path} for suspicious APIs: {e}")
        return False

# Helper: Scan process for suspicious DLL API usage

def scan_process_for_suspicious_apis(pid, listdlls_path):
    dlls = get_loaded_dlls(pid, listdlls_path)
    suspicious = False
    for dll in dlls:
        if scan_dll_for_suspicious_apis(dll):
            api_logger.critical(f"PID {pid} loaded suspicious DLL: {dll}")
            suspicious = True
    return suspicious

# Helper: Log suspicious network activity (WinHttp, etc.)
def log_suspicious_network_activity(pid, api_name, details=None):
    api_logger.warning(f"PID {pid} used suspicious network API: {api_name} {details or ''}")

# Helper: Log suspicious memory/shellcode activity
def log_suspicious_memory_activity(pid, api_name, details=None):
    api_logger.warning(f"PID {pid} used suspicious memory API: {api_name} {details or ''}")
