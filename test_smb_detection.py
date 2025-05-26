#!/usr/bin/env python3
"""
Test script for SMB Propagation Detection System
This script simulates the propagation behavior and tests the detector
"""

import os
import time
import threading
import subprocess
import sys

def test_smb_propagation_detection():
    """Test the SMB propagation detection system"""
    print("=== SMB Propagation Detection Test ===")
    
    # Start the propagator in background
    print("\n1. Starting propagator simulation...")
    propagator_process = subprocess.Popen([
        sys.executable, "propagator.py"
    ], cwd=os.path.dirname(os.path.abspath(__file__)))
    
    print("   Propagator started with PID:", propagator_process.pid)
    
    # Wait a bit for propagator to start
    time.sleep(5)
    
    # Start the detector (this would normally be running already)
    print("\n2. Starting detector with SMB monitoring...")
    try:
        detector_process = subprocess.Popen([
            sys.executable, "detector.py"
        ], cwd=os.path.dirname(os.path.abspath(__file__)))
        
        print("   Detector started with PID:", detector_process.pid)
        
        # Let both run for a while
        print("\n3. Monitoring for 30 seconds...")
        time.sleep(30)
        
        print("\n4. Checking logs...")
        
        # Check SMB propagation detector log
        log_file = "smb_propagation_detector.log"
        if os.path.exists(log_file):
            print(f"\n--- SMB Propagation Detector Log ({log_file}) ---")
            with open(log_file, 'r') as f:
                lines = f.readlines()
                # Show last 20 lines
                for line in lines[-20:]:
                    print(line.strip())
        else:
            print(f"Log file {log_file} not found")
        
        # Cleanup
        print("\n5. Stopping processes...")
        propagator_process.terminate()
        detector_process.terminate()
        
        # Wait for processes to stop
        propagator_process.wait(timeout=5)
        detector_process.wait(timeout=5)
        
        print("Test completed!")
        
    except Exception as e:
        print(f"Error during test: {e}")
        # Cleanup on error
        try:
            propagator_process.terminate()
            if 'detector_process' in locals():
                detector_process.terminate()
        except:
            pass

def show_test_results():
    """Show test results and logs"""
    print("\n=== Test Results ===")
    
    # List all log files
    log_files = [
        "smb_propagation_detector.log",
        "api_call_detector.log"
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            print(f"\n--- {log_file} ---")
            with open(log_file, 'r') as f:
                content = f.read()
                if content.strip():
                    print(content[-1000:])  # Last 1000 chars
                else:
                    print("(Empty log file)")
        else:
            print(f"{log_file}: Not found")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "results":
        show_test_results()
    else:
        test_smb_propagation_detection()
