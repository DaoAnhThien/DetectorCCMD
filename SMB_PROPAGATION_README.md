# SMB Propagation Detection System

## Overview

The SMB Propagation Detection System is an advanced component of the malware detection suite that monitors and prevents malicious software from spreading across network shares via SMB (Server Message Block) protocol.

## Components

### 1. SMB Propagation Detector (`smb_propagation_detector.py`)

**Purpose**: Monitors suspicious processes for SMB network activity and prevents propagation

**Key Features**:
- **Real-time SMB monitoring**: Tracks network connections on SMB ports (445, 139)
- **Network blocking**: Uses Windows Firewall to block suspicious processes from network access
- **Network share scanning**: Discovers and monitors network shares for malicious files
- **Automatic cleanup**: Removes malware files from accessible network shares

**Detection Methods**:
1. **Connection Monitoring**: Uses `netstat` to detect SMB connections by suspicious processes
2. **Firewall Blocking**: Creates Windows Firewall rules to block malicious executables
3. **Share Discovery**: Scans local network for SMB shares using `net view`
4. **File Cleanup**: Identifies and removes suspicious files from network shares

### 2. Propagator Simulator (`propagator.py`)

**Purpose**: Simulates malware propagation behavior for testing the detection system

**Simulation Capabilities**:
- **Network discovery**: Scans local network for SMB hosts
- **Share enumeration**: Lists available shares on discovered hosts
- **File propagation**: Copies malicious files to writable shares
- **Autorun creation**: Creates autorun.inf files for persistence

## Integration with Main Detector

The SMB propagation detector integrates seamlessly with the main detection system:

```python
# In detector.py main()
threading.Thread(
    target=smb_propagation_detector.start_smb_propagation_detector, 
    args=(suspicious_processes, sysinternals_dir), 
    daemon=True
).start()
```

## Detection Flow

```
1. Process Detection
   ↓
2. Suspicious Process Identified
   ↓
3. SMB Activity Monitoring Started
   ↓
4. SMB Connection Detected
   ↓
5. Network Access Blocked
   ↓
6. Network Share Cleanup
```

## Configuration

### Network Monitoring
- **SMB Ports**: 445 (SMB over TCP), 139 (NetBIOS)
- **Scan Range**: Local /24 network (first 50 IPs)
- **Check Interval**: 2 seconds for process monitoring, 5 minutes for share cleanup

### Firewall Rules
- **Rule Name Format**: `Block_Malware_PID_{pid}`
- **Direction**: Outbound
- **Action**: Block
- **Protocol**: Any

## Logging

### SMB Propagation Log (`smb_propagation_detector.log`)
```
2025-05-26 10:15:32 - INFO - Starting SMB propagation detector
2025-05-26 10:15:35 - WARNING - SMB activity detected for PID 1234:
2025-05-26 10:15:35 - WARNING -   TCP 192.168.1.100:50123 -> 192.168.1.10:445 (ESTABLISHED)
2025-05-26 10:15:35 - CRITICAL - Blocking SMB propagation attempt by PID 1234
2025-05-26 10:15:40 - CRITICAL - Found suspicious executable in share: \\192.168.1.10\shared\malware.exe
2025-05-26 10:15:41 - CRITICAL - Deleted malware file from share: \\192.168.1.10\shared\malware.exe
```

## Testing

### Manual Testing
```bash
# Run the propagator simulator
python propagator.py

# Run the main detector (includes SMB detection)
python detector.py

# Run the test suite
python test_smb_detection.py
```

### Test Scenarios
1. **Basic Propagation**: Malware attempts to copy files to network shares
2. **Network Blocking**: Suspicious process is blocked from network access
3. **Share Cleanup**: Existing malware files are removed from shares
4. **Persistence Detection**: Autorun.inf files are detected and removed

## Security Considerations

### Administrative Privileges
- **Firewall Rules**: Requires administrator privileges to create firewall rules
- **Network Shares**: May require appropriate permissions to access and clean shares
- **Process Monitoring**: Uses standard Windows APIs (netstat, psutil)

### False Positives
- **Legitimate SMB Usage**: The system focuses on processes with suspicious DLL loading
- **Network Applications**: Only monitors processes detected by the main malware detector
- **Share Access**: Only cleans files matching suspicious process signatures

## Performance Impact

### Resource Usage
- **CPU**: Minimal impact from periodic network scanning
- **Memory**: Small overhead for tracking process connections
- **Network**: Limited network traffic from share discovery and cleanup

### Optimization Features
- **Threaded Operations**: Network scanning uses thread pools for faster execution
- **Targeted Monitoring**: Only monitors processes already flagged as suspicious
- **Cached Results**: Network share discovery results are cached between scans

## Error Handling

### Network Errors
- **Timeout Protection**: All network operations have appropriate timeouts
- **Permission Errors**: Gracefully handles shares with restricted access
- **Connection Failures**: Continues operation if individual hosts are unreachable

### System Errors
- **Process Termination**: Handles cleanup when monitored processes exit
- **Firewall Failures**: Logs errors but continues monitoring other processes
- **File System Errors**: Continues cleanup operation even if some files can't be deleted

## Future Enhancements

### Advanced Detection
- **Behavioral Analysis**: Monitor file access patterns on network shares
- **Credential Monitoring**: Detect attempts to use stolen credentials
- **Protocol Analysis**: Deep packet inspection of SMB traffic

### Response Capabilities
- **Quarantine Mode**: Isolate infected systems from network
- **Alerting System**: Send notifications to security teams
- **Forensics Collection**: Capture evidence of propagation attempts

## Troubleshooting

### Common Issues

1. **No Network Shares Found**
   - Check network connectivity
   - Verify SMB is enabled on target systems
   - Confirm firewall allows SMB traffic

2. **Firewall Rules Not Created**
   - Run with administrator privileges
   - Check Windows Firewall service status
   - Verify netsh command availability

3. **Files Not Deleted from Shares**
   - Check write permissions on target shares
   - Verify antivirus is not blocking deletion
   - Confirm file is not locked by another process

### Debug Mode
Enable verbose logging by modifying the logger level:
```python
smb_logger.setLevel(logging.DEBUG)
```

## Dependencies

### System Requirements
- **Windows**: Windows 7/2008 or newer
- **Python**: 3.6 or newer
- **Privileges**: Administrator recommended for full functionality

### Python Packages
- `psutil`: Process monitoring
- `socket`: Network operations
- `subprocess`: System command execution
- `threading`: Concurrent operations
- `pathlib`: File system operations

### System Tools
- `netstat`: Network connection monitoring
- `netsh`: Firewall rule management
- `net view`: SMB share enumeration
