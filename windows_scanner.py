import os
import subprocess
import logging
from forensic_helpers import get_file_metadata, get_registry_metadata

try:
    import winreg as reg
except ImportError:
    reg = None

# Known legitimate entries
LEGITIMATE_RUN_KEYS = {
    'SecurityHealth', 'VBoxTray', 'VMware User Process', 'VMware VM3DService Process',
    'OneDrive', 'OneDriveSetup', 'MicrosoftEdgeAutoLaunch', 'SecurityHealth', 'ctfmon'
}

# Legitimate startup approved entries (these can be disabled by user)
LEGITIMATE_STARTUP_APPROVED = {
    'MicrosoftEdgeAutoLaunch', 'OneDrive', 'OneDriveSetup'
}

LEGITIMATE_SERVICES = {
    'AnyDesk', 'Appinfo', 'AppXSvc', 'AudioEndpointBuilder', 'Audiosrv', 'BFE', 'BITS',
    'BrokerInfrastructure', 'camsvc', 'CDPSvc', 'ClipSVC', 'CoreMessagingRegistrar', 'CryptSvc',
    'DcomLaunch', 'DevQueryBroker', 'Dhcp', 'DiagTrack', 'DispBrokerDesktopSvc', 'Dnscache',
    'DoSvc', 'DPS', 'DusmSvc', 'EventLog', 'EventSystem', 'FontCache', 'gpsvc', 'IKEEXT',
    'InstallService', 'iphlpsvc', 'KeyIso', 'LanmanServer', 'LanmanWorkstation', 'lfsvc',
    'LicenseManager', 'lmhosts', 'LSM', 'MDCoreSvc', 'mpssvc', 'NcbService', 'netprofm',
    'NgcCtnrSvc', 'NgcSvc', 'NlaSvc', 'nsi', 'PcaSvc', 'PlugPlay', 'PolicyAgent', 'Power',
    'ProfSvc', 'RasMan', 'RmSvc', 'RpcEptMapper', 'RpcSs', 'SamSs', 'Schedule', 'seclogon',
    'SecurityHealthService', 'SENS', 'ShellHWDetection', 'Spooler', 'SSDPSRV', 'SstpSvc',
    'StateRepository', 'StorSvc', 'SysMain', 'SystemEventsBroker', 'TabletInputService',
    'Themes', 'TimeBrokerSvc', 'TokenBroker', 'TrkWks', 'UltraViewService', 'UserManager',
    'UsoSvc', 'VaultSvc', 'VBoxService', 'WaaSMedicSvc', 'Wcmsvc', 'WdiServiceHost',
    'WdiSystemHost', 'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt', 'wlidsvc', 'wmiApSrv',
    'WpnService', 'wscsvc', 'WSearch', 'wuauserv'
}

LEGITIMATE_IFEO = {
    'ExtExport.exe', 'ie4uinit.exe', 'ieinstal.exe', 'ielowutil.exe', 'ieUnatt.exe',
    'iexplore.exe', 'MicrosoftEdgeUpdate.exe', 'MRT.exe', 'mscorsvw.exe', 'msfeedssync.exe',
    'mshta.exe', 'MsMpEng.exe', 'MsSense.exe', 'ngen.exe', 'ngentask.exe', 'PresentationHost.exe',
    'PrintDialog.exe', 'PrintIsolationHost.exe', 'runtimebroker.exe', 'splwow64.exe',
    'spoolsv.exe', 'svchost.exe', 'SystemSettings.exe', 'wpr.exe', 'wprui.exe'
}

LEGITIMATE_NETSH = {
    'ifmon.dll', 'rasmontr.dll', 'authfwcfg.dll', 'dhcpcmonitor.dll', 'dot3cfg.dll',
    'fwcfg.dll', 'hnetmon.dll', 'netiohlp.dll', 'nettrace.dll', 'nshhttp.dll',
    'nshipsec.dll', 'nshwfp.dll', 'p2pnetsh.dll', 'rpcnsh.dll', 'WcnNetsh.dll',
    'whhelper.dll', 'wlancfg.dll', 'wshelper.dll', 'wwancfg.dll', 'peerdistsh.dll'
}

LEGITIMATE_MONITORS = {
    'Appmon', 'Local Port', 'Microsoft Shared Fax Monitor', 'Standard TCP/IP Port',
    'USB Monitor', 'WSD Port'
}

# Security tools that should NOT be disabled
SECURITY_TOOLS = {'SecurityHealth', 'WinDefend', 'MsMpEng'}

# Helper to extract file path from command string
def extract_file_path(command_str):
    """Extract executable path from command string"""
    import re
    # Remove quotes and get first part
    command_str = command_str.strip('"').strip("'")
    # Extract path before first space or argument
    match = re.match(r'^([^\s]+\.(?:exe|dll|sys|bat|cmd|ps1))', command_str, re.IGNORECASE)
    if match:
        path = match.group(1)
        # Expand environment variables
        return os.path.expandvars(path)
    return None

# Helper to check digital signature
def check_digital_signature(file_path):
    """Check if file is digitally signed by Microsoft"""
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             f'(Get-AuthenticodeSignature "{file_path}").Status'],
            capture_output=True, text=True, timeout=5
        )
        if 'Valid' in result.stdout:
            signer = subprocess.run(
                ['powershell', '-Command',
                 f'(Get-AuthenticodeSignature "{file_path}").SignerCertificate.Subject'],
                capture_output=True, text=True, timeout=5
            )
            return 'Microsoft' in signer.stdout
        return False
    except:
        return None

# Helper function to get registry key timestamp
def get_reg_key_timestamp(hive, path):
    """Get last modified time of registry key"""
    try:
        from datetime import datetime
        key = reg.OpenKey(hive, path)
        _, _, last_modified = reg.QueryInfoKey(key)
        reg.CloseKey(key)
        timestamp = datetime.fromtimestamp(last_modified / 10000000 - 11644473600)
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'N/A'

# ============================================================================
# 1. Registry Run Keys/Startup Folder
# ============================================================================
def check_registry_run_keys():
    if not reg:
        return {}
    results = {}
    paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    for hive_name, hive in [("HKLM", reg.HKEY_LOCAL_MACHINE), ("HKCU", reg.HKEY_CURRENT_USER)]:
        for path in paths:
            try:
                key = reg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = reg.EnumValue(key, i)
                        is_suspicious = name not in LEGITIMATE_RUN_KEYS
                        
                        # Get registry key metadata
                        reg_metadata = get_registry_metadata(hive, path)
                        
                        # Check signature of executable
                        file_path = extract_file_path(value)
                        signed = None
                        file_metadata = None
                        
                        if file_path and os.path.exists(file_path):
                            signed = check_digital_signature(file_path)
                            file_metadata = get_file_metadata(file_path)
                            if signed == False:
                                is_suspicious = True
                        
                        result = {
                            'value': value,
                            'signed_by_ms': signed,
                            'is_suspicious': is_suspicious
                        }
                        
                        # Add forensic metadata
                        if reg_metadata:
                            result['registry_modified'] = reg_metadata['last_modified']
                        if file_metadata:
                            result.update(file_metadata)
                        
                        results[f"{hive_name}\\{path}\\{name}"] = result
                        i += 1
                    except OSError:
                        break
                reg.CloseKey(key)
            except (FileNotFoundError, PermissionError):
                pass
    return results

def check_startup_folders():
    folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    results = {}
    for folder in folders:
        if os.path.exists(folder):
            try:
                files = os.listdir(folder)
                file_details = []
                for f in files:
                    if f.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.lnk')):
                        fpath = os.path.join(folder, f)
                        signed = check_digital_signature(fpath)
                        file_metadata = get_file_metadata(fpath)
                        
                        file_info = {
                            'name': f,
                            'signed_by_ms': signed,
                            'is_suspicious': signed == False
                        }
                        
                        if file_metadata:
                            file_info.update(file_metadata)
                        
                        file_details.append(file_info)
                    else:
                        file_details.append({'name': f})
                if file_details:
                    results[folder] = file_details
            except PermissionError:
                pass
    return results

# ============================================================================
# 2. Scheduled Tasks/Jobs
# ============================================================================
def check_scheduled_tasks():
    try:
        output = subprocess.check_output(['schtasks', '/query', '/fo', 'LIST', '/v'], stderr=subprocess.DEVNULL).decode(errors='ignore')
        tasks = {}
        current_task = None
        task_data = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current_task and task_data:
                    # Filter out Microsoft default tasks
                    if not current_task.startswith('\\Microsoft\\Windows\\'):
                        # Check signature of task executable
                        if 'command' in task_data:
                            file_path = extract_file_path(task_data['command'])
                            if file_path and os.path.exists(file_path):
                                task_data['signed_by_ms'] = check_digital_signature(file_path)
                                file_metadata = get_file_metadata(file_path)
                                if file_metadata:
                                    task_data.update(file_metadata)
                        tasks[current_task] = task_data
                    current_task = None
                    task_data = {}
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'TaskName':
                    current_task = value
                elif key == 'Next Run Time':
                    task_data['next_run'] = value
                elif key == 'Status':
                    task_data['status'] = value
                elif key == 'Author':
                    task_data['author'] = value
                elif key == 'Task To Run':
                    task_data['command'] = value
        
        return tasks
    except:
        return {}

# ============================================================================
# 3. Windows Services
# ============================================================================
def check_services():
    try:
        output = subprocess.check_output(['sc', 'query', 'type=', 'service'], stderr=subprocess.DEVNULL).decode(errors='ignore')
        services = {}
        for line in output.split('\n'):
            if line.startswith('SERVICE_NAME:'):
                name = line.split(':', 1)[1].strip()
                is_suspicious = name not in LEGITIMATE_SERVICES and not name.endswith('_1016dd')
                
                # Get service binary path and check signature
                signed = None
                try:
                    qc_output = subprocess.check_output(['sc', 'qc', name], stderr=subprocess.DEVNULL, timeout=2).decode(errors='ignore')
                    for qc_line in qc_output.split('\n'):
                        if 'BINARY_PATH_NAME' in qc_line:
                            binary_path = qc_line.split(':', 1)[1].strip()
                            file_path = extract_file_path(binary_path)
                            if file_path and os.path.exists(file_path):
                                signed = check_digital_signature(file_path)
                                if signed == False:
                                    is_suspicious = True
                            break
                except:
                    pass
                
                services[name] = {
                    'is_suspicious': is_suspicious,
                    'signed_by_ms': signed
                }
        return services
    except:
        return {}

# ============================================================================
# 4. Winlogon Helper DLL
# ============================================================================
def check_winlogon():
    if not reg:
        return {}
    results = {}
    paths = [
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]
    values_to_check = ['Shell', 'Userinit', 'Notify']
    for path in paths:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
            for val in values_to_check:
                try:
                    value, _ = reg.QueryValueEx(key, val)
                    # Check signature
                    file_path = extract_file_path(value)
                    signed = None
                    is_suspicious = False
                    if file_path and os.path.exists(file_path):
                        signed = check_digital_signature(file_path)
                        is_suspicious = signed == False
                    results[f"HKLM\\{path}\\{val}"] = {
                        'value': value,
                        'signed_by_ms': signed,
                        'is_suspicious': is_suspicious
                    }
                except FileNotFoundError:
                    pass
            reg.CloseKey(key)
        except:
            pass
    return results

# ============================================================================
# 5. Accessibility Features
# ============================================================================
def check_accessibility_features():
    files = [
        r"C:\Windows\System32\sethc.exe",
        r"C:\Windows\System32\utilman.exe",
        r"C:\Windows\System32\osk.exe",
        r"C:\Windows\System32\Magnify.exe",
    ]
    results = {}
    for file in files:
        if os.path.exists(file):
            try:
                stat = os.stat(file)
                signed = check_digital_signature(file)
                is_suspicious = signed == False  # Unsigned or wrong signer
                results[file] = {
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'signed_by_ms': signed,
                    'is_suspicious': is_suspicious
                }
            except:
                pass
    return results

# ============================================================================
# 6. AppInit/AppCert DLLs
# ============================================================================
def check_appinit_dlls():
    if not reg:
        return {}
    results = {}
    paths = [
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
        r"System\CurrentControlSet\Control\Session Manager",
    ]
    for path in paths:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
            try:
                value, _ = reg.QueryValueEx(key, "AppInit_DLLs")
                if value:
                    # Check signature of DLL
                    dll_path = os.path.expandvars(value.strip())
                    signed = None
                    is_suspicious = True
                    if os.path.exists(dll_path):
                        signed = check_digital_signature(dll_path)
                        is_suspicious = signed == False
                    
                    results[f"HKLM\\{path}\\AppInit_DLLs"] = {
                        'value': value,
                        'signed_by_ms': signed,
                        'is_suspicious': is_suspicious
                    }
            except:
                pass
            reg.CloseKey(key)
        except:
            pass
    return results

# ============================================================================
# 7. WMI Event Subscription
# ============================================================================
def check_wmi_subscriptions():
    try:
        output = subprocess.check_output(['wmic', 'process', 'where', 'name="wmiprvse.exe"', 'get', 'ProcessId'], stderr=subprocess.DEVNULL).decode(errors='ignore')
        return {"WMI_Process": output.strip()}
    except:
        return {}

# ============================================================================
# 8. LSASS Driver/SSP
# ============================================================================
def check_lsass_ssp():
    if not reg:
        return {}
    results = {}
    paths = [
        r"SYSTEM\CurrentControlSet\Control\Lsa",
    ]
    for path in paths:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
            try:
                value, _ = reg.QueryValueEx(key, "Security Packages")
                results[f"HKLM\\{path}\\Security Packages"] = value
            except:
                pass
            reg.CloseKey(key)
        except:
            pass
    return results

# ============================================================================
# 9. IFEO Injection
# ============================================================================
def check_ifeo():
    if not reg:
        return {}
    results = {}
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                subkey_name = reg.EnumKey(key, i)
                is_suspicious = subkey_name not in LEGITIMATE_IFEO
                results[f"HKLM\\{path}\\{subkey_name}"] = {'is_suspicious': is_suspicious}
                i += 1
            except OSError:
                break
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 10. Netsh Helper DLL
# ============================================================================
def check_netsh_helpers():
    if not reg:
        return {}
    results = {}
    path = r"SOFTWARE\Microsoft\NetSh"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                name, value, _ = reg.EnumValue(key, i)
                is_suspicious = value not in LEGITIMATE_NETSH
                
                # Check signature of DLL
                dll_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', value)
                signed = None
                if os.path.exists(dll_path):
                    signed = check_digital_signature(dll_path)
                    if signed == False:
                        is_suspicious = True
                
                results[f"HKLM\\{path}\\{name}"] = {
                    'value': value,
                    'signed_by_ms': signed,
                    'is_suspicious': is_suspicious
                }
                i += 1
            except OSError:
                break
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 11. Port Monitors
# ============================================================================
def check_port_monitors():
    if not reg:
        return {}
    results = {}
    path = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                subkey_name = reg.EnumKey(key, i)
                is_suspicious = subkey_name not in LEGITIMATE_MONITORS
                
                # Try to get DLL path from subkey
                signed = None
                try:
                    subkey = reg.OpenKey(key, subkey_name)
                    dll_name, _ = reg.QueryValueEx(subkey, "Driver")
                    dll_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', dll_name)
                    if os.path.exists(dll_path):
                        signed = check_digital_signature(dll_path)
                        if signed == False:
                            is_suspicious = True
                    reg.CloseKey(subkey)
                except:
                    pass
                
                results[f"HKLM\\{path}\\{subkey_name}"] = {
                    'signed_by_ms': signed,
                    'is_suspicious': is_suspicious
                }
                i += 1
            except OSError:
                break
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 12. Authentication Packages
# ============================================================================
def check_auth_packages():
    if not reg:
        return {}
    results = {}
    path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        try:
            packages, _ = reg.QueryValueEx(key, "Authentication Packages")
            # Check each package DLL
            if isinstance(packages, list):
                for pkg in packages:
                    dll_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', pkg + '.dll')
                    signed = None
                    is_suspicious = False
                    if os.path.exists(dll_path):
                        signed = check_digital_signature(dll_path)
                        is_suspicious = signed == False
                    results[f"HKLM\\{path}\\{pkg}"] = {
                        'signed_by_ms': signed,
                        'is_suspicious': is_suspicious
                    }
            else:
                results[f"HKLM\\{path}\\Authentication Packages"] = {'value': packages}
        except:
            pass
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 13. Time Providers
# ============================================================================
def check_time_providers():
    if not reg:
        return {}
    results = {}
    path = r"System\CurrentControlSet\Services\W32Time\TimeProviders"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                subkey_name = reg.EnumKey(key, i)
                results[f"HKLM\\{path}\\{subkey_name}"] = "Present"
                i += 1
            except OSError:
                break
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 14. Active Setup
# ============================================================================
def check_active_setup():
    if not reg:
        return {}
    results = {}
    paths = [
        r"SOFTWARE\Microsoft\Active Setup\Installed Components",
    ]
    for hive_name, hive in [("HKLM", reg.HKEY_LOCAL_MACHINE), ("HKCU", reg.HKEY_CURRENT_USER)]:
        for path in paths:
            try:
                key = reg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        subkey_name = reg.EnumKey(key, i)
                        subkey_path = f"{path}\\{subkey_name}"
                        modified = get_reg_key_timestamp(hive, subkey_path)
                        results[f"{hive_name}\\{path}\\{subkey_name}"] = {
                            'modified': modified
                        }
                        i += 1
                    except OSError:
                        break
                reg.CloseKey(key)
            except:
                pass
    return results

# ============================================================================
# 15. COR_PROFILER
# ============================================================================
def check_cor_profiler():
    results = {}
    env_vars = ['COR_ENABLE_PROFILING', 'COR_PROFILER', 'COR_PROFILER_PATH']
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            results[var] = value
    return results

# ============================================================================
# 16. SilentProcessExit
# ============================================================================
def check_silent_process_exit():
    if not reg:
        return {}
    results = {}
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                subkey_name = reg.EnumKey(key, i)
                results[f"HKLM\\{path}\\{subkey_name}"] = "Present"
                i += 1
            except OSError:
                break
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# 17. BITS Jobs
# ============================================================================
def check_bits_jobs():
    try:
        output = subprocess.check_output(['bitsadmin', '/list', '/allusers', '/verbose'], stderr=subprocess.DEVNULL).decode(errors='ignore')
        return {"BITS_Jobs": output.strip() if output.strip() else "No jobs"}
    except:
        return {}

# ============================================================================
# 18. DLL Search Order Hijacking
# ============================================================================
def check_dll_hijacking():
    # Check common hijack locations
    paths = [
        os.path.expandvars(r"%WINDIR%\System32"),
        os.path.expandvars(r"%WINDIR%\SysWOW64"),
    ]
    results = {}
    suspicious_dlls = ['version.dll', 'dwmapi.dll', 'cryptbase.dll']
    for path in paths:
        if os.path.exists(path):
            for dll in suspicious_dlls:
                dll_path = os.path.join(path, dll)
                if os.path.exists(dll_path):
                    try:
                        stat = os.stat(dll_path)
                        results[dll_path] = f"Size: {stat.st_size}"
                    except:
                        pass
    return results

# ============================================================================
# 19. Startup Approved
# ============================================================================
def check_startup_approved():
    if not reg:
        return {}
    results = {}
    paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
    ]
    for hive_name, hive in [("HKLM", reg.HKEY_LOCAL_MACHINE), ("HKCU", reg.HKEY_CURRENT_USER)]:
        for path in paths:
            try:
                key = reg.OpenKey(hive, path)
                modified = get_reg_key_timestamp(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = reg.EnumValue(key, i)
                        # Parse binary data: Byte 0 = 0x02 (Enabled) or 0x03 (Disabled)
                        status = 'Unknown'
                        is_suspicious = False
                        
                        if isinstance(value, bytes) and len(value) >= 1:
                            status_byte = value[0]
                            status = 'Enabled' if status_byte == 0x02 else 'Disabled' if status_byte == 0x03 else 'Unknown'
                            
                            # Only flag if security tool is disabled
                            if status == 'Disabled' and any(tool in name for tool in SECURITY_TOOLS):
                                is_suspicious = True
                            # Don't flag legitimate startup items
                            elif status == 'Enabled' and name not in LEGITIMATE_RUN_KEYS and name not in LEGITIMATE_STARTUP_APPROVED:
                                # Only suspicious if it's truly unknown
                                is_suspicious = not any(legit in name for legit in ['Microsoft', 'Windows', 'OneDrive', 'Edge'])
                        
                        results[f"{hive_name}\\{path}\\{name}"] = {
                            'modified': modified,
                            'status': status,
                            'is_suspicious': is_suspicious
                        }
                        i += 1
                    except OSError:
                        break
                reg.CloseKey(key)
            except:
                pass
    return results

# ============================================================================
# 20. Boot Execute
# ============================================================================
def check_boot_execute():
    if not reg:
        return {}
    results = {}
    path = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path)
        try:
            value, _ = reg.QueryValueEx(key, "BootExecute")
            results[f"HKLM\\{path}\\BootExecute"] = value
        except:
            pass
        reg.CloseKey(key)
    except:
        pass
    return results

# ============================================================================
# MAIN SCANNER
# ============================================================================
def scan_windows():
    results = {
        "1. Registry Run Keys": check_registry_run_keys(),
        "2. Startup Folders": check_startup_folders(),
        "3. Scheduled Tasks": check_scheduled_tasks(),
        "4. Windows Services": check_services(),
        "5. Winlogon Helper DLL": check_winlogon(),
        "6. Accessibility Features": check_accessibility_features(),
        "7. AppInit/AppCert DLLs": check_appinit_dlls(),
        "8. WMI Event Subscriptions": check_wmi_subscriptions(),
        "9. LSASS/SSP": check_lsass_ssp(),
        "10. IFEO Injection": check_ifeo(),
        "11. Netsh Helper DLL": check_netsh_helpers(),
        "12. Port Monitors": check_port_monitors(),
        "13. Authentication Packages": check_auth_packages(),
        "14. Time Providers": check_time_providers(),
        "15. Active Setup": check_active_setup(),
        "16. COR_PROFILER": check_cor_profiler(),
        "17. SilentProcessExit": check_silent_process_exit(),
        "18. BITS Jobs": check_bits_jobs(),
        "19. Startup Approved": check_startup_approved(),
        "20. Boot Execute": check_boot_execute(),
    }
    return results
