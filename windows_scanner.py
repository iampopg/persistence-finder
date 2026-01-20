import os
import subprocess
import logging

try:
    import winreg as reg
except ImportError:
    reg = None

# Known legitimate entries
LEGITIMATE_RUN_KEYS = {
    'SecurityHealth', 'VBoxTray', 'VMware User Process', 'VMware VM3DService Process',
    'OneDrive', 'OneDriveSetup', 'MicrosoftEdgeAutoLaunch'
}

LEGITIMATE_SERVICES = {
    'AnyDesk', 'AppXSvc', 'AudioEndpointBuilder', 'Audiosrv', 'BFE', 'BrokerInfrastructure',
    'camsvc', 'CDPSvc', 'CoreMessagingRegistrar', 'CryptSvc', 'DcomLaunch', 'DevQueryBroker',
    'Dhcp', 'DiagTrack', 'DispBrokerDesktopSvc', 'Dnscache', 'DoSvc', 'DPS', 'DusmSvc',
    'EventLog', 'EventSystem', 'FontCache', 'gpsvc', 'IKEEXT', 'InstallService', 'iphlpsvc',
    'KeyIso', 'LanmanServer', 'LanmanWorkstation', 'lfsvc', 'LicenseManager', 'lmhosts',
    'LSM', 'MDCoreSvc', 'mpssvc', 'NcbService', 'netprofm', 'NgcSvc', 'NlaSvc', 'nsi',
    'PlugPlay', 'PolicyAgent', 'Power', 'ProfSvc', 'RasMan', 'RmSvc', 'RpcEptMapper', 'RpcSs',
    'SamSs', 'Schedule', 'SecurityHealthService', 'SENS', 'ShellHWDetection', 'Spooler',
    'SstpSvc', 'StateRepository', 'StorSvc', 'SysMain', 'SystemEventsBroker', 'TabletInputService',
    'Themes', 'TimeBrokerSvc', 'TokenBroker', 'TrkWks', 'UltraViewService', 'UserManager',
    'UsoSvc', 'VaultSvc', 'VBoxService', 'WaaSMedicSvc', 'Wcmsvc', 'WdiServiceHost',
    'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt', 'wlidsvc', 'WpnService', 'wscsvc',
    'WSearch', 'wuauserv', 'SSDPSRV', 'WdiSystemHost'
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
                        results[f"{hive_name}\\{path}\\{name}"] = {
                            'value': value,
                            'is_suspicious': is_suspicious
                        }
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
                if files:
                    results[folder] = files
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
                services[name] = {'is_suspicious': is_suspicious}
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
                    results[f"HKLM\\{path}\\{val}"] = value
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
                results[file] = f"Size: {stat.st_size}, Modified: {stat.st_mtime}"
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
                    results[f"HKLM\\{path}\\AppInit_DLLs"] = value
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
                results[f"HKLM\\{path}\\{name}"] = {
                    'value': value,
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
                results[f"HKLM\\{path}\\{subkey_name}"] = {'is_suspicious': is_suspicious}
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
            value, _ = reg.QueryValueEx(key, "Authentication Packages")
            results[f"HKLM\\{path}\\Authentication Packages"] = value
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
                        results[f"{hive_name}\\{path}\\{subkey_name}"] = "Present"
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
                i = 0
                while True:
                    try:
                        name, value, _ = reg.EnumValue(key, i)
                        results[f"{hive_name}\\{path}\\{name}"] = "Present"
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
