# Persistence Techniques Reference
# This file documents all persistence mechanisms to detect across Windows, Linux, and macOS

## WINDOWS PERSISTENCE TECHNIQUES

### Registry Run Keys/Startup Folder
- **Description**: Add entries to HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run or startup folders (e.g., %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup) for user-logon execution.
- **Real-World Examples**: Used by Gootloader for initial access handoff to ransomware operators; common in 96% of kernel rootkits.
- **Detection Locations**:
  - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
  - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
  - %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
  - %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup

### Scheduled Tasks/Jobs
- **Description**: Abuse schtasks.exe or WMI to create recurring tasks.
- **Real-World Examples**: Conti ransomware schedules tasks for encryption triggers; seen in Blue Mockingbird campaigns.
- **Detection**: Query via schtasks /query or WMI Win32_ScheduledJob

### Windows Services
- **Description**: Modify or create services via sc.exe or registry (HKLM\SYSTEM\CurrentControlSet\Services) for background execution.
- **Real-World Examples**: Ransomware like LockBit uses services for persistence post-reboot; 11% of malware bypassing tools in 2021-2023.
- **Detection Locations**:
  - HKLM\SYSTEM\CurrentControlSet\Services
  - Query via sc.exe

### Winlogon Helper DLL
- **Description**: Hijack HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon for DLL loading at logon.
- **Real-World Examples**: Used in APT28 campaigns for credential theft.
- **Detection Locations**:
  - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
  - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
  - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify

### DLL Hijacking/Search Order
- **Description**: Place malicious DLLs in search paths or use side-loading.
- **Real-World Examples**: Malware like Phantom Taurus uses this for espionage; common in supply-chain attacks.
- **Detection**: Check common hijack locations and application directories

### Bootkit/System Firmware
- **Description**: Modify boot sectors or BIOS/UEFI for pre-OS execution.
- **Real-World Examples**: HybridPetya ransomware embeds in firmware for evasion.
- **Detection**: Requires specialized tools (beyond scope)

### Accessibility Features
- **Description**: Replace tools like sethc.exe or utilman.exe for logon screen backdoors.
- **Real-World Examples**: Sticky Keys backdoor in older ransomware variants.
- **Detection Locations**:
  - C:\Windows\System32\sethc.exe
  - C:\Windows\System32\utilman.exe
  - C:\Windows\System32\osk.exe
  - C:\Windows\System32\Magnify.exe

### AppInit/AppCert DLLs
- **Description**: Load DLLs into processes via registry keys (e.g., HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows).
- **Real-World Examples**: Seen in banking trojans for process injection.
- **Detection Locations**:
  - HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
  - HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls

### WMI Event Subscription
- **Description**: Use WMI for event-triggered execution (e.g., on logon).
- **Real-World Examples**: APT groups like Phantom Taurus chain this with other techniques.
- **Detection**: Query WMI event consumers, filters, and bindings

### LSASS Driver/SSP
- **Description**: Modify LSASS for password interception.
- **Real-World Examples**: Mimikatz integration in rootkits.
- **Detection Locations**:
  - HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
  - HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages

### IFEO Injection
- **Description**: Use Image File Execution Options for debugger hijacking.
- **Real-World Examples**: Used in persistence for Cobalt Strike beacons.
- **Detection Locations**:
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

### Netsh Helper DLL
- **Description**: Register DLLs for netsh extensions.
- **Real-World Examples**: Network persistence in APTs.
- **Detection Locations**:
  - HKLM\SOFTWARE\Microsoft\NetSh

### Port Monitors/Print Processors
- **Description**: Load DLLs via spoolsv.exe at boot.
- **Real-World Examples**: Rare but seen in targeted attacks.
- **Detection Locations**:
  - HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors

### Authentication Packages
- **Description**: Load DLLs into LSA at boot.
- **Real-World Examples**: Older rootkits like those in 2000s incidents.
- **Detection Locations**:
  - HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages

### Time Providers
- **Description**: Abuse W32Time for DLL execution.
- **Real-World Examples**: Espionage malware.
- **Detection Locations**:
  - HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders

### Active Setup
- **Description**: Registry keys for logon execution.
- **Real-World Examples**: Commodity malware.
- **Detection Locations**:
  - HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
  - HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components

### COR_PROFILER
- **Description**: Hijack .NET profiling for assembly loading.
- **Real-World Examples**: Modern .NET-based threats.
- **Detection**: Environment variables COR_ENABLE_PROFILING, COR_PROFILER

### SilentProcessExit/GFlags
- **Description**: Abuse Global Flags for process monitoring.
- **Real-World Examples**: Advanced persistence in APTs.
- **Detection Locations**:
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit

### BITS Jobs
- **Description**: Use BITS for persistent downloads.
- **Real-World Examples**: Ransomware precursors like QakBot.
- **Detection**: Query via bitsadmin /list /allusers /verbose


## LINUX PERSISTENCE TECHNIQUES

### Cron Jobs
- **Description**: Schedule via crontab or /etc/cron.d/ for recurring execution.
- **Real-World Examples**: DripDropper modifies anacron for persistence; common in mining malware.
- **Detection Locations**:
  - /etc/crontab
  - /etc/cron.d/*
  - /var/spool/cron/crontabs/*
  - User crontabs (crontab -l)

### Systemd Services/Timers
- **Description**: Create/modify .service or .timer files in /etc/systemd/system/.
- **Real-World Examples**: Masqueraded as legit services in APTs; Kaiji variant.
- **Detection Locations**:
  - /etc/systemd/system/
  - /lib/systemd/system/
  - /usr/lib/systemd/system/
  - systemctl list-unit-files

### RC Scripts/Init.d
- **Description**: Modify /etc/rc.local or /etc/init.d/ for boot execution.
- **Real-World Examples**: Older worms like Ramen.
- **Detection Locations**:
  - /etc/rc.local
  - /etc/init.d/*
  - /etc/rc*.d/*

### Shell Configuration
- **Description**: Edit ~/.bashrc, /etc/profile for shell startup.
- **Real-World Examples**: Backdoors in SSH logins.
- **Detection Locations**:
  - ~/.bashrc
  - ~/.bash_profile
  - ~/.profile
  - /etc/profile
  - /etc/bash.bashrc
  - /etc/profile.d/*

### SSH Authorized Keys
- **Description**: Add keys to ~/.ssh/authorized_keys for remote access.
- **Real-World Examples**: DripDropper alters SSH configs.
- **Detection Locations**:
  - ~/.ssh/authorized_keys
  - /root/.ssh/authorized_keys
  - /etc/ssh/sshd_config (for backdoor configs)

### Loadable Kernel Modules (LKM)
- **Description**: Insert malicious modules via insmod for kernel-level hooks.
- **Real-World Examples**: Rootkits like those in AON's sedexp.
- **Detection**: lsmod, /proc/modules, /sys/module/

### eBPF Rootkits
- **Description**: Use eBPF for kernel tracing and hooking.
- **Real-World Examples**: Modern stealth in cloud environments.
- **Detection**: bpftool prog list (requires newer kernels)

### Dynamic Linker Hijacking (LD_PRELOAD)
- **Description**: Preload malicious libraries to override functions.
- **Real-World Examples**: Seen in Shai-Hulud npm worm.
- **Detection Locations**:
  - /etc/ld.so.preload
  - LD_PRELOAD environment variable

### Udev Rules
- **Description**: Trigger on hardware events via /etc/udev/rules.d/.
- **Real-World Examples**: Sedexp malware.
- **Detection Locations**:
  - /etc/udev/rules.d/*
  - /lib/udev/rules.d/*

### PAM Modules
- **Description**: Modify Pluggable Authentication Modules for credential capture.
- **Real-World Examples**: Backdoors in authentication.
- **Detection Locations**:
  - /etc/pam.d/*
  - /lib/security/*
  - /lib64/security/*

### At Jobs
- **Description**: Schedule one-time tasks via atd.
- **Real-World Examples**: Rare but used in evasion.
- **Detection**: atq, /var/spool/at/*

### XDG Autostart
- **Description**: .desktop files in ~/.config/autostart/ for GUI logins.
- **Real-World Examples**: Desktop malware.
- **Detection Locations**:
  - ~/.config/autostart/*.desktop
  - /etc/xdg/autostart/*.desktop

### Motd
- **Description**: Malicious Message of the Day for SSH triggers.
- **Real-World Examples**: Persistence in logins.
- **Detection Locations**:
  - /etc/update-motd.d/*
  - /etc/motd


## MACOS PERSISTENCE TECHNIQUES

### Launch Agents/Daemons
- **Description**: Modify .plist in /Library/LaunchAgents/ or /Library/LaunchDaemons.
- **Real-World Examples**: XCSSET uses for clipboard hijacking.
- **Detection Locations**:
  - /Library/LaunchAgents/
  - /Library/LaunchDaemons/
  - ~/Library/LaunchAgents/
  - /System/Library/LaunchAgents/
  - /System/Library/LaunchDaemons/

### Login Items
- **Description**: Add via shared file lists or Service Management.
- **Real-World Examples**: Bundlore adware.
- **Detection Locations**:
  - ~/Library/Preferences/com.apple.loginitems.plist
  - System Preferences > Users & Groups > Login Items

### Re-opened Applications
- **Description**: Modify ~/Library/Preferences/ByHost/ plists.
- **Real-World Examples**: Persistence post-reboot.
- **Detection Locations**:
  - ~/Library/Preferences/ByHost/

### Emond
- **Description**: Rules in /etc/emond.d/ for event monitoring.
- **Real-World Examples**: Rare, but in APTs.
- **Detection Locations**:
  - /etc/emond.d/rules/

### Login Hooks
- **Description**: com.apple.loginwindow plists.
- **Real-World Examples**: Older techniques.
- **Detection**: defaults read com.apple.loginwindow LoginHook

### Dylib Hijacking
- **Description**: Insert malicious dylibs in paths.
- **Real-World Examples**: Similar to Windows DLL hijacking.
- **Detection**: Check DYLD_INSERT_LIBRARIES and application bundles


## IMPLEMENTATION PRIORITY

### Phase 1 (Current - Basic Detection)
- Windows: Registry Run keys, Startup folders, Scheduled tasks, Services
- Linux: Cron jobs, Systemd services/timers, RC scripts, Autostart, Profile files
- macOS: Launch Agents/Daemons, Login Items

### Phase 2 (Advanced Detection)
- Windows: Winlogon, IFEO, WMI subscriptions, AppInit DLLs
- Linux: SSH keys, LD_PRELOAD, Kernel modules, PAM modules
- macOS: Re-opened apps, Emond, Login hooks

### Phase 3 (Expert Detection)
- Windows: BITS jobs, Netsh helpers, Port monitors, COR_PROFILER
- Linux: eBPF, Udev rules, At jobs
- macOS: Dylib hijacking

### Phase 4 (Forensic Analysis)
- All platforms: Hash verification, timestamp analysis, suspicious path detection
- Behavioral analysis and anomaly detection
