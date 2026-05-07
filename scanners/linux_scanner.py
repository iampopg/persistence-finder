import os
import subprocess
import logging
import glob
import pwd
from datetime import datetime

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_timestamp(timestamp):
    """Convert Unix timestamp to human-readable format"""
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(timestamp)

def get_file_info(filepath):
    """Get file metadata including timestamps"""
    try:
        stat = os.stat(filepath)
        return {
            'modified': format_timestamp(stat.st_mtime),
            'created': format_timestamp(stat.st_ctime),
            'size': stat.st_size,
            'permissions': oct(stat.st_mode)[-3:]
        }
    except:
        return None

# ============================================================================
# CRON JOBS - Schedule via crontab or /etc/cron.d/ for recurring execution
# Real-World: DripDropper, mining malware
# ============================================================================

def check_cron_jobs():
    results = {}
    
    # User crontab
    try:
        output = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL).decode()
        if output.strip():
            results['user_crontab'] = {
                'content': output,
                'info': 'Current user crontab'
            }
    except subprocess.CalledProcessError:
        pass
    
    # System crontabs
    cron_files = ['/etc/crontab'] + glob.glob('/etc/cron.d/*')
    for file in cron_files:
        if os.path.isfile(file):
            try:
                file_info = get_file_info(file)
                with open(file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        results[file] = {
                            'modified': file_info['modified'],
                            'size': f"{file_info['size']} bytes",
                            'permissions': file_info['permissions'],
                            'content_preview': content[:300] + '...' if len(content) > 300 else content
                        }
            except PermissionError:
                logging.warning(f"Permission denied: {file}")
    
    # User crontabs in /var/spool/cron/crontabs/
    crontab_dir = '/var/spool/cron/crontabs/'
    if os.path.exists(crontab_dir):
        try:
            for user_cron in os.listdir(crontab_dir):
                path = os.path.join(crontab_dir, user_cron)
                try:
                    file_info = get_file_info(path)
                    with open(path, 'r') as f:
                        results[f'crontab_{user_cron}'] = {
                            'modified': file_info['modified'],
                            'content': f.read()
                        }
                except PermissionError:
                    logging.warning(f"Permission denied: {path}")
        except PermissionError:
            logging.warning(f"Permission denied: {crontab_dir}")
    
    return results

# ============================================================================
# SYSTEMD SERVICES/TIMERS - Create/modify .service or .timer files
# Real-World: APTs, Kaiji variant
# ============================================================================

def check_systemd_units():
    try:
        output = subprocess.check_output(['systemctl', 'list-unit-files', '--type=service', '--state=enabled'], 
                                        stderr=subprocess.DEVNULL).decode()
        services = [line.split()[0] for line in output.split('\n')[1:-2] if line.strip()]
        return services
    except Exception as e:
        logging.warning(f"Could not query systemd: {e}")
        return []

def check_systemd_timers():
    try:
        output = subprocess.check_output(['systemctl', 'list-unit-files', '--type=timer', '--state=enabled'], 
                                        stderr=subprocess.DEVNULL).decode()
        timers = [line.split()[0] for line in output.split('\n')[1:-2] if line.strip()]
        return timers
    except Exception as e:
        logging.warning(f"Could not query systemd timers: {e}")
        return []

def check_systemd_files():
    """Check for suspicious systemd unit files"""
    results = {}
    systemd_dirs = [
        '/etc/systemd/system/',
        '/lib/systemd/system/',
        '/usr/lib/systemd/system/',
        os.path.expanduser('~/.config/systemd/user/')
    ]
    
    for dir in systemd_dirs:
        if os.path.exists(dir):
            try:
                for file in os.listdir(dir):
                    if file.endswith(('.service', '.timer')):
                        path = os.path.join(dir, file)
                        try:
                            file_info = get_file_info(path)
                            if file_info:
                                results[path] = {
                                    'modified': file_info['modified'],
                                    'created': file_info['created'],
                                    'size': f"{file_info['size']} bytes",
                                    'permissions': file_info['permissions']
                                }
                        except:
                            pass
            except PermissionError:
                logging.warning(f"Permission denied: {dir}")
    
    return results

# ============================================================================
# RC SCRIPTS/INIT.D - Modify /etc/rc.local or /etc/init.d/ for boot execution
# Real-World: Older worms like Ramen
# ============================================================================

def check_rc_scripts():
    results = {}
    
    # Check /etc/rc.local
    if os.path.exists('/etc/rc.local'):
        try:
            file_info = get_file_info('/etc/rc.local')
            with open('/etc/rc.local', 'r') as f:
                content = f.read()
                if content.strip() and os.access('/etc/rc.local', os.X_OK):
                    results['/etc/rc.local'] = {
                        'modified': file_info['modified'],
                        'size': f"{file_info['size']} bytes",
                        'executable': 'Yes',
                        'content_preview': content[:300] + '...' if len(content) > 300 else content
                    }
        except PermissionError:
            logging.warning("Permission denied: /etc/rc.local")
    
    # Check /etc/init.d/ scripts
    init_dir = '/etc/init.d/'
    if os.path.exists(init_dir):
        try:
            scripts = []
            for f in os.listdir(init_dir):
                fpath = os.path.join(init_dir, f)
                if os.path.isfile(fpath):
                    file_info = get_file_info(fpath)
                    scripts.append({
                        'name': f,
                        'modified': file_info['modified']
                    })
            if scripts:
                results['init.d_scripts'] = scripts
        except PermissionError:
            logging.warning(f"Permission denied: {init_dir}")
    
    # Check rc*.d directories
    for rc_dir in glob.glob('/etc/rc*.d/'):
        try:
            links = os.listdir(rc_dir)
            if links:
                results[rc_dir] = links
        except PermissionError:
            logging.warning(f"Permission denied: {rc_dir}")
    
    return results

# ============================================================================
# SHELL CONFIGURATION - Edit ~/.bashrc, /etc/profile for shell startup
# Real-World: Backdoors in SSH logins
# ============================================================================

def check_profile_files():
    results = {}
    profile_files = [
        '/etc/profile',
        '/etc/bash.bashrc',
        '/etc/zsh/zshrc',
        os.path.expanduser('~/.bashrc'),
        os.path.expanduser('~/.bash_profile'),
        os.path.expanduser('~/.profile'),
        os.path.expanduser('~/.zshrc'),
        os.path.expanduser('~/.bash_login'),
    ]
    
    for file in profile_files:
        if os.path.exists(file):
            try:
                file_info = get_file_info(file)
                with open(file, 'r') as f:
                    content = f.read()
                    if content.strip():
                        suspicious = find_suspicious_commands(content)
                        results[file] = {
                            'size': f"{file_info['size']} bytes",
                            'modified': file_info['modified'],
                            'permissions': file_info['permissions'],
                            'suspicious_commands': suspicious if suspicious else 'None',
                            'is_suspicious': bool(suspicious)
                        }
            except PermissionError:
                logging.warning(f"Permission denied: {file}")
    
    # Check /etc/profile.d/ scripts
    profile_d = '/etc/profile.d/'
    if os.path.exists(profile_d):
        try:
            scripts = []
            for script in os.listdir(profile_d):
                script_path = os.path.join(profile_d, script)
                if os.path.isfile(script_path):
                    file_info = get_file_info(script_path)
                    scripts.append({
                        'name': script,
                        'modified': file_info['modified'],
                        'size': f"{file_info['size']} bytes"
                    })
            if scripts:
                results[profile_d] = scripts
        except PermissionError:
            logging.warning(f"Permission denied: {profile_d}")
    
    return results

def find_suspicious_commands(content):
    """Look for suspicious commands in shell scripts"""
    suspicious = []
    patterns = ['curl', 'wget', 'nc ', 'netcat', '/dev/tcp', 'base64', 'eval', 'exec']
    for pattern in patterns:
        if pattern in content:
            suspicious.append(pattern)
    return suspicious if suspicious else None

# ============================================================================
# SSH AUTHORIZED KEYS - Add keys to ~/.ssh/authorized_keys for remote access
# Real-World: DripDropper
# ============================================================================

def check_ssh_keys():
    results = {}
    
    # Check current user
    ssh_files = [
        os.path.expanduser('~/.ssh/authorized_keys'),
        os.path.expanduser('~/.ssh/authorized_keys2'),
    ]
    
    for file in ssh_files:
        if os.path.exists(file):
            try:
                file_info = get_file_info(file)
                with open(file, 'r') as f:
                    keys = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if keys:
                        results[file] = {
                            'modified': file_info['modified'],
                            'key_count': len(keys),
                            'keys': keys
                        }
            except PermissionError:
                logging.warning(f"Permission denied: {file}")
    
    # Check root
    root_ssh = '/root/.ssh/authorized_keys'
    if os.path.exists(root_ssh):
        try:
            file_info = get_file_info(root_ssh)
            with open(root_ssh, 'r') as f:
                keys = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if keys:
                    results[root_ssh] = {
                        'modified': file_info['modified'],
                        'key_count': len(keys),
                        'keys': keys
                    }
        except PermissionError:
            logging.warning(f"Permission denied: {root_ssh}")
    
    # Check SSH config for backdoors
    sshd_config = '/etc/ssh/sshd_config'
    if os.path.exists(sshd_config):
        try:
            file_info = get_file_info(sshd_config)
            with open(sshd_config, 'r') as f:
                content = f.read()
                suspicious = []
                if 'PermitRootLogin yes' in content:
                    suspicious.append('PermitRootLogin enabled')
                if 'PasswordAuthentication no' not in content:
                    suspicious.append('Password auth enabled')
                if suspicious:
                    results['sshd_config_warnings'] = {
                        'modified': file_info['modified'],
                        'warnings': suspicious
                    }
        except PermissionError:
            logging.warning(f"Permission denied: {sshd_config}")
    
    return results

# ============================================================================
# LOADABLE KERNEL MODULES (LKM) - Insert malicious modules via insmod
# Real-World: Rootkits like sedexp
# ============================================================================

def check_kernel_modules():
    results = {}
    
    # List loaded modules
    try:
        output = subprocess.check_output(['lsmod'], stderr=subprocess.DEVNULL).decode()
        modules = [line.split()[0] for line in output.split('\n')[1:] if line.strip()]
        results['loaded_modules'] = modules
    except Exception as e:
        logging.warning(f"Could not list kernel modules: {e}")
    
    # Check /proc/modules
    if os.path.exists('/proc/modules'):
        try:
            with open('/proc/modules', 'r') as f:
                results['proc_modules'] = f.read()
        except PermissionError:
            logging.warning("Permission denied: /proc/modules")
    
    # Check /sys/module/
    sys_module = '/sys/module/'
    if os.path.exists(sys_module):
        try:
            modules = os.listdir(sys_module)
            results['sys_modules_count'] = len(modules)
        except PermissionError:
            logging.warning(f"Permission denied: {sys_module}")
    
    return results

# ============================================================================
# eBPF ROOTKITS - Use eBPF for kernel tracing and hooking
# Real-World: Modern stealth in cloud environments
# ============================================================================

def check_ebpf():
    results = {}
    
    # Check if bpftool is available
    try:
        output = subprocess.check_output(['bpftool', 'prog', 'list'], 
                                        stderr=subprocess.DEVNULL).decode()
        if output.strip():
            results['bpf_programs'] = output
    except FileNotFoundError:
        results['bpftool'] = 'Not installed (cannot detect eBPF programs)'
    except Exception as e:
        logging.warning(f"Could not query eBPF: {e}")
    
    return results

# ============================================================================
# DYNAMIC LINKER HIJACKING (LD_PRELOAD) - Preload malicious libraries
# Real-World: Shai-Hulud npm worm
# ============================================================================

def check_ld_preload():
    results = {}
    
    # Check /etc/ld.so.preload
    ld_preload_file = '/etc/ld.so.preload'
    if os.path.exists(ld_preload_file):
        try:
            with open(ld_preload_file, 'r') as f:
                content = f.read().strip()
                if content:
                    results[ld_preload_file] = content
        except PermissionError:
            logging.warning(f"Permission denied: {ld_preload_file}")
    
    # Check LD_PRELOAD environment variable
    ld_preload_env = os.environ.get('LD_PRELOAD')
    if ld_preload_env:
        results['LD_PRELOAD_env'] = ld_preload_env
    
    # Check LD_LIBRARY_PATH
    ld_library_path = os.environ.get('LD_LIBRARY_PATH')
    if ld_library_path:
        results['LD_LIBRARY_PATH'] = ld_library_path
    
    return results

# ============================================================================
# UDEV RULES - Trigger on hardware events via /etc/udev/rules.d/
# Real-World: Sedexp malware
# ============================================================================

def check_udev_rules():
    results = {}
    udev_dirs = ['/etc/udev/rules.d/', '/lib/udev/rules.d/']
    
    for dir in udev_dirs:
        if os.path.exists(dir):
            try:
                rules = [f for f in os.listdir(dir) if f.endswith('.rules')]
                if rules:
                    results[dir] = rules
            except PermissionError:
                logging.warning(f"Permission denied: {dir}")
    
    return results

# ============================================================================
# PAM MODULES - Modify Pluggable Authentication Modules
# Real-World: Backdoors in authentication
# ============================================================================

def check_pam_modules():
    results = {}
    
    # Check PAM configuration files
    pam_dir = '/etc/pam.d/'
    if os.path.exists(pam_dir):
        try:
            configs = os.listdir(pam_dir)
            results['pam_configs'] = configs
        except PermissionError:
            logging.warning(f"Permission denied: {pam_dir}")
    
    # Check PAM modules
    pam_lib_dirs = ['/lib/security/', '/lib64/security/', '/lib/x86_64-linux-gnu/security/']
    for dir in pam_lib_dirs:
        if os.path.exists(dir):
            try:
                modules = [f for f in os.listdir(dir) if f.startswith('pam_')]
                if modules:
                    results[dir] = modules
            except PermissionError:
                logging.warning(f"Permission denied: {dir}")
    
    return results

# ============================================================================
# AT JOBS - Schedule one-time tasks via atd
# Real-World: Rare but used in evasion
# ============================================================================

def check_at_jobs():
    results = {}
    
    # Check atq
    try:
        output = subprocess.check_output(['atq'], stderr=subprocess.DEVNULL).decode()
        if output.strip():
            results['at_queue'] = output
    except FileNotFoundError:
        results['at'] = 'Not installed'
    except Exception as e:
        logging.warning(f"Could not query at jobs: {e}")
    
    # Check /var/spool/at/
    at_spool = '/var/spool/at/'
    if os.path.exists(at_spool):
        try:
            jobs = [f for f in os.listdir(at_spool) if os.path.isfile(os.path.join(at_spool, f))]
            if jobs:
                results['at_spool_jobs'] = jobs
        except PermissionError:
            logging.warning(f"Permission denied: {at_spool}")
    
    return results

# ============================================================================
# XDG AUTOSTART - .desktop files for GUI logins
# Real-World: Desktop malware
# ============================================================================

def check_autostart():
    results = {}
    autostart_dirs = [
        '/etc/xdg/autostart/',
        os.path.expanduser('~/.config/autostart/'),
    ]
    
    for dir in autostart_dirs:
        if os.path.exists(dir):
            try:
                desktop_files = []
                for f in os.listdir(dir):
                    if f.endswith('.desktop'):
                        fpath = os.path.join(dir, f)
                        file_info = get_file_info(fpath)
                        desktop_files.append({
                            'name': f,
                            'modified': file_info['modified'],
                            'size': f"{file_info['size']} bytes"
                        })
                if desktop_files:
                    results[dir] = desktop_files
            except PermissionError:
                logging.warning(f"Permission denied: {dir}")
    
    return results

# ============================================================================
# MOTD - Malicious Message of the Day for SSH triggers
# Real-World: Persistence in logins
# ============================================================================

def check_motd():
    results = {}
    
    # Check /etc/update-motd.d/
    motd_dir = '/etc/update-motd.d/'
    if os.path.exists(motd_dir):
        try:
            scripts = []
            for f in os.listdir(motd_dir):
                fpath = os.path.join(motd_dir, f)
                if os.path.isfile(fpath):
                    file_info = get_file_info(fpath)
                    scripts.append({
                        'name': f,
                        'modified': file_info['modified'],
                        'executable': 'Yes' if os.access(fpath, os.X_OK) else 'No'
                    })
            if scripts:
                results[motd_dir] = scripts
        except PermissionError:
            logging.warning(f"Permission denied: {motd_dir}")
    
    # Check /etc/motd
    if os.path.exists('/etc/motd'):
        try:
            file_info = get_file_info('/etc/motd')
            results['/etc/motd'] = {
                'modified': file_info['modified'],
                'size': f"{file_info['size']} bytes"
            }
        except PermissionError:
            logging.warning("Permission denied: /etc/motd")
    
    return results

# ============================================================================
# MAIN SCANNER - Orchestrates all checks
# ============================================================================

def scan_linux():
    results = {
        "1. Cron Jobs": check_cron_jobs(),
        "2. Systemd Services (enabled)": check_systemd_units(),
        "3. Systemd Timers (enabled)": check_systemd_timers(),
        "4. Systemd Unit Files": check_systemd_files(),
        "5. RC Scripts & Init.d": check_rc_scripts(),
        "6. Shell Profile Files": check_profile_files(),
        "7. SSH Authorized Keys": check_ssh_keys(),
        "8. Kernel Modules (LKM)": check_kernel_modules(),
        "9. eBPF Programs": check_ebpf(),
        "10. LD_PRELOAD Hijacking": check_ld_preload(),
        "11. Udev Rules": check_udev_rules(),
        "12. PAM Modules": check_pam_modules(),
        "13. At Jobs": check_at_jobs(),
        "14. XDG Autostart": check_autostart(),
        "15. MOTD Scripts": check_motd(),
    }
    
    return results
