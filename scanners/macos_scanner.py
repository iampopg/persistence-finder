import os
import subprocess
import glob
import plistlib
import logging
from datetime import datetime

def _file_info(path):
    try:
        s = os.stat(path)
        return {
            'modified': datetime.fromtimestamp(s.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'created':  datetime.fromtimestamp(s.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'size':     f"{s.st_size} bytes",
            'permissions': oct(s.st_mode)[-3:],
        }
    except Exception:
        return {}

def _read_plist(path):
    try:
        with open(path, 'rb') as f:
            return plistlib.load(f)
    except Exception:
        try:
            r = subprocess.run(['plutil', '-convert', 'json', '-o', '-', path],
                               capture_output=True, text=True, timeout=5)
            import json
            return json.loads(r.stdout)
        except Exception:
            return {}

def _suspicious_cmd(cmd):
    if not cmd:
        return False
    # Skip if it's a known legit program path
    if _is_legit_program(cmd):
        return False
    import re
    patterns = [
        r'\bcurl\b', r'\bwget\b', r'\bnc \b', r'\bnetcat\b',
        r'/dev/tcp', r'\bbase64\b', r'\beval\b',
        r'\bpython[23]?\b', r'\bruby\b', r'\bperl\b',
        r'\bosascript\b', r'(?<!/var)/tmp/', r'\bchmod \+x\b',
        r'bash -i', r'sh -i',
    ]
    return any(re.search(p, cmd) for p in patterns)

# Known legitimate vendor prefixes — not suspicious
LEGIT_PREFIXES = (
    'com.apple.', 'com.google.', 'com.microsoft.', 'com.adobe.',
    'com.docker.', 'com.dropbox.', 'com.spotify.', 'com.zoom.',
    'com.slack.', 'com.jetbrains.', 'com.github.', 'com.atlassian.',
    'com.vmware.', 'org.virtualbox.', 'com.oracle.',
    'com.1password.', 'com.agilebits.',
)

def _is_legit_label(label):
    return any(label.startswith(p) for p in LEGIT_PREFIXES)

def _is_legit_program(program):
    legit_paths = ('/System/', '/usr/', '/Library/Apple/', '/Applications/', '/sbin/', '/bin/')
    return any(program.startswith(p) for p in legit_paths)

def _run(cmd, timeout=5):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       timeout=timeout).decode(errors='ignore').strip()
    except Exception:
        return ''

# ============================================================================
# 1. LaunchAgents (User & System)
# ============================================================================
def check_launch_agents():
    results = {}
    dirs = [
        os.path.expanduser('~/Library/LaunchAgents'),
        '/Library/LaunchAgents',
        '/System/Library/LaunchAgents',
    ]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.endswith('.plist'):
                continue
            path = os.path.join(d, fname)
            info = _file_info(path)
            plist = _read_plist(path)
            program = plist.get('Program', '') or ' '.join(plist.get('ProgramArguments', []))
            info['program'] = program
            info['run_at_load'] = plist.get('RunAtLoad', False)
            info['label'] = plist.get('Label', fname)
            info['is_suspicious'] = (
                _suspicious_cmd(program) or
                (bool(program) and
                 not _is_legit_program(program) and
                 not _is_legit_label(info.get('label', fname)))
            )
            results[path] = info
    return results

# ============================================================================
# 2. LaunchDaemons (System-wide, root)
# ============================================================================
def check_launch_daemons():
    results = {}
    dirs = ['/Library/LaunchDaemons', '/System/Library/LaunchDaemons']
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.endswith('.plist'):
                continue
            path = os.path.join(d, fname)
            info = _file_info(path)
            plist = _read_plist(path)
            program = plist.get('Program', '') or ' '.join(plist.get('ProgramArguments', []))
            info['program'] = program
            info['run_at_load'] = plist.get('RunAtLoad', False)
            info['label'] = plist.get('Label', fname)
            info['is_suspicious'] = _suspicious_cmd(program)
            results[path] = info
    return results

# ============================================================================
# 3. Login Items (via loginitems / sfltool)
# ============================================================================
def check_login_items():
    results = {}
    # Read BTM database directly — no TCC dialogs, no password prompts
    import plistlib
    btm_paths = [
        os.path.expanduser('~/Library/Application Support/com.apple.backgroundtaskmanagementd/backgrounditems.btm'),
        '/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm',
    ]
    for btm in btm_paths:
        if os.path.isfile(btm):
            info = _file_info(btm)
            try:
                with open(btm, 'rb') as f:
                    data = plistlib.load(f)
                items = data if isinstance(data, list) else []
                info['item_count'] = len(items)
                info['items'] = [str(i.get('name', i)) for i in items[:20] if isinstance(i, dict)]
            except Exception:
                pass
            results[btm] = info
    # Check LaunchAgents for user login items (already covered but add user-specific)
    user_agents = os.path.expanduser('~/Library/LaunchAgents')
    if os.path.isdir(user_agents):
        count = len([f for f in os.listdir(user_agents) if f.endswith('.plist')])
        if count:
            results[user_agents] = {'count': count, 'note': 'See LaunchAgents category for details'}
    return results

# ============================================================================
# 4. Cron Jobs
# ============================================================================
def check_cron_jobs():
    results = {}
    try:
        out = subprocess.check_output(['crontab', '-l'], stderr=subprocess.DEVNULL).decode()
        if out.strip():
            results['user_crontab'] = {'content': out, 'is_suspicious': _suspicious_cmd(out)}
    except Exception:
        pass
    for f in glob.glob('/etc/cron*') + glob.glob('/var/at/tabs/*'):
        if os.path.isfile(f):
            info = _file_info(f)
            try:
                content = open(f).read()
                info['content_preview'] = content[:300]
                info['is_suspicious'] = _suspicious_cmd(content)
            except Exception:
                pass
            results[f] = info
    return results

# ============================================================================
# 5. Shell Profile Files
# ============================================================================
def check_shell_profiles():
    results = {}
    files = [
        os.path.expanduser('~/.zshrc'), os.path.expanduser('~/.zprofile'),
        os.path.expanduser('~/.bash_profile'), os.path.expanduser('~/.bashrc'),
        os.path.expanduser('~/.profile'), '/etc/zshrc', '/etc/profile',
        '/etc/bashrc', '/etc/zsh/zshrc',
    ]
    for f in files:
        if not os.path.isfile(f):
            continue
        info = _file_info(f)
        try:
            content = open(f).read()
            info['is_suspicious'] = _suspicious_cmd(content)
            info['suspicious_commands'] = [p for p in
                ['curl','wget','nc ','base64','eval','exec','osascript','/tmp/']
                if p in content] or None
        except Exception:
            pass
        results[f] = info
    return results

# ============================================================================
# 6. Startup Items (legacy, pre-launchd)
# ============================================================================
def check_startup_items():
    results = {}
    for d in ['/Library/StartupItems', '/System/Library/StartupItems']:
        if os.path.isdir(d):
            for item in os.listdir(d):
                path = os.path.join(d, item)
                results[path] = _file_info(path)
    return results

# ============================================================================
# 7. Kernel Extensions (KEXTs)
# ============================================================================
def check_kernel_extensions():
    results = {}
    kext_dirs = ['/Library/Extensions', '/System/Library/Extensions']
    for d in kext_dirs:
        if not os.path.isdir(d):
            continue
        for kext in os.listdir(d):
            if kext.endswith('.kext'):
                path = os.path.join(d, kext)
                info = _file_info(path)
                # Non-Apple KEXTs are notable
                info['is_suspicious'] = not _is_legit_label(kext)
                results[path] = info
    # Also check loaded kexts
    out = _run(['kextstat'])
    if out:
        loaded = [line.split()[-1] for line in out.splitlines()[1:] if line.strip()]
        third_party = [k for k in loaded if not k.startswith('com.apple.')]
        if third_party:
            results['loaded_third_party_kexts'] = third_party
    return results

# ============================================================================
# 8. System Extensions (DriverKit / modern)
# ============================================================================
def check_system_extensions():
    results = {}
    out = _run(['systemextensionsctl', 'list'])
    if out:
        for line in out.splitlines():
            if line.strip() and not line.startswith('---'):
                results[line.strip()] = {'source': 'systemextensionsctl'}
    return results

# ============================================================================
# 9. SSH Authorized Keys
# ============================================================================
def check_ssh_keys():
    results = {}
    for f in [os.path.expanduser('~/.ssh/authorized_keys'),
              os.path.expanduser('~/.ssh/authorized_keys2'),
              '/root/.ssh/authorized_keys']:
        if not os.path.isfile(f):
            continue
        info = _file_info(f)
        try:
            keys = [l.strip() for l in open(f) if l.strip() and not l.startswith('#')]
            info['key_count'] = len(keys)
            info['keys'] = keys
            info['is_suspicious'] = len(keys) > 0
        except Exception:
            pass
        results[f] = info
    # sshd_config checks
    sshd = '/etc/ssh/sshd_config'
    if os.path.isfile(sshd):
        info = _file_info(sshd)
        content = open(sshd).read()
        warnings = []
        if 'PermitRootLogin yes' in content:
            warnings.append('PermitRootLogin enabled')
        if 'PasswordAuthentication no' not in content:
            warnings.append('Password auth may be enabled')
        info['warnings'] = warnings
        info['is_suspicious'] = bool(warnings)
        results[sshd] = info
    return results

# ============================================================================
# 10. At Jobs
# ============================================================================
def check_at_jobs():
    results = {}
    out = _run(['atq'])
    if out:
        results['at_queue'] = {'content': out}
    at_dir = '/var/at/jobs'
    if os.path.isdir(at_dir):
        try:
            jobs = os.listdir(at_dir)
            if jobs:
                results['at_jobs'] = jobs
        except Exception:
            pass
    return results

# ============================================================================
# 11. Periodic Scripts (daily/weekly/monthly)
# ============================================================================
def check_periodic_scripts():
    results = {}
    for period in ['daily', 'weekly', 'monthly']:
        d = f'/etc/periodic/{period}'
        if os.path.isdir(d):
            scripts = []
            for f in os.listdir(d):
                fpath = os.path.join(d, f)
                info = _file_info(fpath)
                info['name'] = f
                scripts.append(info)
            if scripts:
                results[d] = scripts
    return results

# ============================================================================
# 12. Configuration Profiles (MDM / mobileconfig)
# ============================================================================
def check_config_profiles():
    results = {}
    # profiles list -all requires admin and triggers a password dialog — skip during auto-scan
    # Instead check for .mobileconfig files and the profiles directory directly
    profiles_dir = '/Library/Managed Preferences'
    if os.path.isdir(profiles_dir):
        try:
            files = os.listdir(profiles_dir)
            if files:
                results['managed_preferences'] = {
                    'count': len(files), 'files': files[:20], 'is_suspicious': len(files) > 0
                }
        except Exception:
            pass
    # Check for .mobileconfig files in common locations
    for pattern in [os.path.expanduser('~/Downloads/*.mobileconfig'),
                    '/tmp/*.mobileconfig', '/var/tmp/*.mobileconfig']:
        for f in glob.glob(pattern):
            results[f] = {**_file_info(f), 'is_suspicious': True}
    return results

# ============================================================================
# 13. Emond (Event Monitor Daemon)
# ============================================================================
def check_emond():
    results = {}
    emond_dirs = ['/etc/emond.d/rules/', '/private/var/db/emondClients/']
    for d in emond_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                path = os.path.join(d, f)
                info = _file_info(path)
                info['is_suspicious'] = True  # Emond rules are rare and often abused
                results[path] = info
    return results

# ============================================================================
# 14. XPC Services
# ============================================================================
def check_xpc_services():
    results = {}
    xpc_dirs = [
        os.path.expanduser('~/Library/XPCServices'),
        '/Library/XPCServices',
    ]
    for d in xpc_dirs:
        if os.path.isdir(d):
            for item in os.listdir(d):
                path = os.path.join(d, item)
                results[path] = {**_file_info(path), 'is_suspicious': True}
    return results

# ============================================================================
# 15. Login/Logout Hooks (legacy)
# ============================================================================
def check_login_hooks():
    results = {}
    out = _run(['defaults', 'read', 'com.apple.loginwindow', 'LoginHook'])
    if out:
        results['LoginHook'] = {'command': out, 'is_suspicious': True}
    out2 = _run(['defaults', 'read', 'com.apple.loginwindow', 'LogoutHook'])
    if out2:
        results['LogoutHook'] = {'command': out2, 'is_suspicious': True}
    return results

# ============================================================================
# 16. Dylib Hijacking / DYLD_INSERT_LIBRARIES
# ============================================================================
def check_dylib_hijacking():
    results = {}
    dyld_insert = os.environ.get('DYLD_INSERT_LIBRARIES')
    if dyld_insert:
        results['DYLD_INSERT_LIBRARIES'] = {'value': dyld_insert, 'is_suspicious': True}
    dyld_path = os.environ.get('DYLD_LIBRARY_PATH')
    if dyld_path:
        results['DYLD_LIBRARY_PATH'] = {'value': dyld_path, 'is_suspicious': True}
    # Check for dylib in writable locations next to common apps
    for pattern in ['/Applications/*.app/Contents/MacOS/*.dylib',
                    os.path.expanduser('~/Applications/*.app/Contents/MacOS/*.dylib')]:
        for f in glob.glob(pattern):
            results[f] = {**_file_info(f), 'is_suspicious': True}
    return results

# ============================================================================
# 17. Dock Persistence (via dockutil / plist)
# ============================================================================
def check_dock_items():
    results = {}
    dock_plist = os.path.expanduser('~/Library/Preferences/com.apple.dock.plist')
    if os.path.isfile(dock_plist):
        info = _file_info(dock_plist)
        plist = _read_plist(dock_plist)
        persistent_apps = plist.get('persistent-apps', [])
        items = []
        for app in persistent_apps:
            tile = app.get('tile-data', {})
            label = tile.get('file-label', 'Unknown')
            file_data = tile.get('file-data', {})
            url = file_data.get('_CFURLString', '')
            items.append({'label': label, 'path': url})
        info['persistent_apps_count'] = len(items)
        info['apps'] = items
        results[dock_plist] = info
    return results

# ============================================================================
# 18. Spotlight Importers / mdimporter
# ============================================================================
def check_spotlight_importers():
    results = {}
    dirs = [
        os.path.expanduser('~/Library/Spotlight'),
        '/Library/Spotlight',
    ]
    for d in dirs:
        if os.path.isdir(d):
            for item in os.listdir(d):
                if item.endswith('.mdimporter'):
                    path = os.path.join(d, item)
                    results[path] = {**_file_info(path), 'is_suspicious': True}
    return results

# ============================================================================
# 19. Browser Extensions (Chrome / Safari / Firefox)
# ============================================================================
def check_browser_extensions():
    results = {}
    chrome_ext = os.path.expanduser(
        '~/Library/Application Support/Google/Chrome/Default/Extensions')
    if os.path.isdir(chrome_ext):
        exts = os.listdir(chrome_ext)
        results['chrome_extensions'] = {'count': len(exts), 'ids': exts}

    safari_ext = os.path.expanduser('~/Library/Safari/Extensions')
    if os.path.isdir(safari_ext):
        exts = [f for f in os.listdir(safari_ext) if f.endswith('.safariextz') or f.endswith('.appex')]
        results['safari_extensions'] = {'count': len(exts), 'extensions': exts}

    ff_profiles = glob.glob(os.path.expanduser('~/Library/Application Support/Firefox/Profiles/*/extensions'))
    for ep in ff_profiles:
        if os.path.isdir(ep):
            exts = os.listdir(ep)
            results[f'firefox_extensions ({ep})'] = {'count': len(exts), 'extensions': exts}
    return results

# ============================================================================
# 20. Sudoers / Privilege Escalation
# ============================================================================
def check_sudoers():
    results = {}
    sudoers_files = ['/etc/sudoers'] + glob.glob('/etc/sudoers.d/*')
    for f in sudoers_files:
        if not os.path.isfile(f):
            continue
        info = _file_info(f)
        try:
            content = open(f).read()
            suspicious = 'NOPASSWD' in content or 'ALL=(ALL)' in content
            info['is_suspicious'] = suspicious
            info['has_nopasswd'] = 'NOPASSWD' in content
        except Exception:
            info['is_suspicious'] = False
        results[f] = info
    return results

# ============================================================================
# 21. Installed Applications (non-AppStore, unsigned)
# ============================================================================
def check_installed_apps():
    results = {}
    # Check /Applications directly — faster than system_profiler (no blocking)
    app_dirs = ['/Applications', os.path.expanduser('~/Applications')]
    unsigned = []
    for d in app_dirs:
        if not os.path.isdir(d):
            continue
        for app in os.listdir(d):
            if not app.endswith('.app'):
                continue
            app_path = os.path.join(d, app)
            # Quick codesign check
            try:
                r = subprocess.run(['codesign', '-v', app_path],
                                   capture_output=True, timeout=3)
                if r.returncode != 0:
                    unsigned.append({'name': app, 'path': app_path})
            except Exception:
                unsigned.append({'name': app, 'path': app_path})
    if unsigned:
        results['unsigned_apps'] = unsigned
        results['unsigned_apps_count'] = len(unsigned)
    return results

# ============================================================================
# 22. Quarantine Database (recently downloaded executables)
# ============================================================================
def check_quarantine():
    results = {}
    db_path = os.path.expanduser('~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2')
    if os.path.isfile(db_path):
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("""
                SELECT LSQuarantineDataURLString, LSQuarantineOriginURLString,
                       LSQuarantineTimeStamp, LSQuarantineAgentName
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC LIMIT 50
            """)
            rows = cur.fetchall()
            conn.close()
            results['recent_downloads'] = [
                {'url': r[0], 'origin': r[1], 'timestamp': r[2], 'agent': r[3]}
                for r in rows
            ]
        except Exception as e:
            results['quarantine_db'] = {'error': str(e)}
    return results

# ============================================================================
# MAIN SCANNER
# ============================================================================
def scan_macos():
    return {
        "1. LaunchAgents":            check_launch_agents(),
        "2. LaunchDaemons":           check_launch_daemons(),
        "3. Login Items":             check_login_items(),
        "4. Cron Jobs":               check_cron_jobs(),
        "5. Shell Profile Files":     check_shell_profiles(),
        "6. Startup Items (Legacy)":  check_startup_items(),
        "7. Kernel Extensions":       check_kernel_extensions(),
        "8. System Extensions":       check_system_extensions(),
        "9. SSH Authorized Keys":     check_ssh_keys(),
        "10. At Jobs":                check_at_jobs(),
        "11. Periodic Scripts":       check_periodic_scripts(),
        "12. Config Profiles (MDM)":  check_config_profiles(),
        "13. Emond Rules":            check_emond(),
        "14. XPC Services":           check_xpc_services(),
        "15. Login/Logout Hooks":     check_login_hooks(),
        "16. Dylib Hijacking":        check_dylib_hijacking(),
        "17. Dock Items":             check_dock_items(),
        "18. Spotlight Importers":    check_spotlight_importers(),
        "19. Browser Extensions":     check_browser_extensions(),
        "20. Sudoers":                check_sudoers(),
        "21. Unsigned Applications":  check_installed_apps(),
        "22. Quarantine DB":          check_quarantine(),
    }
