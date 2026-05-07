#!/usr/bin/env python3
import sys, os, json, glob, subprocess, re
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response
import requests

app = Flask(__name__, template_folder='templates', static_folder='static')
SCANS_DIR    = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scans')
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ai_settings.json')

import platform as _plat

# ── OS-aware safe command sets ────────────────────────────────────────────────
_OS = _plat.system().lower()

ALLOWED_BINS_UNIX = {
    'file', 'stat', 'ls', 'cat', 'xxd', 'strings', 'md5', 'shasum', 'sha256sum',
    'lsof', 'ps', 'find', 'grep', 'head', 'tail', 'wc', 'diff', 'cksum',
    'uname', 'whoami', 'id', 'groups', 'sudo',
    # macOS-specific
    'codesign', 'spctl', 'plutil', 'launchctl', 'kextstat', 'sw_vers',
    'security', 'dscl', 'defaults', 'pkgutil', 'otool', 'nm', 'xattr',
    'mdls', 'mdfind', 'log', 'system_profiler',
    # Linux-specific
    'ldd', 'readelf', 'objdump', 'strace', 'ltrace', 'systemctl',
    'journalctl', 'rpm', 'dpkg', 'apt', 'yum', 'ss', 'netstat',
    'lsmod', 'modinfo', 'chkconfig', 'service',
}

ALLOWED_BINS_WINDOWS = {
    'dir', 'type', 'more', 'find', 'findstr', 'where', 'whoami',
    'tasklist', 'sc', 'reg', 'wmic', 'powershell', 'certutil',
    'sigcheck', 'icacls', 'attrib', 'schtasks', 'netstat', 'ipconfig',
    'systeminfo', 'ver', 'fsutil', 'wevtutil',
}

ALLOWED_BINS = ALLOWED_BINS_WINDOWS if _OS == 'windows' else ALLOWED_BINS_UNIX

# Only block commands that MODIFY, DELETE, or make network connections
BLOCKED_PATTERNS_UNIX = [
    'rm ', 'rmdir', 'mv ', 'cp ', 'chmod', 'chown', 'chflags',
    'truncate', 'dd ', 'shred', '> ', '>>', 'tee ',
    'bash -c', 'sh -c', 'zsh -c', 'python -c', 'ruby -e', 'perl -e',
    'eval ', 'exec ',
    'curl', 'wget', 'nc ', 'netcat', 'ncat', 'ssh ', 'scp ', 'sftp',
    'kill ', 'killall', 'pkill',
    'brew install', 'pip install', 'npm install',
    'launchctl load', 'launchctl enable', 'launchctl start',
    '&&', '||', ';', '`', '$(',
]

BLOCKED_PATTERNS_WINDOWS = [
    'del ', 'erase ', 'rd ', 'rmdir', 'move ', 'copy ', 'xcopy ', 'robocopy',
    'format ', 'reg delete', 'reg add', 'reg import',
    'net user', 'net localgroup', 'net share',
    'sc delete', 'sc create', 'sc config',
    'schtasks /create', 'schtasks /delete',
    'curl', 'wget', 'Invoke-WebRequest', 'Invoke-Expression',
    'Start-Process', 'Start-Service', 'Stop-Service',
    '>', '>>', '|', '&&', ';',
]

BLOCKED_PATTERNS = BLOCKED_PATTERNS_WINDOWS if _OS == 'windows' else BLOCKED_PATTERNS_UNIX

# ── Cancel flag for investigations ───────────────────────────────────────────
_cancel_flags = {}  # session_id -> True/False

def load_ai_settings():
    """Load settings. Falls back to example file on first run (no real key)."""
    example = os.path.join(os.path.dirname(SETTINGS_FILE), 'ai_settings.example.json')
    for f in (SETTINGS_FILE, example):
        try:
            with open(f) as fh:
                return json.load(fh)
        except Exception:
            pass
    return {
        'provider': 'ollama', 'endpoint': 'http://localhost:11434',
        'model': '', 'groq_api_key': '',
        'groq_model': 'meta-llama/llama-4-scout-17b-16e-instruct',
    }

def save_ai_settings(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def run_safe_cmd(cmd_str):
    """Validate and run a read-only command. Returns (output, error). OS-aware."""
    cmd_str = cmd_str.strip()
    for b in BLOCKED_PATTERNS:
        if b in cmd_str:
            return None, f'Blocked: {b}'
    parts = cmd_str.split()
    if not parts:
        return None, 'Empty command'

    if _OS == 'windows':
        # Windows: allow powershell as first token, check second
        if parts[0].lower() in ('powershell', 'powershell.exe'):
            check_bin = 'powershell'
        else:
            check_bin = os.path.basename(parts[0]).lower().replace('.exe', '')
    else:
        # Unix: sudo prefix — check actual binary
        check_bin = parts[1] if parts[0] == 'sudo' and len(parts) > 1 else parts[0]
        check_bin = os.path.basename(check_bin)

    if check_bin not in ALLOWED_BINS:
        return None, f'Binary not allowed: {check_bin}'

    try:
        r = subprocess.run(parts, capture_output=True, text=True, timeout=30)
        return (r.stdout + r.stderr)[:8000], None
    except Exception as e:
        return None, str(e)


def load_scans():
    os.makedirs(SCANS_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(SCANS_DIR, 'scan_*.json')), reverse=True)
    scans = []
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
            scans.append({'filename': os.path.basename(f), 'path': f,
                          'metadata': data.get('metadata', {}),
                          'results':  data.get('results', {})})
        except Exception:
            pass
    return scans

def count_findings(results):
    total = suspicious = 0
    for items in results.values():
        if isinstance(items, dict):
            total += len(items)
            suspicious += sum(1 for v in items.values()
                              if isinstance(v, dict) and v.get('is_suspicious'))
        elif isinstance(items, list):
            total += len(items)
    return total, suspicious

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/settings', methods=['GET'])
def api_get_settings():
    return jsonify(load_ai_settings())

@app.route('/api/settings', methods=['POST'])
def api_save_settings():
    data = request.json or {}
    save_ai_settings({
        'provider':     data.get('provider', 'ollama'),
        'endpoint':     data.get('endpoint', 'http://localhost:11434'),
        'model':        data.get('model', ''),
        'groq_api_key': data.get('groq_api_key', ''),
        'groq_model':   data.get('groq_model', 'meta-llama/llama-4-scout-17b-16e-instruct'),
    })
    return jsonify({'ok': True})

@app.route('/api/scans')
def api_scans():
    scans = load_scans()
    out = []
    for s in scans:
        total, suspicious = count_findings(s['results'])
        out.append({'filename': s['filename'],
                    'scan_time': s['metadata'].get('scan_time', ''),
                    'platform':  s['metadata'].get('platform', ''),
                    'total': total, 'suspicious': suspicious})
    return jsonify(out)

@app.route('/api/scan/<filename>')
def api_scan(filename):
    path = os.path.join(SCANS_DIR, filename)
    if not os.path.isfile(path):
        return jsonify({'error': 'Not found'}), 404
    with open(path) as f:
        return jsonify(json.load(f))

@app.route('/api/run-scan', methods=['POST'])
def api_run_scan():
    """Run scanner directly in-process — no subprocess, no password prompt issues."""
    try:
        import platform
        os_type = platform.system().lower()
        if os_type == 'darwin':
            from scanners.macos_scanner import scan_macos
            data = scan_macos()
        elif os_type == 'linux':
            from scanners.linux_scanner import scan_linux
            data = scan_linux()
        elif os_type == 'windows':
            from scanners.windows_scanner import scan_windows
            data = scan_windows()
        else:
            return jsonify({'error': f'Unsupported OS: {os_type}'}), 500

        from core.system_info import get_system_info
        sys_info  = get_system_info()
        scan_time = datetime.now()
        os.makedirs(SCANS_DIR, exist_ok=True)
        fname = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}.json"
        fpath = os.path.join(SCANS_DIR, fname)
        with open(fpath, 'w') as fh:
            json.dump({'metadata': {'scan_time': scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                                    'platform': sys_info['platform'],
                                    'system_info': sys_info},
                       'results': data}, fh, indent=2, default=str)
        return jsonify({'status': 'ok', 'filename': fname})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/run-scan-stream', methods=['GET'])
def api_run_scan_stream():
    """
    Scan category by category.
    If AI endpoint+model provided as query params, pass each category to AI
    before marking items suspicious. Stream every log line live.
    """
    import threading, queue as qmod
    settings = load_ai_settings()
    use_ai   = bool(settings.get('model') or settings.get('groq_api_key'))
    chars_per_batch = (GROQ_SCAN_TOKEN_BUDGET * 4
                       if settings.get('provider') == 'groq'
                       else 90000 * 4)

    q = qmod.Queue()

    def log(msg):          q.put({'type': 'log',    'msg': msg})
    def step(msg):         q.put({'type': 'step',   'msg': msg})
    def ai_in(msg):        q.put({'type': 'ai_in',  'msg': msg})
    def ai_out(msg):       q.put({'type': 'ai_out', 'msg': msg})
    def found(cat, items): q.put({'type': 'found',  'cat': cat, 'items': items})

    def ask_ai(category, items_for_ai):
        if not items_for_ai:
            return {}
        all_verdicts = {}
        batches, cur_batch, cur_chars = [], [], 0
        for path, info in items_for_ai.items():
            if not isinstance(info, dict):
                continue
            prog = info.get('program', '') or info.get('value', '')
            mod  = info.get('modified', '')
            line = f"  {path}"
            if prog: line += f" | program: {str(prog)[:60]}"
            if mod:  line += f" | modified: {mod}"
            if cur_chars + len(line) > chars_per_batch and cur_batch:
                batches.append(cur_batch)
                cur_batch, cur_chars = [], 0
            cur_batch.append((path, line))
            cur_chars += len(line)
        if cur_batch:
            batches.append(cur_batch)

        for b_idx, batch in enumerate(batches):
            lines_text = '\n'.join(line for _, line in batch)
            prompt = (
                f"macOS threat hunter. Analyze [{category}] persistence items (batch {b_idx+1}/{len(batches)}).\n"
                "Identify ONLY genuinely malicious ones. Legitimate Apple/vendor files are NOT suspicious.\n"
                "Reply with a JSON object: each suspicious path maps to {severity, why, technique}.\n"
                "If none are suspicious reply with {}.\n"
                "Output ONLY valid JSON, no markdown, no explanation.\n\n"
                f"ITEMS:\n{lines_text}"
            )
            ai_in(f"[AI ->] [{category}] batch {b_idx+1}/{len(batches)}: {len(batch)} items ({len(lines_text)} chars)")
            try:
                full = call_ai(prompt, settings)
                ai_out(f"[AI <-] [{category}] b{b_idx+1}: {full[:200]}{'...' if len(full)>200 else ''}")

                # Strip markdown fences and <think> tags
                cleaned = re.sub(r'<think>[\s\S]*?</think>', '', full)
                cleaned = re.sub(r'```[a-z]*\n?', '', cleaned).strip()

                # Find the outermost JSON object
                # Use a greedy match from last { to last } to get the full object
                match = re.search(r'(\{[\s\S]*\})', cleaned)
                if match:
                    verdicts = json.loads(match.group(1))
                    if isinstance(verdicts, dict):
                        # Filter out empty-string keys and non-dict values
                        clean_verdicts = {
                            k: v for k, v in verdicts.items()
                            if k and isinstance(v, dict) and v.get('severity')
                        }
                        # Normalize keys: AI may return 'etc/sudoers' instead of '/etc/sudoers'
                        normalized = {}
                        batch_paths = {p for p, _ in batch}
                        for k, v in clean_verdicts.items():
                            # Try exact match first
                            if k in batch_paths:
                                normalized[k] = v
                            else:
                                # Try with leading slash
                                slash_k = '/' + k.lstrip('/')
                                if slash_k in batch_paths:
                                    normalized[slash_k] = v
                                else:
                                    # Try suffix match
                                    for p in batch_paths:
                                        if p.endswith(k) or k.endswith(p.lstrip('/')):
                                            normalized[p] = v
                                            break
                        all_verdicts.update(normalized)
            except Exception as e:
                ai_out(f"[AI ERROR] [{category}] b{b_idx+1}: {e}")
        return all_verdicts

    def do_scan():
        try:
            import platform
            os_type = platform.system().lower()
            step(f"Starting scan on {os_type}…")
            if use_ai:
                step(f"AI triage enabled — {settings.get("provider","ollama")} / {settings.get("model") or settings.get("groq_model","")}")

            # Import scanner functions individually so we can stream per-category
            if os_type == 'darwin':
                from scanners.macos_scanner import (
                    check_launch_agents, check_launch_daemons, check_login_items,
                    check_cron_jobs, check_shell_profiles, check_startup_items,
                    check_kernel_extensions, check_system_extensions, check_ssh_keys,
                    check_at_jobs, check_periodic_scripts, check_config_profiles,
                    check_emond, check_xpc_services, check_login_hooks,
                    check_dylib_hijacking, check_dock_items, check_spotlight_importers,
                    check_browser_extensions, check_sudoers, check_installed_apps,
                    check_quarantine
                )
                categories = [
                    ('1. LaunchAgents',           check_launch_agents),
                    ('2. LaunchDaemons',           check_launch_daemons),
                    ('3. Login Items',             check_login_items),
                    ('4. Cron Jobs',               check_cron_jobs),
                    ('5. Shell Profile Files',     check_shell_profiles),
                    ('6. Startup Items (Legacy)',  check_startup_items),
                    ('7. Kernel Extensions',       check_kernel_extensions),
                    ('8. System Extensions',       check_system_extensions),
                    ('9. SSH Authorized Keys',     check_ssh_keys),
                    ('10. At Jobs',                check_at_jobs),
                    ('11. Periodic Scripts',       check_periodic_scripts),
                    ('12. Config Profiles (MDM)',  check_config_profiles),
                    ('13. Emond Rules',            check_emond),
                    ('14. XPC Services',           check_xpc_services),
                    ('15. Login/Logout Hooks',     check_login_hooks),
                    ('16. Dylib Hijacking',        check_dylib_hijacking),
                    ('17. Dock Items',             check_dock_items),
                    ('18. Spotlight Importers',    check_spotlight_importers),
                    ('19. Browser Extensions',     check_browser_extensions),
                    ('20. Sudoers',                check_sudoers),
                    ('21. Unsigned Applications',  check_installed_apps),
                    ('22. Quarantine DB',          check_quarantine),
                ]
            else:
                q.put({'type': 'error', 'msg': f'Unsupported OS: {os_type}'})
                return

            all_results = {}
            total_items = 0
            total_suspicious = 0

            for cat_name, cat_fn in categories:
                step(f"Scanning: {cat_name}")
                try:
                    cat_results = cat_fn()
                except Exception as e:
                    log(f"  ERROR in {cat_name}: {e}")
                    cat_results = {}

                item_count = len(cat_results) if isinstance(cat_results, dict) else len(cat_results) if isinstance(cat_results, list) else 0
                log(f"  Found {item_count} items in {cat_name}")

                if use_ai and isinstance(cat_results, dict) and item_count > 0:
                    # Only pass dict items to AI (lists are informational)
                    dict_items = {k: v for k, v in cat_results.items() if isinstance(v, dict)}
                    if dict_items:
                        verdicts = ask_ai(cat_name, dict_items)
                        for path, info in cat_results.items():
                            if not isinstance(info, dict):
                                continue
                            if path in verdicts:
                                v = verdicts[path]
                                info['is_suspicious'] = True
                                info['ai_severity']   = v.get('severity', 'Medium')
                                info['ai_why']        = v.get('why', '')
                                info['ai_technique']  = v.get('technique', '')
                                log(f"  ⚠ AI flagged: {path} [{v.get('severity','?')}] {v.get('why','')}")
                                total_suspicious += 1
                            else:
                                info['is_suspicious'] = False
                        log(f"  AI verdict: {len(verdicts)} real threats in {cat_name}")
                    else:
                        log(f"  Skipping AI for {cat_name} (no dict items)")
                else:
                    # No AI — use scanner's own is_suspicious flags
                    if isinstance(cat_results, dict):
                        for info in cat_results.values():
                            if isinstance(info, dict) and info.get('is_suspicious'):
                                total_suspicious += 1

                all_results[cat_name] = cat_results
                total_items += item_count
                found(cat_name, item_count)

            step(f"Scan complete. {total_items} items scanned, {total_suspicious} suspicious.")

            from core.system_info import get_system_info
            sys_info  = get_system_info()
            scan_time = datetime.now()
            os.makedirs(SCANS_DIR, exist_ok=True)
            fname = f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}.json"
            fpath = os.path.join(SCANS_DIR, fname)
            with open(fpath, 'w') as fh:
                json.dump({'metadata': {'scan_time': scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                                        'platform': sys_info['platform'],
                                        'system_info': sys_info},
                           'results': all_results}, fh, indent=2, default=str)
            q.put({'type': 'done', 'filename': fname,
                   'total': total_items, 'suspicious': total_suspicious})
        except Exception as e:
            q.put({'type': 'error', 'msg': str(e)})

    threading.Thread(target=do_scan, daemon=True).start()

    def generate():
        while True:
            try:
                msg = q.get(timeout=1800)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg['type'] in ('done', 'error'):
                    break
            except Exception:
                yield f"data: {json.dumps({'type':'error','msg':'Scan timed out'})}\n\n"
                break

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/ai-models', methods=['POST'])
def api_ai_models():
    body = request.json or {}
    provider = body.get('provider', 'ollama')
    if provider == 'groq':
        return jsonify({'models': GROQ_MODELS})
    base = body.get('endpoint', 'http://localhost:11434')
    base = base.replace('/api/generate', '').replace('/api/chat', '').rstrip('/')
    try:
        r = requests.get(f"{base}/api/tags", timeout=5)
        models = [m['name'] for m in r.json().get('models', [])]
        return jsonify({'models': models})
    except Exception as e:
        return jsonify({'error': str(e), 'models': []})


@app.route('/api/ai-analyze-scan', methods=['POST'])
def api_ai_analyze_scan():
    body          = request.json or {}
    settings      = body.get('settings', load_ai_settings())
    items_text    = body.get('items_text', '')
    batch_num     = body.get('batch_num', 1)
    total_batches = body.get('total_batches', 1)

    if not items_text:
        return jsonify({'threats': []})

    prompt = (
        f"macOS malware analyst. Batch {batch_num}/{total_batches}.\n"
        "Find ONLY genuinely malicious persistence items. Skip all legitimate Apple/system files.\n"
        "Suspicious: /tmp/ paths, curl/wget/base64 in programs, unknown vendors, non-standard locations.\n"
        "Output a JSON array. Each threat: "
        '{"path":"/x","severity":"Critical|High|Medium|Low","title":"name","why":"reason","technique":"MITRE or empty","investigate_cmd":"safe shell cmd"}\n'
        "Empty array [] if no threats. Output ONLY the JSON array, nothing else.\n\n"
        f"ITEMS:\n{items_text}"
    )

    full = ''
    try:
        full = call_ai(prompt, settings)

        # Strip think tags and markdown fences
        import re as _re
        cleaned = _re.sub(r'<think>[\s\S]*?</think>', '', full, flags=_re.DOTALL)
        cleaned = _re.sub(r'```[a-zA-Z]*', '', cleaned).strip().strip('`').strip()

        # Find first complete [...] block using bracket counting
        depth, start = 0, None
        json_str = None
        for i, ch in enumerate(cleaned):
            if ch == '[':
                if start is None: start = i
                depth += 1
            elif ch == ']' and start is not None:
                depth -= 1
                if depth == 0:
                    json_str = cleaned[start:i+1]
                    break

        if not json_str:
            return jsonify({'threats': [], 'raw': full[:300]})

        threats = json.loads(json_str)
        if not isinstance(threats, list):
            return jsonify({'threats': []})

        valid = [
            t for t in threats
            if isinstance(t, dict) and t.get('path') and t.get('severity')
               and t.get('severity') in ('Critical', 'High', 'Medium', 'Low')
        ]
        return jsonify({'threats': valid})
    except Exception as e:
        return jsonify({'error': str(e), 'threats': [], 'raw': full[:300]})



@app.route('/api/ai-batch', methods=['POST'])
def api_ai_batch():
    """Triage a batch of suspicious items. Returns JSON array of real threats only."""
    body     = request.json or {}
    endpoint = body.get('endpoint', 'http://localhost:11434/api/generate')
    model    = body.get('model', '')
    items    = body.get('items', [])  # list of {path, category, program, modified}

    if not items:
        return jsonify({'threats': []})

    # Build compact batch text
    lines = []
    for it in items:
        line = f"  {it.get('path','?')}"
        if it.get('program'): line += f" | prog:{it['program'][:60]}"
        if it.get('modified'): line += f" | mod:{it['modified']}"
        lines.append(line)
    batch_text = '\n'.join(lines)

    prompt = (
        "You are a macOS threat hunter. Below is a list of persistence items flagged as suspicious.\n"
        "Many are false positives (legitimate Apple/system files). Your job: identify ONLY the ones\n"
        "that are genuinely suspicious or malicious (not standard Apple system files).\n"
        "For each REAL threat output a JSON object with:\n"
        "  path, severity (Critical/High/Medium/Low), why (1 sentence), technique (MITRE if known),\n"
        "  investigate_cmd (one safe read-only shell command to inspect it)\n"
        "Output ONLY a JSON array. If all are false positives output [].\n\n"
        f"ITEMS:\n{batch_text}"
    )

    def generate():
        try:
            resp = requests.post(endpoint, json={'model': model, 'prompt': prompt,
                                                  'stream': True}, stream=True, timeout=180)
            for line in resp.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        token = chunk.get('response', '')
                        if token:
                            yield f"data: {json.dumps({'token': token})}\n\n"
                        if chunk.get('done'):
                            yield "data: [DONE]\n\n"
                            return
                    except Exception:
                        pass
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/ai-analyze', methods=['POST'])
def api_ai_analyze():
    body     = request.json or {}
    endpoint = body.get('endpoint', 'http://localhost:11434/api/generate')
    model    = body.get('model', '')
    findings = body.get('findings', '')   # pre-chunked by client

    prompt = (
        "You are a macOS threat hunter. Analyze these persistence mechanism findings.\n"
        "For each item, output a JSON array of threat objects with fields:\n"
        "  id (short slug), severity (Critical/High/Medium/Low), title, path,\n"
        "  why (1 sentence why it's suspicious), technique (MITRE ATT&CK if applicable),\n"
        "  investigate_cmd (single safe read-only shell command to inspect it).\n"
        "Output ONLY valid JSON array, no markdown, no explanation outside the array.\n\n"
        f"FINDINGS:\n{findings}"
    )

    def generate():
        try:
            resp = requests.post(endpoint, json={'model': model, 'prompt': prompt,
                                                  'stream': True}, stream=True, timeout=180)
            for line in resp.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line)
                        token = chunk.get('response', '')
                        if token:
                            yield f"data: {json.dumps({'token': token})}\n\n"
                        if chunk.get('done'):
                            yield "data: [DONE]\n\n"
                            return
                    except Exception:
                        pass
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/api/cancel-investigate', methods=['POST'])
def api_cancel_investigate():
    body = request.json or {}
    sid  = body.get('session_id', '')
    if sid:
        _cancel_flags[sid] = True
    return jsonify({'ok': True})


@app.route('/api/ai-investigate', methods=['POST'])
def api_ai_investigate():
    """
    AI-driven investigation loop using thread+queue (same pattern as scan stream).
    AI suggests commands -> we run them -> AI analyses output -> verdict.
    """
    import threading, queue as qmod, uuid as _uuid
    body      = request.json or {}
    item_path = body.get('path', '')
    context   = body.get('context', '')
    session_id = body.get('session_id', _uuid.uuid4().hex)
    settings  = load_ai_settings()
    _cancel_flags[session_id] = False

    # Validate AI is configured
    provider = settings.get('provider', 'ollama')
    has_ai = (provider == 'groq' and settings.get('groq_api_key')) or \
             (provider == 'ollama' and settings.get('model'))
    if not has_ai:
        return jsonify({'error': 'No AI configured. Go to Settings tab and save your AI settings.'}), 400

    q = qmod.Queue()

    def do_investigate():
        def emit(type_, **kw):
            q.put({'type': type_, **kw})

        def cancelled():
            return _cancel_flags.get(session_id, False)

        emit('session', session_id=session_id)
        emit('log', msg=f'Path: {item_path}')
        emit('log', msg=f'Context: {context or "none"}')
        emit('log', msg=f'Provider: {provider} | Model: {settings.get("groq_model") or settings.get("model")}')

        history = []
        max_rounds = 6

        for round_num in range(1, max_rounds + 1):
            if cancelled():
                emit('log', msg='Investigation cancelled by user.')
                emit('verdict', malicious=False, suspicious=False, msg='Cancelled')
                q.put({'type': '__done__'})
                return
            emit('step', msg=f'Round {round_num}/{max_rounds} — asking AI what to investigate…')

            history_text = chr(10).join(history[-8:])
            prompt = (
                f"You are a macOS malware analyst investigating a persistence item.\n"
                f"Item: {item_path}\n"
                f"Why flagged: {context}\n"
                f"\nPrevious investigation steps:\n{history_text}\n"
                f"\nRound {round_num}/{max_rounds}. Based on what you know so far, decide:\n"
                f"- If you need more info: reply CMD: <one shell command, no pipes/redirection>\n"
                f"  You may use sudo for read-only inspection (e.g. sudo cat, sudo ls, sudo codesign)\n"
                f"  Available: file, stat, ls, cat, xxd, strings, codesign, spctl, plutil, lsof,\n"
                f"             ps, launchctl, defaults, pkgutil, otool, xattr, mdls, security,\n"
                f"             sudo <any of the above>\n"
                f"- If clearly malicious: reply VERDICT: MALICIOUS <reason>\n"
                f"- If clearly clean/legitimate: reply VERDICT: CLEAN <reason>\n"
                f"- If inconclusive after investigation: reply VERDICT: SUSPICIOUS <reason>\n"
                f"Reply with exactly one line starting with CMD: or VERDICT:"
            )

            try:
                ai_reply = call_ai(prompt, settings).strip()
            except Exception as e:
                emit('log', msg=f'AI error: {e}')
                break

            # Strip thinking tags (deepseek-r1 style)
            clean = re.sub(r'<think>.*?</think>', '', ai_reply, flags=re.DOTALL).strip()
            # Find CMD: or VERDICT: line
            for line in clean.splitlines():
                line = line.strip()
                if line.startswith('CMD:') or line.startswith('VERDICT:'):
                    clean = line
                    break

            emit('ai_out', msg=f'AI → {clean}')

            if clean.upper().startswith('VERDICT:'):
                verdict = clean[8:].strip()
                upper = verdict.upper()
                malicious = upper.startswith('MALICIOUS')
                suspicious = upper.startswith('SUSPICIOUS')
                emit('verdict', malicious=malicious, suspicious=suspicious, msg=verdict)
                q.put({'type': '__done__'})
                return

            if clean.upper().startswith('CMD:'):
                cmd_str = clean[4:].strip()
                emit('cmd', msg=cmd_str)
                output, err = run_safe_cmd(cmd_str)
                if err:
                    emit('blocked', msg=f'Blocked: {err}')
                    history.append(f"CMD: {cmd_str}\nBLOCKED: {err}")
                else:
                    out_text = output or '(no output)'
                    emit('output', msg=out_text)
                    history.append(f"CMD: {cmd_str}\nOUTPUT: {out_text[:800]}")
            else:
                emit('log', msg=f'Unexpected reply format, retrying…')
                history.append(f"Round {round_num}: AI gave unexpected reply: {clean[:100]}")

        emit('verdict', malicious=False, suspicious=True,
             msg=f'Investigation complete after {max_rounds} rounds — review findings above')
        q.put({'type': '__done__'})

    threading.Thread(target=do_investigate, daemon=True).start()

    def generate():
        while True:
            try:
                msg = q.get(timeout=120)
                if msg.get('type') == '__done__':
                    break
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') == 'verdict':
                    break
            except Exception:
                yield f"data: {json.dumps({'type':'log','msg':'Timed out'})}\n\n"
                break

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/run-cmd', methods=['POST'])
def api_run_cmd():
    body = request.json or {}
    cmd_str = body.get('cmd', '').strip()
    output, err = run_safe_cmd(cmd_str)
    if err:
        return jsonify({'error': err}), 400
    return jsonify({'cmd': cmd_str, 'stdout': output})


@app.route('/api/report', methods=['POST'])
def api_report():
    body     = request.json or {}
    scan     = body.get('scan', {})
    threats  = body.get('threats', [])
    metadata = scan.get('metadata', {})
    results  = scan.get('results', {})

    total, suspicious = count_findings(results)
    critical = sum(1 for t in threats if t.get('severity') == 'Critical')
    high     = sum(1 for t in threats if t.get('severity') == 'High')
    sev_color = {'Critical': '#f85149', 'High': '#d29922', 'Medium': '#58a6ff', 'Low': '#3fb950'}

    # AI threat cards
    threat_html = ''
    for t in threats:
        col = sev_color.get(t.get('severity', 'Low'), '#8b949e')
        threat_html += f"""
        <div class="tcard" style="border-left:4px solid {col}">
          <div class="tcard-top">
            <span class="tbadge" style="background:{col}22;color:{col}">{t.get('severity','?')}</span>
            <strong style="font-size:0.9rem">{t.get('title','')}</strong>
          </div>
          <div class="tpath">{t.get('path','')}</div>
          <div class="twhy">{t.get('why','')}</div>
          {('<div class="tmitre">MITRE: ' + t.get('technique','') + '</div>') if t.get('technique') else ''}
        </div>"""

    # Findings summary table rows
    findings_rows = ''
    for cat, items in results.items():
        if not items or not isinstance(items, dict):
            continue
        susp_items = [(k, v) for k, v in items.items() if isinstance(v, dict) and v.get('is_suspicious')]
        for k, v in susp_items:
            prog = v.get('program', '') or v.get('value', '')
            findings_rows += f"""<tr>
              <td>{cat}</td>
              <td style="font-family:monospace;font-size:0.78rem;word-break:break-all">{k}</td>
              <td style="font-size:0.78rem;color:#8b949e">{str(prog)[:80]}</td>
              <td style="font-size:0.78rem;color:#8b949e">{v.get('modified','')}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Persistence Finder Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:40px 48px}}
h1{{font-size:1.8rem;color:#58a6ff;margin-bottom:6px}}
.meta{{color:#8b949e;font-size:0.85rem;margin-bottom:36px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:36px}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;text-align:center}}
.stat .n{{font-size:2.2rem;font-weight:700}}
.stat .l{{font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-top:4px}}
.sec{{font-size:1rem;font-weight:700;color:#58a6ff;border-bottom:1px solid #30363d;
  padding-bottom:8px;margin:32px 0 16px}}
.tcard{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin-bottom:10px}}
.tcard-top{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
.tbadge{{padding:2px 10px;border-radius:20px;font-size:0.7rem;font-weight:700}}
.tpath{{font-family:monospace;font-size:0.75rem;color:#8b949e;margin-bottom:5px;word-break:break-all}}
.twhy{{font-size:0.82rem;color:#c9d1d9;line-height:1.5}}
.tmitre{{font-size:0.72rem;color:#58a6ff;margin-top:5px}}
table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
th{{background:#161b22;padding:10px 12px;text-align:left;font-size:0.7rem;
  text-transform:uppercase;letter-spacing:0.8px;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.footer{{text-align:center;margin-top:40px;color:#8b949e;font-size:0.78rem;border-top:1px solid #30363d;padding-top:20px}}
@media print{{body{{background:#fff;color:#000;padding:20px}}
  .stat,.tcard{{background:#f6f8fa;border-color:#d0d7de}}
  h1,.sec{{color:#0969da}}}}
</style>
</head>
<body>
  <h1>🔍 Persistence Finder Report</h1>
  <div class="meta">
    Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp;
    Platform: {metadata.get('platform','Unknown')} &nbsp;·&nbsp;
    Scan time: {metadata.get('scan_time','')}
  </div>

  <div class="stats">
    <div class="stat"><div class="n" style="color:#f85149">{suspicious}</div><div class="l">Suspicious</div></div>
    <div class="stat"><div class="n" style="color:#58a6ff">{total}</div><div class="l">Total Findings</div></div>
    <div class="stat"><div class="n" style="color:#f85149">{critical}</div><div class="l">Critical (AI)</div></div>
    <div class="stat"><div class="n" style="color:#d29922">{high}</div><div class="l">High (AI)</div></div>
  </div>

  {('<div class="sec">🤖 AI-Identified Threats</div>' + threat_html) if threats else '<div class="sec" style="color:#8b949e">No AI analysis run yet — open the app and use the AI Analysis tab.</div>'}

  <div class="sec">⚠ All Suspicious Findings</div>
  <table>
    <thead><tr><th>Category</th><th>Path / Item</th><th>Program</th><th>Modified</th></tr></thead>
    <tbody>{findings_rows or '<tr><td colspan=4 style="color:#8b949e;text-align:center;padding:20px">No suspicious findings</td></tr>'}</tbody>
  </table>

  <div class="footer">Persistence Finder &nbsp;·&nbsp; Read-only security scan &nbsp;·&nbsp; For authorized use only</div>
</body>
</html>"""
    return Response(html, mimetype='text/html')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5001)
    args = parser.parse_args()
    print("🔍 Persistence Finder Web UI")
    print(f"🌐 Open: http://localhost:{args.port}")
    app.run(debug=False, host='0.0.0.0', port=args.port, threaded=True)
