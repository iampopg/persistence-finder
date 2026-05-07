#!/usr/bin/env python3
import sys
import argparse
import json
import os
from datetime import datetime
from colorama import Fore, Style

# Support running from project root
sys.path.insert(0, os.path.dirname(__file__))

from core.utils import detect_os, print_results, print_banner, print_section_header, print_summary
from core.system_info import get_system_info, print_system_info

def save_scan(results, sys_info, scan_time):
    scan_dir = os.path.join(os.path.dirname(__file__), 'scans')
    os.makedirs(scan_dir, exist_ok=True)
    filepath = os.path.join(scan_dir, f"scan_{scan_time.strftime('%Y%m%d_%H%M%S')}.json")
    data = {
        'metadata': {
            'scan_time': scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'platform': sys_info['platform'],
            'system_info': sys_info,
        },
        'results': results,
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return filepath

def run_scan(os_type):
    if os_type == 'windows':
        from scanners.windows_scanner import scan_windows
        return scan_windows()
    elif os_type == 'linux':
        from scanners.linux_scanner import scan_linux
        return scan_linux()
    elif os_type == 'darwin':
        from scanners.macos_scanner import scan_macos
        return scan_macos()
    else:
        print(f"{Fore.RED}Unsupported OS: {os_type}{Style.RESET_ALL}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Cross-platform persistence finder')
    parser.add_argument('--json',     action='store_true', help='JSON output only')
    parser.add_argument('--verbose',  action='store_true', help='Show full file contents')
    parser.add_argument('--summary',  action='store_true', help='Show counts only')
    parser.add_argument('--no-save',  action='store_true', help='Do not save results')
    parser.add_argument('--no-web',   action='store_true', help='Skip web viewer prompt')
    args = parser.parse_args()

    sys_info  = get_system_info()
    scan_time = datetime.now()
    os_type   = sys_info['platform'].lower()

    if args.json:
        print(json.dumps(run_scan(os_type), indent=2, default=str))
        return

    print_banner()
    print_system_info(sys_info)
    print_section_header(f"SCANNING {os_type.upper()} PERSISTENCE MECHANISMS", Fore.YELLOW)
    print(f"  {Fore.CYAN}Starting comprehensive scan...{Style.RESET_ALL}\n")

    results = run_scan(os_type)

    print_section_header("DETECTION RESULTS", Fore.GREEN)
    total = print_results(results, verbose=args.verbose, summary=args.summary)
    print_summary(total, os_type)

    if not args.no_save:
        saved = save_scan(results, sys_info, scan_time)
        print(f"\n{Fore.GREEN}✅ Results saved to: {saved}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}💡 Run web UI: python3 web/app.py{Style.RESET_ALL}")

    if not args.no_web:
        print(f"\n{Fore.YELLOW}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}🌐 Launch web interface? Press ENTER (Ctrl+C to skip)...{Style.RESET_ALL}")
        try:
            input()
            import subprocess
            subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), 'web', 'app.py')])
            print(f"{Fore.GREEN}🚀 Web UI started at http://localhost:5000{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Skipped.{Style.RESET_ALL}")
    print()

if __name__ == '__main__':
    main()
