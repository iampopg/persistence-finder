#!/usr/bin/env python3
import sys
import argparse
import json
import os
from datetime import datetime
from utils import detect_os, print_results, print_banner, print_section_header, print_summary
from system_info import get_system_info, print_system_info
from colorama import Fore, Style

def save_scan_to_json(results, sys_info, scan_time):
    """Save scan results to JSON file in scans directory"""
    # Use scans directory in current working directory
    scan_dir = 'scans'
    
    # Create directory
    try:
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir, mode=0o755)
    except Exception as e:
        print(f"{Fore.RED}Error creating directory: {e}{Style.RESET_ALL}")
        return None
    
    # Generate filename
    timestamp = scan_time.strftime('%Y%m%d_%H%M%S')
    filename = f"scan_{timestamp}.json"
    filepath = os.path.join(scan_dir, filename)
    
    # Prepare data
    scan_data = {
        'metadata': {
            'scan_time': scan_time.strftime('%Y-%m-%d %H:%M:%S'),
            'platform': sys_info['platform'],
            'system_info': sys_info
        },
        'results': results
    }
    
    # Save file
    try:
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        return filepath
    except Exception as e:
        print(f"{Fore.RED}Error saving: {e}{Style.RESET_ALL}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Cross-platform persistence finder')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--verbose', action='store_true', help='Show full file contents')
    parser.add_argument('--summary', action='store_true', help='Show only summary (counts)')
    parser.add_argument('--no-save', action='store_true', help='Do not save results to file')
    parser.add_argument('--no-web', action='store_true', help='Do not prompt for web viewer')
    args = parser.parse_args()
    
    # Get and display system information
    sys_info = get_system_info()
    scan_time = datetime.now()
    
    if args.json:
        # JSON mode - no fancy output
        os_type = sys_info['platform'].lower()
        
        if os_type == 'windows':
            from windows_scanner import scan_windows
            results = scan_windows()
        elif os_type == 'linux':
            from linux_scanner import scan_linux
            results = scan_linux()
        else:
            print(json.dumps({"error": f"Unsupported OS: {os_type}"}))
            sys.exit(1)
        
        print(json.dumps(results, indent=2, default=str))
    else:
        # Beautiful colored output
        print_banner()
        print_system_info(sys_info)
        
        os_type = sys_info['platform'].lower()
        
        print_section_header(f"SCANNING {os_type.upper()} PERSISTENCE MECHANISMS", Fore.YELLOW)
        print(f"  {Fore.CYAN}Starting comprehensive scan...{Style.RESET_ALL}\n")
        
        if os_type == 'windows':
            from windows_scanner import scan_windows
            results = scan_windows()
        elif os_type == 'linux':
            from linux_scanner import scan_linux
            results = scan_linux()
        else:
            print(f"{Fore.RED}Unsupported OS: {os_type}{Style.RESET_ALL}")
            sys.exit(1)
        
        print_section_header("DETECTION RESULTS", Fore.GREEN)
        total_findings = print_results(results, verbose=args.verbose, summary=args.summary)
        
        print_summary(total_findings, os_type)
        
        # Save results to JSON file
        if not args.no_save:
            print(f"\n{Fore.CYAN}💾 Saving scan results...{Style.RESET_ALL}")
            saved_file = save_scan_to_json(results, sys_info, scan_time)
            if saved_file:
                print(f"{Fore.GREEN}✅ Results saved to: {saved_file}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}💡 Tip: Use --json flag for machine-readable output{Style.RESET_ALL}")
        print(f"{Fore.CYAN}💡 Run with sudo/admin for complete scanning{Style.RESET_ALL}")
        
        # Prompt to view in web browser
        if not args.no_web:
            print(f"\n{Fore.YELLOW}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}🌐 View results in beautiful web interface?{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   Press ENTER to launch web viewer (or Ctrl+C to skip)...{Style.RESET_ALL}")
            try:
                input()
                print(f"\n{Fore.CYAN}🚀 Launching web viewer...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}   Opening results in browser...{Style.RESET_ALL}\n")
                
                import subprocess
                subprocess.run([sys.executable, 'html_viewer.py'])
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Skipped web viewer{Style.RESET_ALL}")
        
        print()

if __name__ == "__main__":
    main()
