import platform
import os
import sys
import subprocess
from colorama import Fore, Style

def get_system_info():
    """Gather comprehensive system information"""
    info = {
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'python_version': sys.version.split()[0],
        'is_admin': is_admin(),
    }
    
    # OS-specific details
    if info['platform'] == 'Linux':
        info.update(get_linux_details())
    elif info['platform'] == 'Windows':
        info.update(get_windows_details())
    elif info['platform'] == 'Darwin':
        info.update(get_macos_details())
    
    return info

def is_admin():
    """Check if running with elevated privileges"""
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def get_linux_details():
    """Get Linux distribution details"""
    details = {}
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    if key in ['NAME', 'VERSION', 'ID', 'VERSION_ID']:
                        details[f'linux_{key.lower()}'] = value.strip('"')
    except:
        pass
    
    # Kernel version
    try:
        details['kernel'] = platform.release()
    except:
        pass
    
    return details

def get_windows_details():
    """Get Windows edition and build details"""
    details = {}
    try:
        details['windows_edition'] = platform.win32_edition()
        details['windows_version'] = platform.win32_ver()[0]
        details['windows_build'] = platform.win32_ver()[1]
    except:
        pass
    
    return details

def get_macos_details():
    """Get macOS version details"""
    details = {}
    try:
        mac_ver = platform.mac_ver()
        details['macos_version'] = mac_ver[0]
        details['macos_arch'] = mac_ver[2]
    except:
        pass
    
    return details

def print_system_info(info):
    """Print system information in readable format"""
    from colorama import Fore, Style
    
    print(Fore.CYAN + Style.BRIGHT + "="*70)
    print(Fore.CYAN + Style.BRIGHT + "  SYSTEM INFORMATION")
    print(Fore.CYAN + Style.BRIGHT + "="*70 + Style.RESET_ALL)
    print(f"  {Fore.YELLOW}Platform:{Style.RESET_ALL} {Fore.WHITE}{info['platform']} {info.get('platform_release', '')}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Architecture:{Style.RESET_ALL} {Fore.WHITE}{info['architecture']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Python:{Style.RESET_ALL} {Fore.WHITE}{info['python_version']}{Style.RESET_ALL}")
    
    if info['is_admin']:
        print(f"  {Fore.YELLOW}Privileges:{Style.RESET_ALL} {Fore.GREEN}✓ Admin/Root{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}Privileges:{Style.RESET_ALL} {Fore.RED}✗ Standard User{Style.RESET_ALL}")
    
    if info['platform'] == 'Linux':
        print(f"  {Fore.YELLOW}Distribution:{Style.RESET_ALL} {Fore.WHITE}{info.get('linux_name', 'Unknown')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Version:{Style.RESET_ALL} {Fore.WHITE}{info.get('linux_version', 'Unknown')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Kernel:{Style.RESET_ALL} {Fore.WHITE}{info.get('kernel', 'Unknown')}{Style.RESET_ALL}")
    elif info['platform'] == 'Windows':
        print(f"  {Fore.YELLOW}Edition:{Style.RESET_ALL} {Fore.WHITE}{info.get('windows_edition', 'Unknown')}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Build:{Style.RESET_ALL} {Fore.WHITE}{info.get('windows_build', 'Unknown')}{Style.RESET_ALL}")
    elif info['platform'] == 'Darwin':
        print(f"  {Fore.YELLOW}macOS Version:{Style.RESET_ALL} {Fore.WHITE}{info.get('macos_version', 'Unknown')}{Style.RESET_ALL}")
    
    if not info['is_admin']:
        print(f"\n  {Fore.RED}⚠️  WARNING: Not running with elevated privileges!{Style.RESET_ALL}")
        print(f"  {Fore.RED}   Some persistence mechanisms may not be detected.{Style.RESET_ALL}")
    
    print(Fore.CYAN + Style.BRIGHT + "="*70 + Style.RESET_ALL)

if __name__ == "__main__":
    info = get_system_info()
    print_system_info(info)
