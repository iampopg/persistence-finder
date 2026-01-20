import logging
import platform
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def detect_os():
    return platform.system().lower()

def print_banner():
    """Print ASCII art banner"""
    try:
        import pyfiglet
        banner = pyfiglet.figlet_format("PERSISTENCE\nFINDER", font="slant")
        print(Fore.CYAN + Style.BRIGHT + banner)
    except ImportError:
        print(Fore.CYAN + Style.BRIGHT + "="*70)
        print(Fore.CYAN + Style.BRIGHT + "    PERSISTENCE FINDER - Cross-Platform Detection Tool")
        print(Fore.CYAN + Style.BRIGHT + "="*70)

def print_section_header(title, color=Fore.YELLOW):
    """Print a colored section header"""
    print("\n" + color + Style.BRIGHT + "="*70)
    print(color + Style.BRIGHT + f"  {title}")
    print(color + Style.BRIGHT + "="*70 + Style.RESET_ALL)

def print_subsection(title, color=Fore.CYAN):
    """Print a colored subsection header"""
    print("\n" + color + Style.BRIGHT + f"[+] {title}" + Style.RESET_ALL)
    print(color + "-" * 70 + Style.RESET_ALL)

def print_item(key, value, indent=2, verbose=False):
    """Print a key-value item with color"""
    spaces = " " * indent
    
    if isinstance(value, list):
        # Check if list contains dicts (structured data)
        if value and isinstance(value[0], dict):
            print(f"{spaces}{Fore.GREEN}• {Fore.CYAN}{key}:{Style.RESET_ALL} {Fore.YELLOW}[{len(value)} items]{Style.RESET_ALL}")
            for item in value:
                if isinstance(item, dict):
                    # Display dict items nicely
                    name = item.get('name', 'Unknown')
                    modified = item.get('modified', 'N/A')
                    size = item.get('size', '')
                    print(f"{spaces}  {Fore.CYAN}{name}{Style.RESET_ALL}")
                    print(f"{spaces}    {Fore.YELLOW}Modified:{Style.RESET_ALL} {Fore.WHITE}{modified}{Style.RESET_ALL}  {Fore.YELLOW}Size:{Style.RESET_ALL} {Fore.WHITE}{size}{Style.RESET_ALL}")
                else:
                    print(f"{spaces}  {Fore.WHITE}- {item}{Style.RESET_ALL}")
        else:
            print(f"{spaces}{Fore.GREEN}• {Fore.CYAN}{key}:{Style.RESET_ALL} {Fore.YELLOW}[{len(value)} items]{Style.RESET_ALL}")
            for item in value:
                print(f"{spaces}  {Fore.WHITE}- {item}{Style.RESET_ALL}")
    elif isinstance(value, dict):
        # Check if this is a suspicious item
        is_suspicious = value.get('is_suspicious', False)
        key_color = Fore.RED if is_suspicious else Fore.CYAN
        
        print(f"{spaces}{Fore.GREEN}• {key_color}{key}:{Style.RESET_ALL}")
        if is_suspicious:
            print(f"{spaces}  {Fore.RED}⚠️  SUSPICIOUS COMMANDS DETECTED!{Style.RESET_ALL}")
        
        for k, v in value.items():
            if k == 'is_suspicious':  # Skip internal flag
                continue
            elif k == 'suspicious_commands' and v and v != 'None':
                # Highlight suspicious commands in red
                print(f"{spaces}  {Fore.YELLOW}{k}:{Style.RESET_ALL} {Fore.RED}{v}{Style.RESET_ALL}")
            elif isinstance(v, list):
                print(f"{spaces}  {Fore.YELLOW}{k}:{Style.RESET_ALL}")
                for item in v:
                    if isinstance(item, str) and len(item) > 100:
                        print(f"{spaces}    {Fore.WHITE}{item[:100]}...{Style.RESET_ALL}")
                    else:
                        print(f"{spaces}    {Fore.WHITE}{item}{Style.RESET_ALL}")
            elif isinstance(v, dict):
                print(f"{spaces}  {Fore.YELLOW}{k}:{Style.RESET_ALL}")
                for dk, dv in v.items():
                    print(f"{spaces}    {Fore.CYAN}{dk}:{Style.RESET_ALL} {Fore.WHITE}{dv}{Style.RESET_ALL}")
            else:
                print(f"{spaces}  {Fore.YELLOW}{k}:{Style.RESET_ALL} {Fore.WHITE}{v}{Style.RESET_ALL}")
    elif isinstance(value, str) and len(value) > 200 and not verbose:
        # For long strings (like file contents), show preview unless verbose
        lines = value.split('\n')
        print(f"{spaces}{Fore.GREEN}• {Fore.CYAN}{key}:{Style.RESET_ALL} {Fore.YELLOW}[{len(lines)} lines, {len(value)} bytes]{Style.RESET_ALL}")
        # Show first few non-empty lines
        shown = 0
        for line in lines:
            if line.strip() and not line.strip().startswith('#'):
                print(f"{spaces}  {Fore.WHITE}{line[:100]}{Style.RESET_ALL}")
                shown += 1
                if shown >= 3:
                    print(f"{spaces}  {Fore.YELLOW}... (use --verbose for full content){Style.RESET_ALL}")
                    break
    else:
        print(f"{spaces}{Fore.GREEN}• {Fore.CYAN}{key}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")

def print_results(results, verbose=False, summary=False):
    """Print scan results with beautiful formatting"""
    total_findings = 0
    
    for category, items in results.items():
        if items:  # Only show categories with findings
            print_subsection(category)
            
            if isinstance(items, list):
                if items:
                    total_findings += len(items)
                    if summary:
                        print(f"  {Fore.CYAN}Found {len(items)} items{Style.RESET_ALL}")
                    else:
                        for item in items:  # Show ALL items
                            print(f"  {Fore.WHITE}• {item}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.GREEN}✓ No items found{Style.RESET_ALL}")
            elif isinstance(items, dict):
                if items:
                    total_findings += len(items)
                    if summary:
                        print(f"  {Fore.CYAN}Found {len(items)} items{Style.RESET_ALL}")
                    else:
                        for key, value in items.items():  # Show ALL items
                            print_item(key, value, verbose=verbose)
                else:
                    print(f"  {Fore.GREEN}✓ No items found{Style.RESET_ALL}")
            else:
                total_findings += 1
                print(f"  {Fore.WHITE}{items}{Style.RESET_ALL}")
    
    return total_findings

def print_summary(total_findings, os_type):
    """Print scan summary"""
    print_section_header("SCAN SUMMARY", Fore.MAGENTA)
    print(f"  {Fore.CYAN}Platform:{Style.RESET_ALL} {Fore.WHITE}{os_type.upper()}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total Findings:{Style.RESET_ALL} {Fore.YELLOW}{total_findings}{Style.RESET_ALL}")
    
    if total_findings > 0:
        print(f"\n  {Fore.YELLOW}⚠️  Review findings in the output above{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}⚠️  Not all findings are malicious - verify each entry{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}✓ No persistence mechanisms detected{Style.RESET_ALL}")
    
    print(Fore.MAGENTA + Style.BRIGHT + "="*70 + Style.RESET_ALL)
