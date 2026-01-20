"""
Integration with external open-source tools
"""
import os
import json
import hashlib

# ============================================================================
# VirusTotal Integration
# ============================================================================
def check_virustotal(file_hash, api_key=None):
    """Check file hash against VirusTotal (requires API key)"""
    if not api_key:
        api_key = os.environ.get('VT_API_KEY')
    
    if not api_key:
        return {'error': 'No API key provided'}
    
    try:
        import requests
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'vt_link': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        elif response.status_code == 404:
            return {'status': 'not_found'}
        else:
            return {'error': f'HTTP {response.status_code}'}
    except ImportError:
        return {'error': 'requests library not installed'}
    except Exception as e:
        return {'error': str(e)}

# ============================================================================
# YARA Integration
# ============================================================================
def scan_with_yara(file_path, rules_path='rules/'):
    """Scan file with YARA rules"""
    try:
        import yara
        
        # Compile all .yar files in rules directory
        if os.path.isdir(rules_path):
            rule_files = {f: os.path.join(rules_path, f) 
                         for f in os.listdir(rules_path) 
                         if f.endswith('.yar')}
            rules = yara.compile(filepaths=rule_files)
        else:
            rules = yara.compile(filepath=rules_path)
        
        matches = rules.match(file_path)
        
        return {
            'matched': len(matches) > 0,
            'rules': [m.rule for m in matches],
            'tags': [tag for m in matches for tag in m.tags]
        }
    except ImportError:
        return {'error': 'yara-python not installed'}
    except Exception as e:
        return {'error': str(e)}

# ============================================================================
# PE File Analysis
# ============================================================================
def analyze_pe(file_path):
    """Analyze PE file structure"""
    try:
        import pefile
        
        pe = pefile.PE(file_path)
        
        return {
            'machine': pe.FILE_HEADER.Machine,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'sections': len(pe.sections),
            'imports': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            'exports': len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'is_dll': pe.is_dll(),
            'is_exe': pe.is_exe(),
            'suspicious_sections': [s.Name.decode().strip('\x00') for s in pe.sections 
                                   if s.Name.decode().strip('\x00') in ['.text', '.data', '.rsrc']]
        }
    except ImportError:
        return {'error': 'pefile not installed'}
    except Exception as e:
        return {'error': str(e)}

# ============================================================================
# Timesketch Export Format
# ============================================================================
def export_timesketch(scan_results, output_file='timesketch_export.jsonl'):
    """Export results in Timesketch JSONL format"""
    try:
        with open(output_file, 'w') as f:
            for category, items in scan_results.get('results', {}).items():
                if isinstance(items, dict):
                    for key, value in items.items():
                        if isinstance(value, dict) and 'modified' in value:
                            event = {
                                'message': f"{category}: {key}",
                                'timestamp': value['modified'],
                                'datetime': value['modified'],
                                'timestamp_desc': 'File Modified',
                                'data_type': 'persistence:artifact',
                                'category': category,
                                'artifact': key,
                                'is_suspicious': value.get('is_suspicious', False)
                            }
                            f.write(json.dumps(event) + '\n')
        
        return {'success': True, 'file': output_file}
    except Exception as e:
        return {'error': str(e)}

# ============================================================================
# TheHive Alert Format
# ============================================================================
def create_thehive_alert(finding, severity='medium'):
    """Create TheHive alert format for suspicious finding"""
    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    
    alert = {
        'title': f"Suspicious Persistence: {finding.get('name', 'Unknown')}",
        'description': f"Persistence mechanism detected:\n{json.dumps(finding, indent=2)}",
        'type': 'persistence',
        'source': 'PersistenceFinder',
        'sourceRef': finding.get('full_path', 'N/A'),
        'severity': severity_map.get(severity, 2),
        'tags': ['persistence', 'autoruns'],
        'artifacts': []
    }
    
    # Add file hash as artifact
    if 'sha256' in finding:
        alert['artifacts'].append({
            'dataType': 'hash',
            'data': finding['sha256'],
            'message': 'SHA256 hash of suspicious file'
        })
    
    # Add file path as artifact
    if 'full_path' in finding:
        alert['artifacts'].append({
            'dataType': 'file',
            'data': finding['full_path'],
            'message': 'Full path to suspicious file'
        })
    
    return alert

# ============================================================================
# Installation Helper
# ============================================================================
def check_dependencies():
    """Check which optional dependencies are installed"""
    deps = {
        'requests': False,
        'yara': False,
        'pefile': False
    }
    
    for dep in deps:
        try:
            __import__(dep)
            deps[dep] = True
        except ImportError:
            pass
    
    return deps

def install_instructions():
    """Print installation instructions for optional dependencies"""
    print("""
Optional Dependencies for Enhanced Features:
    
1. VirusTotal Integration:
   pip install requests
   export VT_API_KEY="your_api_key_here"

2. YARA Scanning:
   pip install yara-python

3. PE Analysis:
   pip install pefile

4. Install all:
   pip install requests yara-python pefile
""")
