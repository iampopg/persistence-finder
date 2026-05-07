"""
Forensic metadata collection helpers for incident response
"""
import os
import hashlib
from datetime import datetime

def get_file_metadata(file_path):
    """Get comprehensive forensic metadata for a file"""
    if not os.path.exists(file_path):
        return None
    
    try:
        stat = os.stat(file_path)
        
        metadata = {
            'full_path': os.path.abspath(file_path),
            'size_bytes': stat.st_size,
            'size_human': format_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'accessed': datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Add hashes for files under 50MB (performance)
        if stat.st_size < 50 * 1024 * 1024:
            try:
                metadata['md5'] = calculate_hash(file_path, 'md5')
                metadata['sha256'] = calculate_hash(file_path, 'sha256')
            except:
                metadata['md5'] = 'Error calculating'
                metadata['sha256'] = 'Error calculating'
        else:
            metadata['md5'] = 'File too large (>50MB)'
            metadata['sha256'] = 'File too large (>50MB)'
        
        return metadata
    except Exception as e:
        return {'error': str(e)}

def calculate_hash(file_path, algorithm='sha256'):
    """Calculate file hash"""
    if algorithm == 'md5':
        h = hashlib.md5()
    elif algorithm == 'sha256':
        h = hashlib.sha256()
    else:
        return None
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def format_size(bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} TB"

def get_registry_metadata(hive, path):
    """Get registry key metadata (Windows only)"""
    try:
        import winreg as reg
        key = reg.OpenKey(hive, path)
        _, _, last_modified = reg.QueryInfoKey(key)
        reg.CloseKey(key)
        
        # Convert Windows FILETIME to Unix timestamp
        timestamp = datetime.fromtimestamp(last_modified / 10000000 - 11644473600)
        
        return {
            'last_modified': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'last_modified_epoch': int(timestamp.timestamp())
        }
    except:
        return None
