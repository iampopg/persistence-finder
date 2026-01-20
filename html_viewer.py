#!/usr/bin/env python3
import json
import os
import glob

def generate_html(scan_files):
    """Generate HTML with embedded scan data"""
    
    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Persistence Finder - Results</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: white; border-radius: 10px; padding: 20px; text-align: center; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .header h1 { color: #667eea; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .stat-card h3 { color: #666; font-size: 0.9em; margin-bottom: 10px; text-transform: uppercase; }
        .stat-card .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .category { background: white; border-radius: 10px; margin-bottom: 15px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .category-header { background: #667eea; color: white; padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .category-header:hover { background: #5568d3; }
        .category-content { padding: 20px; display: none; max-height: 500px; overflow-y: auto; }
        .category-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f5f5f5; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: 600; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .suspicious { background: #fff5f5 !important; border-left: 4px solid #e74c3c; }
        .suspicious:hover { background: #ffe5e5 !important; }
        .badge { padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .arrow { transition: transform 0.3s; }
        .arrow.active { transform: rotate(180deg); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Persistence Finder</h1>
            <p style="color: #666; margin-top: 10px;">Security Analysis Dashboard</p>
        </div>
        
        <div class="stats" id="stats"></div>
        <div id="content"></div>
    </div>
    
    <script>
'''
    
    # Embed scan data
    html += '    const scanData = ' + json.dumps(scan_files[0]['data']) + ';\n\n'
    
    html += '''    function init() {
        displayStats();
        displayCategories();
    }
    
    function displayStats() {
        let totalFindings = 0;
        let suspiciousCount = 0;
        let categoriesWithFindings = 0;
        
        for (const [category, items] of Object.entries(scanData.results)) {
            if (!items) continue;
            
            const itemCount = Array.isArray(items) ? items.length : Object.keys(items).length;
            if (itemCount > 0) {
                categoriesWithFindings++;
                totalFindings += itemCount;
                
                if (typeof items === 'object' && !Array.isArray(items)) {
                    for (const value of Object.values(items)) {
                        if (value && value.is_suspicious) {
                            suspiciousCount++;
                        }
                    }
                }
            }
        }
        
        document.getElementById('stats').innerHTML = `
            <div class="stat-card">
                <h3>Scan Time</h3>
                <div class="value" style="font-size: 1.2em;">${scanData.metadata.scan_time}</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">${totalFindings}</div>
            </div>
            <div class="stat-card">
                <h3>Categories</h3>
                <div class="value">${categoriesWithFindings}</div>
            </div>
            <div class="stat-card">
                <h3>Suspicious Items</h3>
                <div class="value" style="color: #e74c3c;">${suspiciousCount}</div>
            </div>
        `;
    }
    
    function displayCategories() {
        let html = '';
        let categoryId = 0;
        
        for (const [category, items] of Object.entries(scanData.results)) {
            if (!items) continue;
            
            const itemCount = Array.isArray(items) ? items.length : Object.keys(items).length;
            if (itemCount === 0) continue;
            
            categoryId++;
            
            html += `
                <div class="category">
                    <div class="category-header" onclick="toggleCategory(${categoryId})">
                        <div><strong>${category}</strong> <span style="opacity: 0.8;">(${itemCount} items)</span></div>
                        <span class="arrow" id="arrow-${categoryId}">▼</span>
                    </div>
                    <div class="category-content" id="cat-${categoryId}">
                        ${generateTable(items)}
                    </div>
                </div>
            `;
        }
        
        document.getElementById('content').innerHTML = html || '<div style="background: white; padding: 20px; border-radius: 10px; text-align: center;">No findings to display</div>';
    }
    
    function generateTable(items) {
        let html = '<table><thead><tr><th>Item</th><th>Details</th><th>Status</th></tr></thead><tbody>';
        
        if (typeof items === 'object' && !Array.isArray(items)) {
            for (const [key, value] of Object.entries(items)) {
                const isSuspicious = value && value.is_suspicious;
                const rowClass = isSuspicious ? 'suspicious' : '';
                const status = isSuspicious ? 
                    '<span class="badge badge-danger">⚠️ SUSPICIOUS</span>' : 
                    '<span class="badge badge-success">✓ OK</span>';
                
                let details = '';
                if (value) {
                    if (value.modified) details += value.modified + ' ';
                    if (value.size) details += value.size + ' ';
                    if (value.permissions) details += 'perms: ' + value.permissions;
                }
                
                html += `<tr class="${rowClass}"><td>${escapeHtml(key)}</td><td>${details}</td><td>${status}</td></tr>`;
            }
        } else if (Array.isArray(items)) {
            items.forEach(item => {
                const name = typeof item === 'object' ? (item.name || JSON.stringify(item)) : String(item);
                html += `<tr><td>${escapeHtml(name)}</td><td></td><td></td></tr>`;
            });
        }
        
        html += '</tbody></table>';
        return html;
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function toggleCategory(id) {
        const content = document.getElementById('cat-' + id);
        const arrow = document.getElementById('arrow-' + id);
        content.classList.toggle('active');
        arrow.classList.toggle('active');
    }
    
    init();
    </script>
</body>
</html>
'''
    
    return html

if __name__ == '__main__':
    # Find latest scan file
    scan_files = glob.glob('scans/scan_*.json')
    if not scan_files:
        print("❌ No scan files found in scans/ directory")
        exit(1)
    
    latest_scan = max(scan_files, key=os.path.getctime)
    
    print(f"📂 Loading: {latest_scan}")
    
    with open(latest_scan, 'r') as f:
        scan_data = json.load(f)
    
    scans = [{'file': latest_scan, 'data': scan_data}]
    
    # Generate HTML
    html = generate_html(scans)
    
    # Write to file
    with open('scan_results.html', 'w', encoding='utf-8') as f:
        f.write(html)
    
    print("✅ Generated: scan_results.html")
    print("🌐 Opening in browser...")
    
    # Auto-open in browser
    import webbrowser
    import os
    file_path = os.path.abspath('scan_results.html')
    webbrowser.open('file://' + file_path)
