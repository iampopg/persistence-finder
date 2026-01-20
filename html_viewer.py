#!/usr/bin/env python3
"""
Simple HTML Viewer for Persistence Finder Results
Alternative to Streamlit when dependencies have issues
"""

import json
import os
import glob
import webbrowser

def generate_html(scan_files):
    """Generate HTML page from scan files"""
    
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Persistence Finder - Scan Results</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { background: white; border-radius: 12px; padding: 30px; text-align: center; margin-bottom: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
        .header h1 { font-size: 2.5em; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .controls { background: white; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
        .controls label { font-weight: 600; color: #495057; }
        .controls select, .controls input { padding: 10px; border: 2px solid #dee2e6; border-radius: 6px; font-size: 14px; }
        .controls button { padding: 10px 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .controls button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; transition: transform 0.3s; }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }
        .stat-card h3 { color: #6c757d; font-size: 0.9em; margin-bottom: 10px; text-transform: uppercase; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .category-card { background: white; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden; transition: all 0.3s; }
        .category-card:hover { box-shadow: 0 8px 24px rgba(0,0,0,0.15); }
        .category-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 25px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .category-header:hover { background: linear-gradient(135deg, #5568d3, #6a3f8f); }
        .category-title { display: flex; align-items: center; gap: 15px; }
        .category-title h3 { font-size: 1.3em; }
        .category-badge { background: rgba(255,255,255,0.25); padding: 6px 14px; border-radius: 20px; font-size: 0.9em; font-weight: 600; }
        .category-content { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
        .category-content.active { max-height: 10000px; }
        .table-container { padding: 25px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; font-size: 0.95em; text-transform: uppercase; }
        td { padding: 15px; border-bottom: 1px solid #e9ecef; vertical-align: top; }
        tr:hover { background: #f8f9fa; }
        .clickable { color: #667eea; cursor: pointer; font-weight: 600; text-decoration: underline; }
        .clickable:hover { color: #764ba2; }
        .suspicious-row { background: #fff5f5 !important; border-left: 4px solid #e74c3c; }
        .suspicious-row:hover { background: #ffe5e5 !important; }
        .timestamp { color: #8e44ad; font-family: 'Courier New', monospace; font-size: 0.9em; font-weight: 600; }
        .badge { display: inline-block; padding: 5px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600; margin-right: 5px; }
        .badge-danger { background: #e74c3c; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-success { background: #27ae60; color: white; }
        .arrow { font-size: 1.2em; transition: transform 0.3s; }
        .arrow.active { transform: rotate(180deg); }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); }
        .modal-content { background: white; margin: 5% auto; padding: 0; width: 80%; max-width: 900px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); max-height: 80vh; overflow: hidden; display: flex; flex-direction: column; }
        .modal-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 25px; display: flex; justify-content: space-between; align-items: center; }
        .modal-body { padding: 25px; overflow-y: auto; flex: 1; }
        .close { color: white; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: #f0f0f0; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.9em; line-height: 1.5; }
        .detail-item { margin-bottom: 15px; padding: 12px; background: #f8f9fa; border-radius: 6px; border-left: 3px solid #667eea; }
        .detail-label { font-weight: 600; color: #495057; margin-bottom: 5px; }
        .detail-value { color: #2c3e50; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Persistence Finder</h1>
            <p style="color: #6c757d; margin-top: 10px;">Security Analysis Dashboard</p>
        </div>
        
        <div class="controls">
            <div>
                <label for="scanSelect">📁 Select Scan:</label>
                <select id="scanSelect" onchange="loadScan()">
"""
    
    for i, scan_file in enumerate(scan_files):
        basename = os.path.basename(scan_file)
        selected = 'selected' if i == 0 else ''
        html += f'                    <option value="{scan_file}" {selected}>{basename}</option>\n'
    
    html += """
                </select>
            </div>
            <div>
                <label for="dateFilter">📅 Filter by Date:</label>
                <input type="date" id="dateFrom" onchange="filterByDate()">
                <span>to</span>
                <input type="date" id="dateTo" onchange="filterByDate()">
            </div>
            <button onclick="clearFilters()" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer;">Clear Filters</button>
        </div>
        
        <div class="stats" id="stats"></div>
        <div id="content"></div>
    </div>
    
    <div id="detailModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Details</h2>
                <span class="close" onclick="closeModal()">&times;</span>
            </div>
            <div class="modal-body" id="modalBody"></div>
        </div>
    </div>
    
    <script>
    const scans = {};
    let currentData = null;
"""
    
    for scan_file in scan_files:
        try:
            with open(scan_file, 'r') as f:
                data = json.load(f)
                html += f"    scans['{scan_file}'] = {json.dumps(data)};\n"
        except:
            pass
    
    html += """
    
    function showDetails(key, value) {
        document.getElementById('modalTitle').textContent = key;
        let html = '';
        
        if (typeof value === 'object') {
            for (const [k, v] of Object.entries(value)) {
                if (k === 'is_suspicious') continue;
                
                html += '<div class="detail-item">';
                html += `<div class="detail-label">${k.toUpperCase()}</div>`;
                
                if (k === 'content' || k === 'content_preview') {
                    html += `<pre>${escapeHtml(v)}</pre>`;
                } else if (k === 'suspicious_commands' && v && v !== 'None') {
                    html += `<div class="detail-value"><span class="badge badge-danger">⚠️ ${JSON.stringify(v)}</span></div>`;
                } else if (Array.isArray(v)) {
                    html += '<div class="detail-value">';
                    v.forEach(item => {
                        if (typeof item === 'string' && item.length > 100) {
                            html += `<pre>${escapeHtml(item)}</pre>`;
                        } else {
                            html += `<div>• ${escapeHtml(String(item))}</div>`;
                        }
                    });
                    html += '</div>';
                } else {
                    html += `<div class="detail-value">${escapeHtml(String(v))}</div>`;
                }
                html += '</div>';
            }
        } else {
            html = `<pre>${escapeHtml(String(value))}</pre>`;
        }
        
        document.getElementById('modalBody').innerHTML = html;
        document.getElementById('detailModal').style.display = 'block';
    }
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function closeModal() {
        document.getElementById('detailModal').style.display = 'none';
    }
    
    window.onclick = function(event) {
        const modal = document.getElementById('detailModal');
        if (event.target == modal) {
            closeModal();
        }
    }
    
    function toggleCategory(id) {
        const content = document.getElementById('content-' + id);
        const arrow = document.getElementById('arrow-' + id);
        content.classList.toggle('active');
        arrow.classList.toggle('active');
    }
    
    function loadScan() {
        const select = document.getElementById('scanSelect');
        const scanFile = select.value;
        currentData = scans[scanFile];
        
        if (!currentData) return;
        
        displayData(currentData);
    }
    
    function displayData(data) {
        const metadata = data.metadata;
        const results = data.results;
        
        // Stats
        let totalFindings = 0;
        let suspiciousCount = 0;
        let categoriesWithFindings = 0;
        
        for (const [category, items] of Object.entries(results)) {
            if (items && (Array.isArray(items) ? items.length > 0 : Object.keys(items).length > 0)) {
                categoriesWithFindings++;
                const count = Array.isArray(items) ? items.length : Object.keys(items).length;
                totalFindings += count;
                
                // Count suspicious
                if (typeof items === 'object' && !Array.isArray(items)) {
                    for (const [key, value] of Object.entries(items)) {
                        if (value.is_suspicious || (value.suspicious_commands && value.suspicious_commands !== 'None')) {
                            suspiciousCount++;
                        }
                    }
                }
            }
        }
        
        document.getElementById('stats').innerHTML = `
            <div class="stat-card">
                <h3>Scan Time</h3>
                <div class="value" style="font-size: 1.2em;">${metadata.scan_time}</div>
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
        
        // Content
        let html = '';
        let categoryId = 0;
        
        for (const [category, items] of Object.entries(results)) {
            if (!items || (Array.isArray(items) && items.length === 0) || (typeof items === 'object' && Object.keys(items).length === 0)) {
                continue;
            }
            
            const count = Array.isArray(items) ? items.length : Object.keys(items).length;
            categoryId++;
            
            html += `
                <div class="category-card">
                    <div class="category-header" onclick="toggleCategory(${categoryId})">
                        <div class="category-title">
                            <h3>${category}</h3>
                            <span class="category-badge">${count} items</span>
                        </div>
                        <span class="arrow" id="arrow-${categoryId}">▼</span>
                    </div>
                    <div class="category-content" id="content-${categoryId}">
                        <div class="table-container">
            `;
            
            if (typeof items === 'object' && !Array.isArray(items)) {
                html += '<table><thead><tr><th>Item</th><th>Modified</th><th>Size</th><th>Status</th></tr></thead><tbody>';
                
                for (const [key, value] of Object.entries(items)) {
                    const isSuspicious = value.is_suspicious || (value.suspicious_commands && value.suspicious_commands !== 'None');
                    const rowClass = isSuspicious ? 'suspicious-row' : '';
                    
                    let modified = value.modified || 'N/A';
                    let size = value.size || '';
                    let status = '';
                    
                    if (typeof value === 'object') {
                        if (isSuspicious) {
                            status = '<span class="badge badge-danger">⚠️ SUSPICIOUS</span>';
                        } else {
                            status = '<span class="badge badge-success">✓ OK</span>';
                        }
                        
                        if (value.permissions) status += ` <span class="badge badge-warning">${value.permissions}</span>`;
                    }
                    
                    const valueStr = JSON.stringify(value).replace(/"/g, '&quot;');
                    
                    html += `
                        <tr class="${rowClass}" data-modified="${modified}">
                            <td><span class="clickable" onclick="showDetails('${key.replace(/'/g, "\\'").replace(/"/g, '&quot;')}', JSON.parse('${valueStr}'))">${key}</span></td>
                            <td><span class="timestamp">${modified}</span></td>
                            <td>${size}</td>
                            <td>${status}</td>
                        </tr>
                    `;
                }
                
                html += '</tbody></table>';
            } else if (Array.isArray(items)) {
                html += '<table><thead><tr><th>Item</th><th>Modified</th></tr></thead><tbody>';
                items.forEach((item, idx) => {
                    if (typeof item === 'object') {
                        const name = item.name || 'Unknown';
                        const modified = item.modified || '';
                        const valueStr = JSON.stringify(item).replace(/"/g, '&quot;');
                        html += `<tr data-modified="${modified}"><td><span class="clickable" onclick="showDetails('${name.replace(/'/g, "\\'").replace(/"/g, '&quot;')}', JSON.parse('${valueStr}'))">${name}</span></td><td><span class="timestamp">${modified}</span></td></tr>`;
                    } else {
                        html += `<tr><td>${item}</td><td></td></tr>`;
                    }
                });
                html += '</tbody></table>';
            }
            
            html += '</div></div></div>';
        }
        
        document.getElementById('content').innerHTML = html || '<div class="no-data">No findings to display</div>';
    }
    
    function filterByDate() {
        const dateFrom = document.getElementById('dateFrom').value;
        const dateTo = document.getElementById('dateTo').value;
        
        if (!dateFrom && !dateTo) {
            displayData(currentData);
            return;
        }
        
        const rows = document.querySelectorAll('tr[data-modified]');
        rows.forEach(row => {
            const modified = row.getAttribute('data-modified');
            if (!modified || modified === 'N/A') {
                row.style.display = '';
                return;
            }
            
            const modDate = modified.split(' ')[0];
            let show = true;
            
            if (dateFrom && modDate < dateFrom) show = false;
            if (dateTo && modDate > dateTo) show = false;
            
            row.style.display = show ? '' : 'none';
        });
    }
    
    function clearFilters() {
        document.getElementById('dateFrom').value = '';
        document.getElementById('dateTo').value = '';
        filterByDate();
    }
    
    loadScan();
    </script>
</body>
</html>
"""
    
    return html

def main():
    scan_dirs = ['scans']
    scan_files = []
    
    for scan_dir in scan_dirs:
        if os.path.exists(scan_dir):
            try:
                files = glob.glob(os.path.join(scan_dir, "scan_*.json"))
                scan_files.extend(files)
            except PermissionError:
                pass
    
    scan_files.sort(reverse=True)
    
    if not scan_files:
        print("❌ No scan files found!")
        print("   Run: python3 main.py to generate scan data")
        return
    
    html_content = generate_html(scan_files)
    html_file = 'scan_results.html'
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Generated: {html_file}")
    print(f"🌐 Opening in browser...")
    
    webbrowser.open(f'file://{os.path.abspath(html_file)}')
    print(f"\n📊 View results at: file://{os.path.abspath(html_file)}")

if __name__ == "__main__":
    main()
