# Web Viewer - Beautiful Scan Results Interface

## 🌐 Overview

The Persistence Finder includes a beautiful web-based interface built with Streamlit to view, analyze, and filter scan results.

## ✨ Features

### 📊 Interactive Dashboard
- **Overview Tab**: Visual charts showing findings distribution
- **Timeline Tab**: Interactive timeline of file modifications
- **Details Tab**: Detailed view of all findings with expandable sections
- **Raw JSON Tab**: View and download raw scan data

### 🔍 Filtering Capabilities
- **Date Range Filter**: Filter findings by modification date
- **Category Filter**: Select specific persistence categories to view
- **Search**: Full-text search across all findings
- **Recent Modifications**: Automatic highlighting of items modified in last 7 days

### 📈 Visualizations
- **Bar Charts**: Findings distribution by category
- **Timeline Scatter Plot**: Visual timeline of modifications
- **Metrics Cards**: Quick stats (total findings, categories, etc.)
- **Color-coded Alerts**: Visual indicators for warnings and critical items

### 💾 Data Management
- **Multiple Scans**: View and compare different scan results
- **JSON Export**: Download scan results in JSON format
- **Automatic Save**: All scans automatically saved to `scans/` directory

## 🚀 Usage

### Automatic Launch (After Scan)
```bash
# Run a scan
sudo python3 main.py

# At the end, press ENTER to launch web viewer
# Opens automatically at http://localhost:8501
```

### Manual Launch
```bash
# Launch web viewer directly
streamlit run web_viewer.py

# Or with custom port
streamlit run web_viewer.py --server.port 8502
```

### Command Line Options
```bash
# Skip web viewer prompt
python3 main.py --no-web

# Don't save scan results
python3 main.py --no-save

# Both options
python3 main.py --no-web --no-save
```

## 📁 Scan Files Location

All scan results are saved in the `scans/` directory:
```
scans/
├── scan_20250207_143022.json
├── scan_20250207_150145.json
└── scan_20250208_091533.json
```

Filename format: `scan_YYYYMMDD_HHMMSS.json`

## 🎨 Web Interface Sections

### 1. Sidebar
- **Scan Selection**: Dropdown to select which scan to view
- **Date Filter**: Enable/disable date range filtering
- **Category Filter**: Multi-select for specific categories
- **Search Box**: Full-text search functionality

### 2. Overview Tab
- System information metrics
- Category distribution bar chart
- Recent modifications table (last 7 days)
- Total findings summary

### 3. Timeline Tab
- Interactive scatter plot of modifications over time
- Hover to see details
- Color-coded by category
- Statistics: oldest/newest modifications

### 4. Details Tab
- Expandable sections for each category
- Filtered results based on sidebar selections
- Formatted display of:
  - Timestamps (human-readable)
  - File sizes
  - Permissions
  - Content previews
  - SSH keys
  - Cron jobs
  - And more...

### 5. Raw JSON Tab
- Complete scan data in JSON format
- Syntax highlighting
- Download button for export

## 🔧 Advanced Features

### Date Filtering Example
1. Enable "Date Filtering" in sidebar
2. Select date range (From/To)
3. Only items modified within range will show
4. Useful for incident response and forensics

### Category Filtering Example
1. Uncheck categories you don't want to see
2. Focus on specific persistence types
3. Combine with date filter for precise analysis

### Search Example
1. Enter search term in sidebar
2. Searches across:
   - Category names
   - File paths
   - Item names
3. Real-time filtering

### Comparing Scans
1. Select different scans from dropdown
2. Compare findings over time
3. Identify new persistence mechanisms
4. Track changes in your environment

## 📊 Data Structure

### JSON Format
```json
{
  "metadata": {
    "scan_time": "2025-02-07 14:30:22",
    "platform": "Linux",
    "system_info": {
      "platform": "Linux",
      "architecture": "x86_64",
      "is_admin": true,
      "linux_name": "Kali GNU/Linux",
      "kernel": "6.17.10+kali-amd64"
    }
  },
  "results": {
    "1. Cron Jobs": {
      "/etc/crontab": {
        "modified": "2025-02-05 11:29:29",
        "size": "1042 bytes",
        "permissions": "644",
        "content_preview": "..."
      }
    },
    "2. Systemd Services": [...],
    ...
  }
}
```

## 🎯 Use Cases

### 1. Security Auditing
- Review all persistence mechanisms
- Filter by recent modifications
- Identify suspicious entries
- Export findings for reporting

### 2. Incident Response
- Quickly identify compromised systems
- Timeline analysis of modifications
- Compare before/after scans
- Track attacker persistence

### 3. Compliance Checking
- Regular scheduled scans
- Historical comparison
- Baseline establishment
- Change tracking

### 4. System Hardening
- Identify unnecessary persistence
- Review autostart items
- Audit cron jobs and services
- Clean up legacy entries

## 🛠️ Troubleshooting

### Web Viewer Won't Start
```bash
# Install Streamlit
pip install streamlit pandas plotly

# Check if port is available
lsof -i :8501

# Use different port
streamlit run web_viewer.py --server.port 8502
```

### No Scan Files Found
```bash
# Run a scan first
sudo python3 main.py

# Check scans directory exists
ls -la scans/

# Manually create if needed
mkdir scans
```

### Browser Doesn't Open
```bash
# Manually open browser to:
http://localhost:8501

# Or use IP address
http://127.0.0.1:8501
```

### Large Scan Files
- Web viewer handles large files efficiently
- Pagination and lazy loading built-in
- Use filters to reduce displayed data
- Export specific categories if needed

## 🎨 Customization

### Change Theme
Edit `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#1f77b4"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
```

### Modify Port
```bash
streamlit run web_viewer.py --server.port 8080
```

### Disable Auto-open Browser
```bash
streamlit run web_viewer.py --server.headless true
```

## 📱 Mobile Support

The web interface is responsive and works on:
- Desktop browsers (Chrome, Firefox, Safari, Edge)
- Tablets
- Mobile phones (limited functionality)

## 🔒 Security Notes

- Web viewer runs locally (localhost only)
- No external connections required
- Scan data stays on your machine
- Use SSH tunneling for remote access:
  ```bash
  ssh -L 8501:localhost:8501 user@remote-host
  ```

## 💡 Tips

1. **Regular Scans**: Schedule scans and compare results over time
2. **Baseline First**: Create a baseline scan on clean system
3. **Date Filters**: Use for incident investigation
4. **Export Data**: Download JSON for external analysis
5. **Search Feature**: Quick way to find specific files/services

## 🆘 Support

If you encounter issues:
1. Check Streamlit is installed: `streamlit --version`
2. Verify scan files exist: `ls scans/`
3. Check browser console for errors
4. Try different browser
5. Restart web viewer

## 📚 Additional Resources

- [Streamlit Documentation](https://docs.streamlit.io)
- [Plotly Charts](https://plotly.com/python/)
- [Pandas Guide](https://pandas.pydata.org/docs/)

---

**Version**: 1.0
**Status**: ✅ Production Ready
