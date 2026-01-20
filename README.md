# Persistence Finder

A powerful cross-platform tool to detect persistence mechanisms on Windows and Linux systems with beautiful terminal output and interactive web interface.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/iampopg/persistence-finder)

> **Created by [@iampopg](https://github.com/iampopg)**

---

## ⚠️ DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED SECURITY ASSESSMENTS ONLY**

- Only use on systems you own or have explicit written permission to scan
- Unauthorized scanning of systems may be illegal in your jurisdiction
- The authors assume NO liability for misuse or damage caused by this tool
- This tool is provided "AS IS" without warranty of any kind
- Use at your own risk

---

## ✨ Features

### 🎯 Detection Capabilities

- **✅ 15 Linux Persistence Techniques** (Production Ready)
- **✅ 20 Windows Techniques** (Production Ready)
- **🚧 6 macOS Techniques** (Coming Soon)

### 🔬 Forensic Analysis Features

- **File Hashing** - MD5/SHA256 for IOC tracking
- **Digital Signatures** - Verify Microsoft-signed binaries
- **Timestamps** - Created/Modified/Accessed dates
- **Registry Metadata** - Last modified timestamps
- **File Metadata** - Size, permissions, full paths

### 🎨 Beautiful Output

- Color-coded terminal display with ASCII art banner
- Human-readable timestamps (YYYY-MM-DD HH:MM:SS)
- Red highlighting for suspicious items
- Organized categorized results
- Progress indicators

### 💾 Automatic Saving

- Auto-save all scans to JSON format
- Organized in `scans/` directory
- Full forensic metadata included
- Easy to parse for automation
- Timesketch/TheHive export support

### 🌐 Interactive Web Viewer

- Beautiful HTML dashboard
- Click items to view full details
- Date filtering capabilities
- Collapsible categories
- Export to JSON

---

## 🎯 Use Cases

### 🚨 Incident Response
- Quickly identify persistence mechanisms during active incidents
- Export findings to SIEM/TheHive for case management
- Timeline analysis with Timesketch integration

### 🔍 Threat Hunting
- Proactive hunting for APT persistence
- Baseline comparison to detect anomalies
- Hash-based IOC tracking

### 🧪 Malware Analysis
- Identify malware persistence techniques
- Digital signature verification
- Forensic metadata collection

### 🛡️ Security Auditing
- Regular security assessments
- Compliance checking
- Vulnerability identification

---

## 📋 Detection Coverage

### Linux (15 Techniques)

1. ✅ Cron Jobs (system & user)
2. ✅ Systemd Services & Timers
3. ✅ RC Scripts & Init.d
4. ✅ Shell Profile Files (with suspicious command detection)
5. ✅ SSH Authorized Keys
6. ✅ Kernel Modules (LKM)
7. ✅ eBPF Programs
8. ✅ LD_PRELOAD Hijacking
9. ✅ Udev Rules
10. ✅ PAM Modules
11. ✅ At Jobs
12. ✅ XDG Autostart
13. ✅ MOTD Scripts
14. ✅ Systemd Unit Files
15. ✅ Profile.d Scripts

### Windows (20 Techniques)

1. ✅ Registry Run Keys (6 locations)
2. ✅ Startup Folders
3. ✅ Scheduled Tasks
4. ✅ Windows Services
5. ✅ Winlogon Helper DLL
6. ✅ Accessibility Features
7. ✅ AppInit/AppCert DLLs
8. ✅ WMI Event Subscriptions
9. ✅ LSASS/SSP
10. ✅ IFEO Injection
11. ✅ Netsh Helper DLL
12. ✅ Port Monitors
13. ✅ Authentication Packages
14. ✅ Time Providers
15. ✅ Active Setup
16. ✅ COR_PROFILER
17. ✅ SilentProcessExit
18. ✅ BITS Jobs
19. ✅ Startup Approved
20. ✅ Boot Execute

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/iampopg/persistence-finder.git
cd persistence-finder

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

**Linux:**

```bash
# Run with sudo for complete access
sudo python3 main.py
```

**Windows:**

```cmd
# Run as Administrator
python main.py
```

### View Results in Browser

```bash
python3 html_viewer.py
```

---

## 📖 Usage Examples

### Command Line Options

```bash
# JSON output only
python3 main.py --json

# Verbose mode (show full file contents)
sudo python3 main.py --verbose

# Summary mode (counts only)
sudo python3 main.py --summary

# Skip web viewer prompt
sudo python3 main.py --no-web

# Don't save results
python3 main.py --no-save
```

### Example Output

```
    ____  __________  _____ ______________________   ______________
   / __ \/ ____/ __ \/ ___//  _/ ___/_  __/ ____/ | / / ____/ ____/
  / /_/ / __/ / /_/ /\__ \ / / \__ \ / / / __/ /  |/ / /   / __/   
 / ____/ /___/ _, _/___/ // / ___/ // / / /___/ /|  / /___/ /___   
/_/   /_____/_/ |_|/____/___//____//_/ /_____/_/ |_/\____/_____/   

======================================================================
  SYSTEM INFORMATION
======================================================================
  Platform: Linux 6.17.10+kali-amd64
  Architecture: x86_64
  Privileges: ✓ Admin/Root
  Distribution: Kali GNU/Linux

[+] 6. Shell Profile Files
----------------------------------------------------------------------
  • /home/user/.bashrc:
    ⚠️  SUSPICIOUS COMMANDS DETECTED!
    size: 5751 bytes
    modified: 2026-01-14 06:34:01
    permissions: 644
    suspicious_commands: ['eval', 'exec']
```

---

## 🔍 Suspicious Command Detection

Automatically flags files containing:

- `curl`, `wget` - Download tools
- `nc`, `netcat` - Network tools
- `/dev/tcp` - Bash networking
- `base64` - Encoding
- `eval`, `exec` - Code execution

---

## 📊 Output Files

All scans are automatically saved to:

```
scans/scan_YYYYMMDD_HHMMSS.json
```

JSON structure:

```json
{
  "metadata": {
    "scan_time": "2025-01-19 03:56:56",
    "platform": "Linux",
    "system_info": {...}
  },
  "results": {
    "1. Cron Jobs": {...},
    "2. Systemd Services": [...]
  }
}
```

---

## 🛠️ Requirements

- **Python**: 3.8 or higher
- **Privileges**: Admin/root for complete scanning
- **Dependencies**:
  - colorama (terminal colors)
  - pyfiglet (ASCII art)
  - Standard library modules

---

## 📚 Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Complete usage instructions
- **[PERSISTENCE_TECHNIQUES.md](PERSISTENCE_TECHNIQUES.md)** - All techniques reference
- **[LINUX_IMPLEMENTATION.md](LINUX_IMPLEMENTATION.md)** - Linux implementation details
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Security analyst quick reference

---

## 🤝 Contributing

**This is an open-source project and we welcome contributors!**

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution

- 🪟 Windows technique testing and improvements
- 🍎 macOS implementation
- 🌐 Web viewer enhancements
- 📝 Documentation improvements
- 🐛 Bug fixes and optimizations
- 🔍 Additional persistence techniques
- 🌍 Internationalization

---

## 📜 License & Credit

### MIT License

Copyright (c) 2025 [@iampopg](https://github.com/iampopg)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

**The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.**

### ⚠️ Credit Requirement

**If you use, copy, or modify this code, you MUST:**

- Give credit to **[@iampopg](https://github.com/iampopg)**
- Include a link to the original repository
- Maintain this credit requirement in derivative works

**Example credit:**

```
Based on Persistence Finder by @iampopg
https://github.com/iampopg/persistence-finder
```

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🔒 Security Notice

### Responsible Use

- This tool is designed for defensive security purposes
- Use only on systems you own or have authorization to test
- Do not use for malicious purposes
- Report any security issues responsibly

### Limitations

- Cannot detect kernel-level rootkits (use rkhunter, chkrootkit)
- Cannot detect firmware implants
- May produce false positives from legitimate software
- Requires elevated privileges for complete scanning

---

## 🌟 Comparison with Other Tools

| Tool                         | Platform  | GUI    | Auto-Save | Open Source |
| ---------------------------- | --------- | ------ | --------- | ----------- |
| **Persistence Finder** | Win/Linux | ✅ Web | ✅        | ✅          |
| Sysinternals Autoruns        | Windows   | ✅     | ❌        | ❌          |
| chkrootkit                   | Linux     | ❌     | ❌        | ✅          |
| rkhunter                     | Linux     | ❌     | ✅        | ✅          |

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/iampopg/persistence-finder/issues)
- **Discussions**: [GitHub Discussions](https://github.com/iampopg/persistence-finder/discussions)
- **Author**: [@iampopg](https://github.com/iampopg)

---

## 🎯 Roadmap

- [X] Linux implementation (15 techniques)
- [X] Windows implementation (20 techniques)
- [X] Beautiful terminal output
- [X] Web viewer
- [X] JSON export
- [ ] macOS implementation (6 techniques)
- [ ] Baseline comparison mode
- [ ] Hash verification
- [ ] Threat intelligence integration
- [ ] SIEM integration
- [ ] Docker container
- [ ] CI/CD integration

---

## 🙏 Acknowledgments

- MITRE ATT&CK Framework for persistence technique documentation
- Security research community for real-world examples
- All contributors and testers

---

## ⭐ Star History

If you find this tool useful, please consider giving it a star! ⭐

---

**Made with ❤️ by [@iampopg](https://github.com/iampopg)**

**For educational and authorized security testing purposes only.**
