# Persistence Finder - Quick Reference Card

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan (Linux)
sudo python3 main.py

# JSON output
sudo python3 main.py --json > results.json

# Check system info only
python3 system_info.py
```

---

## 🔍 What Gets Detected (Linux)

| # | Technique | Risk Level | Common in |
|---|-----------|------------|-----------|
| 1 | Cron Jobs | HIGH | Mining malware, backdoors |
| 2 | Systemd Services | HIGH | APTs, ransomware |
| 3 | Systemd Timers | MEDIUM | Scheduled attacks |
| 4 | RC Scripts | MEDIUM | Legacy malware |
| 5 | Shell Profiles | HIGH | SSH backdoors |
| 6 | SSH Keys | CRITICAL | Remote access |
| 7 | Kernel Modules | CRITICAL | Rootkits |
| 8 | eBPF Programs | HIGH | Modern rootkits |
| 9 | LD_PRELOAD | HIGH | Library hijacking |
| 10 | Udev Rules | MEDIUM | Hardware triggers |
| 11 | PAM Modules | CRITICAL | Auth backdoors |
| 12 | At Jobs | LOW | One-time tasks |
| 13 | XDG Autostart | MEDIUM | Desktop malware |
| 14 | MOTD Scripts | LOW | Login triggers |

---

## 🚨 Red Flags to Look For

### Immediate Investigation Required
- Unknown SSH keys in /root/.ssh/authorized_keys
- Suspicious kernel modules (check against known good baseline)
- LD_PRELOAD entries in /etc/ld.so.preload
- Unknown PAM modules in /lib/security/
- Cron jobs with suspicious commands (curl, wget to unknown IPs)

### High Priority
- New systemd services not from package manager
- Shell profile modifications with base64/eval
- Udev rules executing scripts
- eBPF programs (if unexpected)

### Medium Priority
- New autostart .desktop files
- Modified MOTD scripts
- At jobs (rare, investigate all)
- RC scripts (legacy, but check)

---

## 📋 Investigation Workflow

### 1. Initial Scan
```bash
sudo python3 main.py | tee initial_scan.txt
```

### 2. Review High-Risk Areas First
- SSH authorized keys
- Kernel modules
- Systemd services
- Cron jobs

### 3. Check Timestamps
Look for recently modified files:
```bash
# Files modified in last 7 days
find /etc/systemd/system/ -mtime -7 -type f
find /etc/cron.d/ -mtime -7 -type f
```

### 4. Verify Against Baseline
Compare with known good system or package manager:
```bash
# Check if file is from package
dpkg -S /path/to/file
rpm -qf /path/to/file
```

### 5. Analyze Suspicious Entries
```bash
# View full cron job
cat /etc/cron.d/suspicious_file

# Check systemd service
systemctl cat suspicious.service
systemctl status suspicious.service

# View kernel module info
modinfo suspicious_module
```

---

## 🎯 Common False Positives

### Legitimate Entries (Usually Safe)
- **Systemd Services**: NetworkManager, docker, ssh, cron
- **Cron Jobs**: logrotate, apt-daily, man-db
- **Autostart**: nm-applet, blueman, xfce components
- **PAM Modules**: pam_unix, pam_systemd, pam_permit

### Vendor Software
- Docker services
- Cloud agent services (AWS SSM, Azure agent)
- Monitoring tools (Nagios, Zabbix)
- Backup software

### Development Tools
- Anaconda/Miniconda services
- IDE services (VS Code server)
- Container runtimes

---

## 🔧 Remediation Steps

### Remove Malicious Cron Job
```bash
# Edit crontab
crontab -e  # For user cron
sudo vim /etc/cron.d/malicious_file  # For system cron
sudo rm /etc/cron.d/malicious_file
```

### Disable Malicious Systemd Service
```bash
sudo systemctl stop malicious.service
sudo systemctl disable malicious.service
sudo rm /etc/systemd/system/malicious.service
sudo systemctl daemon-reload
```

### Remove SSH Key
```bash
# Edit authorized_keys
vim ~/.ssh/authorized_keys
# Or for root
sudo vim /root/.ssh/authorized_keys
```

### Remove Kernel Module
```bash
# Unload module
sudo rmmod malicious_module
# Blacklist it
echo "blacklist malicious_module" | sudo tee -a /etc/modprobe.d/blacklist.conf
```

### Remove LD_PRELOAD Hijack
```bash
sudo vim /etc/ld.so.preload  # Remove malicious library
sudo rm /path/to/malicious.so
```

---

## 📊 Output Interpretation

### Color Coding
- 🟢 **Green**: Normal items, no action needed
- 🟡 **Yellow**: Review recommended
- 🔴 **Red**: Errors or warnings

### Finding Counts
- **0-50**: Normal for minimal system
- **50-200**: Typical workstation
- **200-500**: Server with services
- **500+**: Heavy server or needs cleanup

### Suspicious Indicators
Look for in shell profiles:
- `curl | bash`
- `wget -O- | sh`
- `nc -e /bin/bash`
- `base64 -d | bash`
- `/dev/tcp/IP/PORT`

---

## 🛡️ Prevention Best Practices

### System Hardening
1. **Disable root SSH login**
   ```bash
   # In /etc/ssh/sshd_config
   PermitRootLogin no
   ```

2. **Use SSH keys only**
   ```bash
   PasswordAuthentication no
   ```

3. **Monitor file integrity**
   ```bash
   # Install AIDE or Tripwire
   sudo apt install aide
   ```

4. **Regular audits**
   ```bash
   # Run this tool weekly
   sudo python3 main.py --json > scan_$(date +%Y%m%d).json
   ```

### Monitoring
- Set up file integrity monitoring (FIM)
- Enable auditd for system call monitoring
- Use osquery for continuous monitoring
- Deploy SIEM for log aggregation

---

## 📞 Incident Response

### If Compromise Detected

1. **Isolate System**
   ```bash
   # Disconnect network
   sudo ip link set eth0 down
   ```

2. **Preserve Evidence**
   ```bash
   # Capture scan results
   sudo python3 main.py --json > evidence_$(date +%Y%m%d_%H%M%S).json
   
   # Capture running processes
   ps auxf > processes.txt
   
   # Capture network connections
   netstat -tulpn > network.txt
   ```

3. **Document Findings**
   - Screenshot suspicious entries
   - Note timestamps
   - Record file hashes

4. **Contain & Remediate**
   - Follow remediation steps above
   - Change all passwords
   - Rotate SSH keys
   - Update all software

5. **Post-Incident**
   - Analyze how compromise occurred
   - Implement additional controls
   - Schedule regular scans

---

## 🔬 Advanced Analysis

### Compare Scans Over Time
```bash
# Baseline scan
sudo python3 main.py --json > baseline.json

# Later scan
sudo python3 main.py --json > current.json

# Compare (requires jq)
diff <(jq -S . baseline.json) <(jq -S . current.json)
```

### Focus on Specific Category
```bash
# Extract just cron jobs
sudo python3 main.py --json | jq '."1. Cron Jobs"'
```

### Check Specific User
```bash
# Check user's crontab
sudo crontab -u username -l

# Check user's SSH keys
sudo cat /home/username/.ssh/authorized_keys
```

---

## 📚 Additional Resources

### Tools to Complement This Scanner
- **rkhunter**: Rootkit detection
- **chkrootkit**: Rootkit checker
- **lynis**: Security auditing
- **osquery**: System monitoring
- **AIDE**: File integrity

### Learning Resources
- MITRE ATT&CK Framework (TA0003)
- Linux Security Modules documentation
- Systemd security documentation
- PAM configuration guides

---

## 💡 Pro Tips

1. **Run as root** for complete detection
2. **Baseline first** on clean system
3. **Schedule regular scans** (weekly/monthly)
4. **Compare results** over time
5. **Investigate unknowns** immediately
6. **Document everything** for audit trail
7. **Test in VM first** before production
8. **Keep tool updated** for new techniques

---

## ⚠️ Limitations

- Cannot detect kernel-level rootkits (use rkhunter)
- Cannot detect firmware implants
- May miss obfuscated persistence
- Requires root for complete scan
- False positives possible (verify all findings)

---

## 📧 Support & Contribution

- Report issues with detailed logs
- Suggest new detection techniques
- Share false positive patterns
- Contribute detection improvements

---

**Version**: 1.0 (Linux Complete)
**Last Updated**: 2025
**Status**: Production Ready ✅
