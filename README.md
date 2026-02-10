# SME Network Security Assessment Framework
## Week 6: Testing, Hardening & Refinement

This directory contains the implementation files for Week 6 of the SME Network Security Assessment Framework, focusing on testing, hardening, and refinement of security controls.

## Overview

Week 6 combines all previous work into comprehensive testing and validation:
- Automated penetration testing
- Security hardening verification
- Compliance checking against multiple frameworks
- Performance monitoring and optimization
- Final report generation

## Directory Structure

```
Week_6_Testing_Hardening_Refinement/Code/
├── pentest_automation.py      # Automated penetration testing
├── security_hardening.py      # System hardening checks
├── firewall_rules.sh          # Linux firewall hardening (iptables)
├── firewall_rules.ps1         # Windows Firewall hardening
├── wazuh_tuning.py           # Wazuh rule tuning and analysis
├── performance_monitor.py     # Performance monitoring
├── compliance_checker.py      # Multi-framework compliance checking
├── vulnerability_comparison.py # Before/after vulnerability comparison
├── final_report_generator.py  # Comprehensive report generation
├── test_hardening.py         # Hardening validation tests
├── run_full_assessment.sh    # Complete assessment (Linux/macOS)
├── run_full_assessment.ps1   # Complete assessment (Windows)
├── requirements.txt          # Python dependencies
├── config/
│   └── compliance_mappings.json  # Compliance control mappings
├── rules/
│   └── tuned_rules.xml       # Tuned Wazuh detection rules
└── templates/
    └── report_template.html  # HTML report template
```

## Prerequisites

### Software Requirements
- Python 3.8 or higher
- pip (Python package manager)
- Nmap (for network scanning)
- Administrative/root access (for some tests)

### Python Dependencies
```bash
pip install -r requirements.txt
```

## Quick Start

### Run Complete Assessment

**Linux/macOS:**
```bash
chmod +x run_full_assessment.sh
./run_full_assessment.sh
```

**Windows (PowerShell as Administrator):**
```powershell
.\run_full_assessment.ps1
```

### Run Individual Components

**Penetration Testing:**
```bash
python pentest_automation.py 192.168.1.0/24 -t quick -o reports/
```

**Security Hardening Check:**
```bash
python security_hardening.py -o hardening_report.json
```

**Compliance Assessment:**
```bash
python compliance_checker.py -f all -o reports/
```

**Performance Monitoring:**
```bash
python performance_monitor.py -d 60 --demo
```

**Wazuh Rule Tuning:**
```bash
python wazuh_tuning.py -o reports/ --hours 24
```

**Vulnerability Comparison:**
```bash
python vulnerability_comparison.py --demo
```

**Final Report Generation:**
```bash
python final_report_generator.py -d reports/ -o reports/final/
```

**Hardening Validation Tests:**
```bash
python test_hardening.py
```

## Component Details

### 1. Penetration Testing (`pentest_automation.py`)

Automated penetration testing that includes:
- Network discovery and port scanning (via Nmap)
- Service enumeration
- Vulnerability detection
- Safe exploit verification
- Comprehensive HTML/JSON reporting

**Usage:**
```bash
python pentest_automation.py TARGET [TARGET...] [-t TYPE] [-o OUTPUT]

Options:
  TARGET          IP address or hostname to scan
  -t, --type      Scan type: quick, full, or vuln (default: full)
  -o, --output    Output directory for reports
  -v, --verbose   Enable verbose output
```

### 2. Security Hardening (`security_hardening.py`)

Checks system security configuration against best practices:
- SSH configuration (Linux)
- Firewall status
- Password policies
- Audit logging
- Service configuration
- File permissions

**Platforms:** Linux, Windows

### 3. Firewall Hardening

**Linux (`firewall_rules.sh`):**
- iptables rule management
- Security zone definition
- Rate limiting
- Port scanner detection
- Connection logging

**Windows (`firewall_rules.ps1`):**
- Windows Firewall profile management
- Inbound/outbound rule creation
- Service-specific rules
- Logging configuration

### 4. Wazuh Rule Tuning (`wazuh_tuning.py`)

Analyzes Wazuh alerts to:
- Identify false positives
- Calculate tuning recommendations
- Generate optimized rule sets
- Measure improvement metrics

### 5. Performance Monitoring (`performance_monitor.py`)

Monitors and reports:
- CPU, memory, disk usage
- Scan performance metrics
- Alert processing times
- System health trends

### 6. Compliance Checking (`compliance_checker.py`)

Checks compliance against:
- NIST Cybersecurity Framework (CSF)
- ISO 27001
- CIS Controls v8

### 7. Vulnerability Comparison (`vulnerability_comparison.py`)

Compares scan results to show:
- New vulnerabilities
- Resolved vulnerabilities
- Risk score changes
- Remediation progress

### 8. Final Report Generation (`final_report_generator.py`)

Combines all assessment data into:
- Executive summary
- Detailed findings
- Compliance status
- Recommendations
- HTML and JSON reports

## Configuration

### Compliance Mappings (`config/compliance_mappings.json`)

Contains control mappings between frameworks and automated check definitions.

### Tuned Rules (`rules/tuned_rules.xml`)

Pre-configured Wazuh rules for:
- False positive reduction
- Enhanced detection
- Custom correlation rules

### Report Template (`templates/report_template.html`)

Customizable HTML template for report generation.

## Output

All scripts generate output in the `reports/` directory:
- JSON reports for programmatic access
- HTML reports for human review
- CSV exports for metrics
- Log files for troubleshooting

## Security Considerations

1. **Permissions**: Many scripts require elevated privileges
2. **Network Impact**: Penetration testing can trigger alerts
3. **Scope**: Always test only authorized systems
4. **Data**: Reports may contain sensitive information

## Troubleshooting

### Common Issues

**Nmap not found:**
```bash
# Linux
sudo apt install nmap

# Windows
choco install nmap
```

**Permission denied:**
```bash
# Linux - run with sudo
sudo python script.py

# Windows - run PowerShell as Administrator
```

**Module not found:**
```bash
pip install -r requirements.txt
```

## Integration

### With CI/CD

```yaml
# Example GitHub Actions workflow
- name: Run Security Assessment
  run: |
    pip install -r requirements.txt
    python compliance_checker.py -f nist -o results/
```

### With SIEM

The generated JSON reports can be ingested by:
- Wazuh
- Splunk
- Elastic SIEM
- Azure Sentinel

## Contributing

1. Follow PEP 8 style guidelines
2. Add tests for new features
3. Update documentation
4. Submit pull requests

## License

This framework is provided for educational and authorized security assessment purposes only.

## Support

For issues and questions:
1. Check the log files in the output directory
2. Run scripts with `-v` for verbose output
3. Review error messages for specific guidance

## Version History

- **1.0.0** (2024-01-15): Initial release
  - Complete testing and hardening suite
  - Multi-framework compliance checking
  - Comprehensive reporting

---

*SME Network Security Assessment Framework - Week 6*
