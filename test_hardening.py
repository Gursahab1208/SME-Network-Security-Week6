#!/usr/bin/env python3
"""
SME Network Security Assessment Framework
Week 6: Hardening Validation Test Script

This script validates that security hardening measures are properly applied:
- Firewall rules verification
- Detection rules testing
- Compliance validation
- Configuration verification

Author: SME Security Team
Version: 1.0.0
"""

import subprocess
import platform
import socket
import ssl
import json
import logging
import argparse
import os
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_hardening.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TestResult(Enum):
    """Test result status"""
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class TestCase:
    """Represents a single test case"""
    name: str
    category: str
    description: str
    result: TestResult
    message: str = ""
    details: str = ""
    duration_ms: float = 0


@dataclass
class TestSuite:
    """Collection of test cases"""
    name: str
    tests: List[TestCase] = field(default_factory=list)

    def summary(self) -> Dict:
        """Get test suite summary"""
        return {
            'total': len(self.tests),
            'passed': len([t for t in self.tests if t.result == TestResult.PASS]),
            'failed': len([t for t in self.tests if t.result == TestResult.FAIL]),
            'skipped': len([t for t in self.tests if t.result == TestResult.SKIP]),
            'errors': len([t for t in self.tests if t.result == TestResult.ERROR])
        }


class HardeningTester:
    """Tests hardening configurations"""

    def __init__(self):
        self.system = platform.system()
        self.suites: List[TestSuite] = []

    def run_all_tests(self) -> List[TestSuite]:
        """Run all hardening tests"""
        logger.info("Starting hardening validation tests")

        # Create test suites
        self.suites = [
            self._test_firewall_rules(),
            self._test_ssh_hardening(),
            self._test_network_security(),
            self._test_authentication(),
            self._test_logging_monitoring(),
            self._test_file_permissions(),
            self._test_service_security(),
            self._test_detection_rules(),
        ]

        return self.suites

    def _run_command(self, command: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Run a system command"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)

    def _run_powershell(self, command: str) -> Tuple[bool, str]:
        """Run a PowerShell command"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', command],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)

    # ========================================================================
    # FIREWALL TESTS
    # ========================================================================

    def _test_firewall_rules(self) -> TestSuite:
        """Test firewall configuration"""
        suite = TestSuite(name="Firewall Rules")

        if self.system == 'Linux':
            # Test: Firewall is enabled
            start = datetime.now()
            success, output = self._run_command(['iptables', '-L', '-n'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success:
                suite.tests.append(TestCase(
                    name="Firewall Enabled",
                    category="Firewall",
                    description="Verify iptables is active",
                    result=TestResult.PASS,
                    message="iptables is active",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="Firewall Enabled",
                    category="Firewall",
                    description="Verify iptables is active",
                    result=TestResult.FAIL,
                    message="iptables not accessible",
                    duration_ms=duration
                ))

            # Test: Default policy is DROP
            start = datetime.now()
            success, output = self._run_command(['iptables', '-L', 'INPUT', '-n'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and 'policy DROP' in output:
                suite.tests.append(TestCase(
                    name="Default DROP Policy",
                    category="Firewall",
                    description="Verify default INPUT policy is DROP",
                    result=TestResult.PASS,
                    message="INPUT chain policy is DROP",
                    duration_ms=duration
                ))
            elif success:
                suite.tests.append(TestCase(
                    name="Default DROP Policy",
                    category="Firewall",
                    description="Verify default INPUT policy is DROP",
                    result=TestResult.FAIL,
                    message="INPUT chain policy is not DROP",
                    duration_ms=duration
                ))

            # Test: SSH rate limiting
            start = datetime.now()
            success, output = self._run_command(['iptables', '-L', '-n'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and ('recent' in output.lower() or 'limit' in output.lower()):
                suite.tests.append(TestCase(
                    name="SSH Rate Limiting",
                    category="Firewall",
                    description="Verify SSH rate limiting rules exist",
                    result=TestResult.PASS,
                    message="Rate limiting rules found",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="SSH Rate Limiting",
                    category="Firewall",
                    description="Verify SSH rate limiting rules exist",
                    result=TestResult.FAIL,
                    message="No rate limiting rules found",
                    duration_ms=duration
                ))

        elif self.system == 'Windows':
            # Test: Windows Firewall enabled
            start = datetime.now()
            success, output = self._run_powershell(
                "Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count"
            )
            duration = (datetime.now() - start).total_seconds() * 1000

            try:
                enabled_count = int(output)
                if enabled_count >= 3:
                    suite.tests.append(TestCase(
                        name="Windows Firewall Enabled",
                        category="Firewall",
                        description="Verify Windows Firewall is enabled for all profiles",
                        result=TestResult.PASS,
                        message=f"All {enabled_count} profiles enabled",
                        duration_ms=duration
                    ))
                else:
                    suite.tests.append(TestCase(
                        name="Windows Firewall Enabled",
                        category="Firewall",
                        description="Verify Windows Firewall is enabled for all profiles",
                        result=TestResult.FAIL,
                        message=f"Only {enabled_count} profiles enabled",
                        duration_ms=duration
                    ))
            except:
                suite.tests.append(TestCase(
                    name="Windows Firewall Enabled",
                    category="Firewall",
                    description="Verify Windows Firewall is enabled for all profiles",
                    result=TestResult.ERROR,
                    message="Could not determine firewall status",
                    duration_ms=duration
                ))

            # Test: Default inbound action
            start = datetime.now()
            success, output = self._run_powershell(
                "(Get-NetFirewallProfile -Name Domain).DefaultInboundAction"
            )
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and 'Block' in output:
                suite.tests.append(TestCase(
                    name="Default Inbound Block",
                    category="Firewall",
                    description="Verify default inbound action is Block",
                    result=TestResult.PASS,
                    message="Default inbound action is Block",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="Default Inbound Block",
                    category="Firewall",
                    description="Verify default inbound action is Block",
                    result=TestResult.FAIL,
                    message=f"Default inbound action: {output}",
                    duration_ms=duration
                ))

        return suite

    # ========================================================================
    # SSH TESTS
    # ========================================================================

    def _test_ssh_hardening(self) -> TestSuite:
        """Test SSH hardening"""
        suite = TestSuite(name="SSH Hardening")

        if self.system != 'Linux':
            suite.tests.append(TestCase(
                name="SSH Hardening",
                category="SSH",
                description="SSH tests for Linux only",
                result=TestResult.SKIP,
                message="Not applicable on Windows"
            ))
            return suite

        sshd_config = Path('/etc/ssh/sshd_config')
        if not sshd_config.exists():
            suite.tests.append(TestCase(
                name="SSH Configuration",
                category="SSH",
                description="SSH configuration file exists",
                result=TestResult.SKIP,
                message="sshd_config not found"
            ))
            return suite

        try:
            content = sshd_config.read_text()
        except PermissionError:
            content = ""

        # Test: Root login disabled
        start = datetime.now()
        if 'PermitRootLogin no' in content or 'PermitRootLogin prohibit-password' in content:
            suite.tests.append(TestCase(
                name="Root Login Disabled",
                category="SSH",
                description="Verify root SSH login is disabled",
                result=TestResult.PASS,
                message="Root login is disabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))
        else:
            suite.tests.append(TestCase(
                name="Root Login Disabled",
                category="SSH",
                description="Verify root SSH login is disabled",
                result=TestResult.FAIL,
                message="Root login may be enabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))

        # Test: Protocol 2 only
        start = datetime.now()
        if 'Protocol 1' not in content:
            suite.tests.append(TestCase(
                name="SSH Protocol 2",
                category="SSH",
                description="Verify only SSH Protocol 2 is used",
                result=TestResult.PASS,
                message="Protocol 1 not enabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))
        else:
            suite.tests.append(TestCase(
                name="SSH Protocol 2",
                category="SSH",
                description="Verify only SSH Protocol 2 is used",
                result=TestResult.FAIL,
                message="Protocol 1 may be enabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))

        # Test: Empty passwords disabled
        start = datetime.now()
        if 'PermitEmptyPasswords no' in content:
            suite.tests.append(TestCase(
                name="Empty Passwords Disabled",
                category="SSH",
                description="Verify empty passwords are disabled",
                result=TestResult.PASS,
                message="Empty passwords disabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))
        else:
            suite.tests.append(TestCase(
                name="Empty Passwords Disabled",
                category="SSH",
                description="Verify empty passwords are disabled",
                result=TestResult.FAIL,
                message="Empty passwords not explicitly disabled",
                duration_ms=(datetime.now() - start).total_seconds() * 1000
            ))

        return suite

    # ========================================================================
    # NETWORK SECURITY TESTS
    # ========================================================================

    def _test_network_security(self) -> TestSuite:
        """Test network security settings"""
        suite = TestSuite(name="Network Security")

        # Test: Check for open ports
        start = datetime.now()
        common_ports = [21, 23, 25, 80, 443, 3389]
        open_ports = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        duration = (datetime.now() - start).total_seconds() * 1000

        suite.tests.append(TestCase(
            name="Open Ports Audit",
            category="Network",
            description="Audit commonly attacked ports",
            result=TestResult.PASS if len(open_ports) < 5 else TestResult.FAIL,
            message=f"Open ports found: {open_ports}" if open_ports else "No common ports open",
            duration_ms=duration
        ))

        # Test: IPv6 disabled (if applicable)
        if self.system == 'Linux':
            start = datetime.now()
            success, output = self._run_command(['sysctl', 'net.ipv6.conf.all.disable_ipv6'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and '= 1' in output:
                suite.tests.append(TestCase(
                    name="IPv6 Disabled",
                    category="Network",
                    description="Verify IPv6 is disabled if not needed",
                    result=TestResult.PASS,
                    message="IPv6 is disabled",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="IPv6 Disabled",
                    category="Network",
                    description="Verify IPv6 is disabled if not needed",
                    result=TestResult.FAIL,
                    message="IPv6 is enabled (verify if needed)",
                    duration_ms=duration
                ))

        # Test: IP forwarding disabled
        if self.system == 'Linux':
            start = datetime.now()
            success, output = self._run_command(['sysctl', 'net.ipv4.ip_forward'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and '= 0' in output:
                suite.tests.append(TestCase(
                    name="IP Forwarding Disabled",
                    category="Network",
                    description="Verify IP forwarding is disabled",
                    result=TestResult.PASS,
                    message="IP forwarding is disabled",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="IP Forwarding Disabled",
                    category="Network",
                    description="Verify IP forwarding is disabled",
                    result=TestResult.FAIL,
                    message="IP forwarding may be enabled",
                    duration_ms=duration
                ))

        return suite

    # ========================================================================
    # AUTHENTICATION TESTS
    # ========================================================================

    def _test_authentication(self) -> TestSuite:
        """Test authentication settings"""
        suite = TestSuite(name="Authentication")

        if self.system == 'Linux':
            # Test: Password complexity
            start = datetime.now()
            pam_files = ['/etc/pam.d/common-password', '/etc/security/pwquality.conf']
            found_complexity = False

            for pam_file in pam_files:
                if Path(pam_file).exists():
                    try:
                        content = Path(pam_file).read_text()
                        if 'minlen' in content or 'pwquality' in content:
                            found_complexity = True
                            break
                    except:
                        pass

            duration = (datetime.now() - start).total_seconds() * 1000

            suite.tests.append(TestCase(
                name="Password Complexity",
                category="Authentication",
                description="Verify password complexity requirements",
                result=TestResult.PASS if found_complexity else TestResult.FAIL,
                message="Password complexity configured" if found_complexity else "Password complexity not configured",
                duration_ms=duration
            ))

            # Test: Password aging
            start = datetime.now()
            try:
                content = Path('/etc/login.defs').read_text()
                max_days_match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                if max_days_match and int(max_days_match.group(1)) <= 90:
                    suite.tests.append(TestCase(
                        name="Password Aging",
                        category="Authentication",
                        description="Verify password aging is configured",
                        result=TestResult.PASS,
                        message=f"Max password age: {max_days_match.group(1)} days",
                        duration_ms=(datetime.now() - start).total_seconds() * 1000
                    ))
                else:
                    suite.tests.append(TestCase(
                        name="Password Aging",
                        category="Authentication",
                        description="Verify password aging is configured",
                        result=TestResult.FAIL,
                        message="Password aging exceeds 90 days",
                        duration_ms=(datetime.now() - start).total_seconds() * 1000
                    ))
            except:
                suite.tests.append(TestCase(
                    name="Password Aging",
                    category="Authentication",
                    description="Verify password aging is configured",
                    result=TestResult.ERROR,
                    message="Could not check password aging"
                ))

        elif self.system == 'Windows':
            # Test: Account lockout policy
            start = datetime.now()
            success, output = self._run_powershell(
                "(Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).LockoutThreshold"
            )
            if not success:
                # Try local policy
                success, output = self._run_command(['net', 'accounts'])

            duration = (datetime.now() - start).total_seconds() * 1000

            if success and 'Lockout threshold' in str(output):
                match = re.search(r'Lockout threshold:\s*(\d+)', str(output))
                if match and int(match.group(1)) > 0:
                    suite.tests.append(TestCase(
                        name="Account Lockout",
                        category="Authentication",
                        description="Verify account lockout policy",
                        result=TestResult.PASS,
                        message=f"Lockout threshold: {match.group(1)}",
                        duration_ms=duration
                    ))
                else:
                    suite.tests.append(TestCase(
                        name="Account Lockout",
                        category="Authentication",
                        description="Verify account lockout policy",
                        result=TestResult.FAIL,
                        message="Account lockout not configured",
                        duration_ms=duration
                    ))

        return suite

    # ========================================================================
    # LOGGING & MONITORING TESTS
    # ========================================================================

    def _test_logging_monitoring(self) -> TestSuite:
        """Test logging and monitoring"""
        suite = TestSuite(name="Logging & Monitoring")

        if self.system == 'Linux':
            # Test: Syslog running
            start = datetime.now()
            success, output = self._run_command(['systemctl', 'is-active', 'rsyslog'])
            duration = (datetime.now() - start).total_seconds() * 1000

            if success and 'active' in output:
                suite.tests.append(TestCase(
                    name="Syslog Service",
                    category="Logging",
                    description="Verify syslog service is running",
                    result=TestResult.PASS,
                    message="rsyslog is active",
                    duration_ms=duration
                ))
            else:
                # Try syslog-ng
                success, output = self._run_command(['systemctl', 'is-active', 'syslog-ng'])
                if success and 'active' in output:
                    suite.tests.append(TestCase(
                        name="Syslog Service",
                        category="Logging",
                        description="Verify syslog service is running",
                        result=TestResult.PASS,
                        message="syslog-ng is active",
                        duration_ms=duration
                    ))
                else:
                    suite.tests.append(TestCase(
                        name="Syslog Service",
                        category="Logging",
                        description="Verify syslog service is running",
                        result=TestResult.FAIL,
                        message="No syslog service detected",
                        duration_ms=duration
                    ))

            # Test: Audit daemon
            start = datetime.now()
            success, output = self._run_command(['systemctl', 'is-active', 'auditd'])
            duration = (datetime.now() - start).total_seconds() * 1000

            suite.tests.append(TestCase(
                name="Audit Daemon",
                category="Logging",
                description="Verify auditd is running",
                result=TestResult.PASS if (success and 'active' in output) else TestResult.FAIL,
                message="auditd is active" if (success and 'active' in output) else "auditd not active",
                duration_ms=duration
            ))

            # Test: Wazuh agent
            start = datetime.now()
            wazuh_paths = ['/var/ossec', '/opt/wazuh']
            wazuh_found = any(Path(p).exists() for p in wazuh_paths)
            duration = (datetime.now() - start).total_seconds() * 1000

            suite.tests.append(TestCase(
                name="Wazuh Agent",
                category="Monitoring",
                description="Verify Wazuh/OSSEC agent is installed",
                result=TestResult.PASS if wazuh_found else TestResult.FAIL,
                message="Wazuh agent found" if wazuh_found else "Wazuh agent not found",
                duration_ms=duration
            ))

        elif self.system == 'Windows':
            # Test: Windows Event Log
            start = datetime.now()
            success, output = self._run_powershell("(Get-Service eventlog).Status")
            duration = (datetime.now() - start).total_seconds() * 1000

            suite.tests.append(TestCase(
                name="Windows Event Log",
                category="Logging",
                description="Verify Windows Event Log service",
                result=TestResult.PASS if (success and 'Running' in output) else TestResult.FAIL,
                message="Event Log service running" if (success and 'Running' in output) else "Event Log not running",
                duration_ms=duration
            ))

            # Test: Security audit policy
            start = datetime.now()
            success, output = self._run_command(['auditpol', '/get', '/category:Logon/Logoff'])
            duration = (datetime.now() - start).total_seconds() * 1000

            suite.tests.append(TestCase(
                name="Audit Policy",
                category="Logging",
                description="Verify security audit policy is configured",
                result=TestResult.PASS if (success and 'Success' in output) else TestResult.FAIL,
                message="Audit policy configured" if (success and 'Success' in output) else "Audit policy needs configuration",
                duration_ms=duration
            ))

        return suite

    # ========================================================================
    # FILE PERMISSIONS TESTS
    # ========================================================================

    def _test_file_permissions(self) -> TestSuite:
        """Test file permissions"""
        suite = TestSuite(name="File Permissions")

        if self.system == 'Linux':
            # Test: /etc/passwd permissions
            start = datetime.now()
            try:
                mode = os.stat('/etc/passwd').st_mode & 0o777
                suite.tests.append(TestCase(
                    name="/etc/passwd Permissions",
                    category="Permissions",
                    description="Verify /etc/passwd has correct permissions",
                    result=TestResult.PASS if mode <= 0o644 else TestResult.FAIL,
                    message=f"Permissions: {oct(mode)}",
                    duration_ms=(datetime.now() - start).total_seconds() * 1000
                ))
            except:
                suite.tests.append(TestCase(
                    name="/etc/passwd Permissions",
                    category="Permissions",
                    description="Verify /etc/passwd has correct permissions",
                    result=TestResult.ERROR,
                    message="Could not check permissions"
                ))

            # Test: /etc/shadow permissions
            start = datetime.now()
            try:
                mode = os.stat('/etc/shadow').st_mode & 0o777
                suite.tests.append(TestCase(
                    name="/etc/shadow Permissions",
                    category="Permissions",
                    description="Verify /etc/shadow has correct permissions",
                    result=TestResult.PASS if mode <= 0o640 else TestResult.FAIL,
                    message=f"Permissions: {oct(mode)}",
                    duration_ms=(datetime.now() - start).total_seconds() * 1000
                ))
            except:
                suite.tests.append(TestCase(
                    name="/etc/shadow Permissions",
                    category="Permissions",
                    description="Verify /etc/shadow has correct permissions",
                    result=TestResult.ERROR,
                    message="Could not check permissions"
                ))

            # Test: SSH directory permissions
            start = datetime.now()
            ssh_dir = Path.home() / '.ssh'
            if ssh_dir.exists():
                try:
                    mode = os.stat(ssh_dir).st_mode & 0o777
                    suite.tests.append(TestCase(
                        name="SSH Directory Permissions",
                        category="Permissions",
                        description="Verify ~/.ssh has correct permissions",
                        result=TestResult.PASS if mode <= 0o700 else TestResult.FAIL,
                        message=f"Permissions: {oct(mode)}",
                        duration_ms=(datetime.now() - start).total_seconds() * 1000
                    ))
                except:
                    pass

        return suite

    # ========================================================================
    # SERVICE SECURITY TESTS
    # ========================================================================

    def _test_service_security(self) -> TestSuite:
        """Test service security"""
        suite = TestSuite(name="Service Security")

        if self.system == 'Linux':
            # Test: Unnecessary services disabled
            dangerous_services = ['telnet', 'rsh', 'rlogin', 'tftp']
            start = datetime.now()

            for service in dangerous_services:
                success, output = self._run_command(['systemctl', 'is-enabled', service])
                if success and 'enabled' in output:
                    suite.tests.append(TestCase(
                        name=f"Service: {service}",
                        category="Services",
                        description=f"Verify {service} is disabled",
                        result=TestResult.FAIL,
                        message=f"{service} is enabled (should be disabled)"
                    ))

            duration = (datetime.now() - start).total_seconds() * 1000

            if not any(t.result == TestResult.FAIL for t in suite.tests):
                suite.tests.append(TestCase(
                    name="Dangerous Services",
                    category="Services",
                    description="Verify dangerous services are disabled",
                    result=TestResult.PASS,
                    message="No dangerous services enabled",
                    duration_ms=duration
                ))

        elif self.system == 'Windows':
            # Test: Remote Registry disabled
            start = datetime.now()
            success, output = self._run_powershell("(Get-Service 'RemoteRegistry' -ErrorAction SilentlyContinue).Status")
            duration = (datetime.now() - start).total_seconds() * 1000

            if not success or 'Stopped' in output:
                suite.tests.append(TestCase(
                    name="Remote Registry",
                    category="Services",
                    description="Verify Remote Registry is disabled",
                    result=TestResult.PASS,
                    message="Remote Registry is stopped/disabled",
                    duration_ms=duration
                ))
            else:
                suite.tests.append(TestCase(
                    name="Remote Registry",
                    category="Services",
                    description="Verify Remote Registry is disabled",
                    result=TestResult.FAIL,
                    message="Remote Registry is running",
                    duration_ms=duration
                ))

        return suite

    # ========================================================================
    # DETECTION RULES TESTS
    # ========================================================================

    def _test_detection_rules(self) -> TestSuite:
        """Test detection rules"""
        suite = TestSuite(name="Detection Rules")

        # Test: Tuned rules file exists
        start = datetime.now()
        rules_file = Path(__file__).parent / 'rules' / 'tuned_rules.xml'
        duration = (datetime.now() - start).total_seconds() * 1000

        if rules_file.exists():
            suite.tests.append(TestCase(
                name="Tuned Rules File",
                category="Detection",
                description="Verify tuned detection rules exist",
                result=TestResult.PASS,
                message="tuned_rules.xml exists",
                duration_ms=duration
            ))

            # Test: Rules file is valid XML
            start = datetime.now()
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(rules_file)
                root = tree.getroot()
                rule_count = len(root.findall('.//rule'))

                suite.tests.append(TestCase(
                    name="Rules XML Valid",
                    category="Detection",
                    description="Verify rules file is valid XML",
                    result=TestResult.PASS,
                    message=f"Valid XML with {rule_count} rules",
                    duration_ms=(datetime.now() - start).total_seconds() * 1000
                ))
            except Exception as e:
                suite.tests.append(TestCase(
                    name="Rules XML Valid",
                    category="Detection",
                    description="Verify rules file is valid XML",
                    result=TestResult.FAIL,
                    message=f"Invalid XML: {e}",
                    duration_ms=(datetime.now() - start).total_seconds() * 1000
                ))
        else:
            suite.tests.append(TestCase(
                name="Tuned Rules File",
                category="Detection",
                description="Verify tuned detection rules exist",
                result=TestResult.FAIL,
                message="tuned_rules.xml not found",
                duration_ms=duration
            ))

        return suite


class TestReportGenerator:
    """Generates test reports"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, suites: List[TestSuite]) -> Dict[str, str]:
        """Generate test reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        # JSON report
        json_path = self.output_dir / f"hardening_test_{timestamp}.json"
        self._save_json(suites, json_path)
        reports['json'] = str(json_path)

        # Console output
        self._print_results(suites)

        return reports

    def _save_json(self, suites: List[TestSuite], path: Path):
        """Save JSON report"""
        report = {
            'generated': datetime.now().isoformat(),
            'platform': platform.system(),
            'summary': {
                'total_tests': sum(len(s.tests) for s in suites),
                'passed': sum(s.summary()['passed'] for s in suites),
                'failed': sum(s.summary()['failed'] for s in suites),
                'skipped': sum(s.summary()['skipped'] for s in suites)
            },
            'suites': [
                {
                    'name': s.name,
                    'summary': s.summary(),
                    'tests': [
                        {
                            'name': t.name,
                            'category': t.category,
                            'description': t.description,
                            'result': t.result.value,
                            'message': t.message,
                            'duration_ms': t.duration_ms
                        }
                        for t in s.tests
                    ]
                }
                for s in suites
            ]
        }

        with open(path, 'w') as f:
            json.dump(report, f, indent=2)

    def _print_results(self, suites: List[TestSuite]):
        """Print test results to console"""
        print("\n" + "=" * 60)
        print("HARDENING VALIDATION TEST RESULTS")
        print("=" * 60)

        total_pass = 0
        total_fail = 0
        total_skip = 0

        for suite in suites:
            summary = suite.summary()
            total_pass += summary['passed']
            total_fail += summary['failed']
            total_skip += summary['skipped']

            print(f"\n{suite.name}")
            print("-" * 40)

            for test in suite.tests:
                if test.result == TestResult.PASS:
                    status = "\033[92mPASS\033[0m"
                elif test.result == TestResult.FAIL:
                    status = "\033[91mFAIL\033[0m"
                elif test.result == TestResult.SKIP:
                    status = "\033[93mSKIP\033[0m"
                else:
                    status = "\033[95mERROR\033[0m"

                print(f"  [{status}] {test.name}")
                if test.message and test.result != TestResult.PASS:
                    print(f"         {test.message}")

        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"  Total Tests: {total_pass + total_fail + total_skip}")
        print(f"  Passed:      {total_pass}")
        print(f"  Failed:      {total_fail}")
        print(f"  Skipped:     {total_skip}")

        if total_fail == 0:
            print("\n\033[92mAll hardening tests passed!\033[0m")
        else:
            print(f"\n\033[91m{total_fail} tests failed - review hardening configuration\033[0m")

        print("")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SME Network Security Assessment - Hardening Validation Tests'
    )
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for test reports'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run tests
    tester = HardeningTester()
    suites = tester.run_all_tests()

    # Generate reports
    reporter = TestReportGenerator(args.output)
    reports = reporter.generate_report(suites)

    # Return exit code based on results
    total_failed = sum(s.summary()['failed'] for s in suites)
    return 1 if total_failed > 0 else 0


if __name__ == "__main__":
    exit(main())
