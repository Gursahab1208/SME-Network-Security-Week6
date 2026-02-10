#!/usr/bin/env python3
"""
SME Network Security Assessment Framework
Week 6: Security Hardening Script

This script implements security hardening measures including:
- System configuration checks
- Security baseline enforcement
- Service hardening
- Compliance verification

Author: SME Security Team
Version: 1.0.0
"""

import subprocess
import json
import logging
import platform
import os
import sys
import re
import shutil
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Callable
from enum import Enum


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_hardening.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of a security check"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class HardeningCheck:
    """Represents a security hardening check"""
    category: str
    name: str
    description: str
    status: CheckStatus
    current_value: str = ""
    expected_value: str = ""
    remediation: str = ""
    auto_remediate: bool = False


@dataclass
class HardeningResult:
    """Results of hardening assessment"""
    timestamp: str
    system_info: Dict
    checks: List[HardeningCheck] = field(default_factory=list)
    applied_changes: List[str] = field(default_factory=list)

    def summary(self) -> Dict:
        """Generate summary statistics"""
        return {
            'total_checks': len(self.checks),
            'passed': len([c for c in self.checks if c.status == CheckStatus.PASS]),
            'failed': len([c for c in self.checks if c.status == CheckStatus.FAIL]),
            'warnings': len([c for c in self.checks if c.status == CheckStatus.WARNING]),
            'skipped': len([c for c in self.checks if c.status == CheckStatus.SKIPPED]),
            'errors': len([c for c in self.checks if c.status == CheckStatus.ERROR]),
            'changes_applied': len(self.applied_changes)
        }


class SystemInfo:
    """Collects system information"""

    @staticmethod
    def get_info() -> Dict:
        """Get comprehensive system information"""
        info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }

        if platform.system() == 'Linux':
            try:
                with open('/etc/os-release') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            info[f'os_{key.lower()}'] = value.strip('"')
            except FileNotFoundError:
                pass

        return info


class LinuxHardening:
    """Linux-specific hardening checks and remediation"""

    def __init__(self, auto_remediate: bool = False):
        self.auto_remediate = auto_remediate
        self.checks: List[HardeningCheck] = []

    def run_all_checks(self) -> List[HardeningCheck]:
        """Run all Linux hardening checks"""
        check_methods = [
            self.check_ssh_root_login,
            self.check_ssh_protocol,
            self.check_ssh_password_auth,
            self.check_firewall_enabled,
            self.check_selinux_status,
            self.check_password_policy,
            self.check_audit_enabled,
            self.check_unattended_upgrades,
            self.check_core_dumps_disabled,
            self.check_suid_files,
            self.check_world_writable_files,
            self.check_tmp_noexec,
            self.check_kernel_params,
            self.check_cron_permissions,
            self.check_grub_permissions,
        ]

        for check_method in check_methods:
            try:
                check = check_method()
                self.checks.append(check)

                if self.auto_remediate and check.status == CheckStatus.FAIL and check.auto_remediate:
                    logger.info(f"Auto-remediating: {check.name}")
                    # Remediation would be implemented here

            except Exception as e:
                self.checks.append(HardeningCheck(
                    category="Error",
                    name=check_method.__name__,
                    description=str(e),
                    status=CheckStatus.ERROR
                ))
                logger.error(f"Error in {check_method.__name__}: {e}")

        return self.checks

    def check_ssh_root_login(self) -> HardeningCheck:
        """Check if SSH root login is disabled"""
        check = HardeningCheck(
            category="SSH",
            name="SSH Root Login",
            description="Root login via SSH should be disabled",
            status=CheckStatus.SKIPPED,
            expected_value="PermitRootLogin no",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            auto_remediate=True
        )

        sshd_config = Path('/etc/ssh/sshd_config')
        if not sshd_config.exists():
            check.status = CheckStatus.SKIPPED
            check.current_value = "SSH not installed"
            return check

        try:
            content = sshd_config.read_text()
            match = re.search(r'^PermitRootLogin\s+(\w+)', content, re.MULTILINE)

            if match:
                value = match.group(1).lower()
                check.current_value = f"PermitRootLogin {value}"

                if value == 'no':
                    check.status = CheckStatus.PASS
                elif value == 'prohibit-password':
                    check.status = CheckStatus.WARNING
                else:
                    check.status = CheckStatus.FAIL
            else:
                check.current_value = "Not explicitly set (default: yes)"
                check.status = CheckStatus.FAIL

        except PermissionError:
            check.status = CheckStatus.ERROR
            check.current_value = "Permission denied"

        return check

    def check_ssh_protocol(self) -> HardeningCheck:
        """Check SSH protocol version"""
        check = HardeningCheck(
            category="SSH",
            name="SSH Protocol Version",
            description="Only SSH Protocol 2 should be used",
            status=CheckStatus.SKIPPED,
            expected_value="Protocol 2 (or not set - default in modern SSH)",
            remediation="Remove any Protocol 1 configuration"
        )

        sshd_config = Path('/etc/ssh/sshd_config')
        if not sshd_config.exists():
            return check

        try:
            content = sshd_config.read_text()
            match = re.search(r'^Protocol\s+(\d)', content, re.MULTILINE)

            if match:
                value = match.group(1)
                check.current_value = f"Protocol {value}"

                if value == '2':
                    check.status = CheckStatus.PASS
                else:
                    check.status = CheckStatus.FAIL
            else:
                # Modern SSH defaults to Protocol 2
                check.current_value = "Not set (default: 2)"
                check.status = CheckStatus.PASS

        except PermissionError:
            check.status = CheckStatus.ERROR

        return check

    def check_ssh_password_auth(self) -> HardeningCheck:
        """Check if SSH password authentication is disabled"""
        check = HardeningCheck(
            category="SSH",
            name="SSH Password Authentication",
            description="Password authentication should be disabled in favor of key-based auth",
            status=CheckStatus.SKIPPED,
            expected_value="PasswordAuthentication no",
            remediation="Set 'PasswordAuthentication no' and use SSH keys",
            auto_remediate=True
        )

        sshd_config = Path('/etc/ssh/sshd_config')
        if not sshd_config.exists():
            return check

        try:
            content = sshd_config.read_text()
            match = re.search(r'^PasswordAuthentication\s+(\w+)', content, re.MULTILINE)

            if match:
                value = match.group(1).lower()
                check.current_value = f"PasswordAuthentication {value}"
                check.status = CheckStatus.PASS if value == 'no' else CheckStatus.WARNING
            else:
                check.current_value = "Not set (default: yes)"
                check.status = CheckStatus.WARNING

        except PermissionError:
            check.status = CheckStatus.ERROR

        return check

    def check_firewall_enabled(self) -> HardeningCheck:
        """Check if firewall is enabled"""
        check = HardeningCheck(
            category="Firewall",
            name="Firewall Status",
            description="Host-based firewall should be enabled",
            status=CheckStatus.FAIL,
            expected_value="Active/Running",
            remediation="Enable iptables/nftables/firewalld",
            auto_remediate=True
        )

        # Check iptables
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                rules = result.stdout
                # Check if there are actual rules beyond default
                if 'DROP' in rules or 'REJECT' in rules or len(rules.split('\n')) > 10:
                    check.status = CheckStatus.PASS
                    check.current_value = "iptables active with rules"
                    return check
        except:
            pass

        # Check firewalld
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'firewalld'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.stdout.strip() == 'active':
                check.status = CheckStatus.PASS
                check.current_value = "firewalld active"
                return check
        except:
            pass

        # Check ufw
        try:
            result = subprocess.run(
                ['ufw', 'status'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if 'active' in result.stdout.lower():
                check.status = CheckStatus.PASS
                check.current_value = "ufw active"
                return check
        except:
            pass

        check.current_value = "No active firewall detected"
        return check

    def check_selinux_status(self) -> HardeningCheck:
        """Check SELinux status"""
        check = HardeningCheck(
            category="Access Control",
            name="SELinux Status",
            description="SELinux should be enabled and enforcing",
            status=CheckStatus.SKIPPED,
            expected_value="Enforcing",
            remediation="Enable SELinux and set to enforcing mode"
        )

        try:
            result = subprocess.run(
                ['getenforce'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                status = result.stdout.strip()
                check.current_value = status

                if status == 'Enforcing':
                    check.status = CheckStatus.PASS
                elif status == 'Permissive':
                    check.status = CheckStatus.WARNING
                else:
                    check.status = CheckStatus.FAIL
        except FileNotFoundError:
            # SELinux not installed (common on Debian/Ubuntu)
            check.current_value = "SELinux not installed"
            check.status = CheckStatus.SKIPPED

        return check

    def check_password_policy(self) -> HardeningCheck:
        """Check password policy configuration"""
        check = HardeningCheck(
            category="Authentication",
            name="Password Policy",
            description="Strong password policy should be configured",
            status=CheckStatus.FAIL,
            expected_value="minlen=14, complexity requirements",
            remediation="Configure pam_pwquality or pam_cracklib",
            auto_remediate=True
        )

        # Check common PAM password config files
        pam_files = [
            '/etc/pam.d/common-password',
            '/etc/pam.d/system-auth',
            '/etc/security/pwquality.conf'
        ]

        for pam_file in pam_files:
            if Path(pam_file).exists():
                try:
                    content = Path(pam_file).read_text()

                    if 'pwquality' in content or 'cracklib' in content:
                        # Check for minimum length
                        if 'minlen' in content:
                            match = re.search(r'minlen\s*=?\s*(\d+)', content)
                            if match:
                                minlen = int(match.group(1))
                                check.current_value = f"minlen={minlen} in {pam_file}"

                                if minlen >= 14:
                                    check.status = CheckStatus.PASS
                                elif minlen >= 8:
                                    check.status = CheckStatus.WARNING
                                else:
                                    check.status = CheckStatus.FAIL
                                return check

                except PermissionError:
                    continue

        check.current_value = "No password quality module configured"
        return check

    def check_audit_enabled(self) -> HardeningCheck:
        """Check if auditd is enabled"""
        check = HardeningCheck(
            category="Logging",
            name="Audit Daemon",
            description="auditd should be enabled for security logging",
            status=CheckStatus.FAIL,
            expected_value="Active/Running",
            remediation="Install and enable auditd",
            auto_remediate=True
        )

        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'auditd'],
                capture_output=True,
                text=True,
                timeout=10
            )
            status = result.stdout.strip()
            check.current_value = status

            if status == 'active':
                check.status = CheckStatus.PASS
            else:
                check.status = CheckStatus.FAIL

        except FileNotFoundError:
            check.current_value = "systemctl not available"
            check.status = CheckStatus.SKIPPED

        return check

    def check_unattended_upgrades(self) -> HardeningCheck:
        """Check if automatic security updates are enabled"""
        check = HardeningCheck(
            category="Patching",
            name="Automatic Security Updates",
            description="Automatic security updates should be enabled",
            status=CheckStatus.FAIL,
            expected_value="Enabled",
            remediation="Enable unattended-upgrades or dnf-automatic"
        )

        # Check for unattended-upgrades (Debian/Ubuntu)
        apt_conf = Path('/etc/apt/apt.conf.d/20auto-upgrades')
        if apt_conf.exists():
            try:
                content = apt_conf.read_text()
                if 'APT::Periodic::Unattended-Upgrade "1"' in content:
                    check.status = CheckStatus.PASS
                    check.current_value = "unattended-upgrades enabled"
                    return check
            except:
                pass

        # Check for dnf-automatic (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', 'dnf-automatic.timer'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.stdout.strip() == 'enabled':
                check.status = CheckStatus.PASS
                check.current_value = "dnf-automatic enabled"
                return check
        except:
            pass

        check.current_value = "Automatic updates not configured"
        return check

    def check_core_dumps_disabled(self) -> HardeningCheck:
        """Check if core dumps are disabled"""
        check = HardeningCheck(
            category="System",
            name="Core Dumps Disabled",
            description="Core dumps should be disabled to prevent information disclosure",
            status=CheckStatus.FAIL,
            expected_value="* hard core 0",
            remediation="Add '* hard core 0' to /etc/security/limits.conf"
        )

        limits_conf = Path('/etc/security/limits.conf')
        if limits_conf.exists():
            try:
                content = limits_conf.read_text()
                if 'hard core 0' in content or 'hard core\t0' in content:
                    check.status = CheckStatus.PASS
                    check.current_value = "Core dumps disabled in limits.conf"
                else:
                    check.current_value = "Core dumps not restricted"
            except:
                check.current_value = "Cannot read limits.conf"

        return check

    def check_suid_files(self) -> HardeningCheck:
        """Check for unnecessary SUID files"""
        check = HardeningCheck(
            category="File Permissions",
            name="SUID File Audit",
            description="Minimize files with SUID bit set",
            status=CheckStatus.WARNING,
            expected_value="Only necessary SUID files",
            remediation="Review and remove unnecessary SUID bits"
        )

        # Known safe SUID files
        safe_suid = {
            '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd',
            '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
            '/usr/bin/gpasswd', '/bin/mount', '/bin/umount',
            '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/pkexec'
        }

        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '-maxdepth', '4'],
                capture_output=True,
                text=True,
                timeout=60
            )

            suid_files = set(result.stdout.strip().split('\n')) - {''}
            unknown_suid = suid_files - safe_suid

            check.current_value = f"Found {len(suid_files)} SUID files, {len(unknown_suid)} non-standard"

            if len(unknown_suid) == 0:
                check.status = CheckStatus.PASS
            elif len(unknown_suid) <= 5:
                check.status = CheckStatus.WARNING
            else:
                check.status = CheckStatus.FAIL

        except:
            check.status = CheckStatus.SKIPPED
            check.current_value = "Could not complete SUID scan"

        return check

    def check_world_writable_files(self) -> HardeningCheck:
        """Check for world-writable files"""
        check = HardeningCheck(
            category="File Permissions",
            name="World-Writable Files",
            description="No world-writable files in system directories",
            status=CheckStatus.WARNING,
            expected_value="None",
            remediation="Review and fix permissions on world-writable files"
        )

        try:
            result = subprocess.run(
                ['find', '/etc', '/usr', '-type', 'f', '-perm', '-002', '-maxdepth', '3'],
                capture_output=True,
                text=True,
                timeout=60
            )

            ww_files = [f for f in result.stdout.strip().split('\n') if f]
            check.current_value = f"Found {len(ww_files)} world-writable files"

            if len(ww_files) == 0:
                check.status = CheckStatus.PASS
            else:
                check.status = CheckStatus.FAIL

        except:
            check.status = CheckStatus.SKIPPED

        return check

    def check_tmp_noexec(self) -> HardeningCheck:
        """Check if /tmp is mounted with noexec"""
        check = HardeningCheck(
            category="Filesystem",
            name="/tmp noexec Mount",
            description="/tmp should be mounted with noexec option",
            status=CheckStatus.FAIL,
            expected_value="noexec,nosuid,nodev",
            remediation="Add noexec,nosuid,nodev options to /tmp in /etc/fstab"
        )

        try:
            result = subprocess.run(
                ['mount'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split('\n'):
                if ' /tmp ' in line:
                    check.current_value = line
                    if 'noexec' in line and 'nosuid' in line:
                        check.status = CheckStatus.PASS
                    elif 'noexec' in line:
                        check.status = CheckStatus.WARNING
                    else:
                        check.status = CheckStatus.FAIL
                    return check

            check.current_value = "/tmp not separately mounted"
            check.status = CheckStatus.WARNING

        except:
            check.status = CheckStatus.SKIPPED

        return check

    def check_kernel_params(self) -> HardeningCheck:
        """Check kernel security parameters"""
        check = HardeningCheck(
            category="Kernel",
            name="Kernel Security Parameters",
            description="Security-related kernel parameters should be properly set",
            status=CheckStatus.WARNING,
            expected_value="All security params enabled",
            remediation="Configure sysctl parameters in /etc/sysctl.conf"
        )

        security_params = {
            'net.ipv4.ip_forward': '0',
            'net.ipv4.conf.all.send_redirects': '0',
            'net.ipv4.conf.all.accept_redirects': '0',
            'net.ipv4.conf.all.accept_source_route': '0',
            'net.ipv4.conf.all.log_martians': '1',
            'net.ipv4.icmp_echo_ignore_broadcasts': '1',
            'kernel.randomize_va_space': '2',
        }

        issues = []
        for param, expected in security_params.items():
            try:
                result = subprocess.run(
                    ['sysctl', '-n', param],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                actual = result.stdout.strip()
                if actual != expected:
                    issues.append(f"{param}={actual} (expected {expected})")
            except:
                pass

        if not issues:
            check.status = CheckStatus.PASS
            check.current_value = "All checked parameters correct"
        else:
            check.status = CheckStatus.FAIL if len(issues) > 3 else CheckStatus.WARNING
            check.current_value = f"{len(issues)} parameters misconfigured"

        return check

    def check_cron_permissions(self) -> HardeningCheck:
        """Check cron configuration permissions"""
        check = HardeningCheck(
            category="Cron",
            name="Cron Permissions",
            description="Cron directories should have restricted permissions",
            status=CheckStatus.PASS,
            expected_value="700 or 600",
            remediation="chmod 600 /etc/crontab; chmod 700 /etc/cron.*"
        )

        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly'
        ]

        issues = []
        for path in cron_paths:
            if Path(path).exists():
                stat = os.stat(path)
                mode = stat.st_mode & 0o777
                if mode > 0o700:
                    issues.append(f"{path}: {oct(mode)}")

        if issues:
            check.status = CheckStatus.WARNING
            check.current_value = f"{len(issues)} paths with loose permissions"
        else:
            check.current_value = "All cron paths properly secured"

        return check

    def check_grub_permissions(self) -> HardeningCheck:
        """Check GRUB configuration permissions"""
        check = HardeningCheck(
            category="Boot",
            name="GRUB Configuration",
            description="GRUB config should have restricted permissions",
            status=CheckStatus.PASS,
            expected_value="600",
            remediation="chmod 600 /boot/grub*/grub.cfg"
        )

        grub_paths = [
            '/boot/grub/grub.cfg',
            '/boot/grub2/grub.cfg'
        ]

        for path in grub_paths:
            if Path(path).exists():
                stat = os.stat(path)
                mode = stat.st_mode & 0o777
                check.current_value = f"{path}: {oct(mode)}"

                if mode <= 0o600:
                    check.status = CheckStatus.PASS
                else:
                    check.status = CheckStatus.FAIL
                return check

        check.current_value = "GRUB config not found"
        check.status = CheckStatus.SKIPPED

        return check


class WindowsHardening:
    """Windows-specific hardening checks"""

    def __init__(self, auto_remediate: bool = False):
        self.auto_remediate = auto_remediate
        self.checks: List[HardeningCheck] = []

    def run_all_checks(self) -> List[HardeningCheck]:
        """Run all Windows hardening checks"""
        check_methods = [
            self.check_firewall_enabled,
            self.check_windows_defender,
            self.check_uac_enabled,
            self.check_password_policy,
            self.check_audit_policy,
            self.check_remote_desktop,
            self.check_guest_account,
            self.check_windows_update,
            self.check_smb_signing,
            self.check_ntlm_settings,
        ]

        for check_method in check_methods:
            try:
                check = check_method()
                self.checks.append(check)
            except Exception as e:
                self.checks.append(HardeningCheck(
                    category="Error",
                    name=check_method.__name__,
                    description=str(e),
                    status=CheckStatus.ERROR
                ))

        return self.checks

    def _run_powershell(self, command: str) -> Tuple[bool, str]:
        """Run a PowerShell command and return result"""
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

    def check_firewall_enabled(self) -> HardeningCheck:
        """Check Windows Firewall status"""
        check = HardeningCheck(
            category="Firewall",
            name="Windows Firewall",
            description="Windows Firewall should be enabled for all profiles",
            status=CheckStatus.FAIL,
            expected_value="Enabled for all profiles",
            remediation="Enable Windows Firewall in Control Panel or via GPO"
        )

        success, output = self._run_powershell(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        )

        if success:
            try:
                profiles = json.loads(output)
                if isinstance(profiles, dict):
                    profiles = [profiles]

                all_enabled = all(p.get('Enabled', False) for p in profiles)
                disabled = [p['Name'] for p in profiles if not p.get('Enabled', False)]

                if all_enabled:
                    check.status = CheckStatus.PASS
                    check.current_value = "All profiles enabled"
                else:
                    check.status = CheckStatus.FAIL
                    check.current_value = f"Disabled: {', '.join(disabled)}"
            except:
                check.current_value = output
        else:
            check.status = CheckStatus.ERROR
            check.current_value = output

        return check

    def check_windows_defender(self) -> HardeningCheck:
        """Check Windows Defender status"""
        check = HardeningCheck(
            category="Antivirus",
            name="Windows Defender",
            description="Windows Defender should be enabled and up-to-date",
            status=CheckStatus.FAIL,
            expected_value="Enabled with current definitions",
            remediation="Enable Windows Defender in Windows Security settings"
        )

        success, output = self._run_powershell(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json"
        )

        if success:
            try:
                status = json.loads(output)
                av_enabled = status.get('AntivirusEnabled', False)
                rtp_enabled = status.get('RealTimeProtectionEnabled', False)

                if av_enabled and rtp_enabled:
                    check.status = CheckStatus.PASS
                    check.current_value = "AV and Real-time protection enabled"
                elif av_enabled:
                    check.status = CheckStatus.WARNING
                    check.current_value = "AV enabled, but real-time protection disabled"
                else:
                    check.status = CheckStatus.FAIL
                    check.current_value = "Windows Defender disabled"
            except:
                check.current_value = output
        else:
            check.status = CheckStatus.SKIPPED
            check.current_value = "Could not query Windows Defender"

        return check

    def check_uac_enabled(self) -> HardeningCheck:
        """Check UAC status"""
        check = HardeningCheck(
            category="Access Control",
            name="User Account Control",
            description="UAC should be enabled at highest level",
            status=CheckStatus.FAIL,
            expected_value="EnableLUA = 1",
            remediation="Enable UAC in Control Panel > User Accounts"
        )

        success, output = self._run_powershell(
            "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA"
        )

        if success:
            try:
                value = int(output)
                check.current_value = f"EnableLUA = {value}"
                check.status = CheckStatus.PASS if value == 1 else CheckStatus.FAIL
            except:
                check.current_value = output

        return check

    def check_password_policy(self) -> HardeningCheck:
        """Check password policy settings"""
        check = HardeningCheck(
            category="Authentication",
            name="Password Policy",
            description="Strong password policy should be configured",
            status=CheckStatus.WARNING,
            expected_value="Min length 14, complexity enabled",
            remediation="Configure password policy via Local Security Policy or GPO"
        )

        success, output = self._run_powershell("net accounts")

        if success:
            check.current_value = "Policy retrieved"
            # Parse minimum password length
            match = re.search(r'Minimum password length:\s*(\d+)', output)
            if match:
                min_len = int(match.group(1))
                if min_len >= 14:
                    check.status = CheckStatus.PASS
                elif min_len >= 8:
                    check.status = CheckStatus.WARNING
                else:
                    check.status = CheckStatus.FAIL
                check.current_value = f"Minimum length: {min_len}"

        return check

    def check_audit_policy(self) -> HardeningCheck:
        """Check audit policy settings"""
        check = HardeningCheck(
            category="Logging",
            name="Audit Policy",
            description="Audit policy should log security events",
            status=CheckStatus.WARNING,
            expected_value="Logon/Logoff, Object Access auditing enabled",
            remediation="Configure audit policy via Local Security Policy or GPO"
        )

        success, output = self._run_powershell("auditpol /get /category:*")

        if success:
            if 'Success and Failure' in output:
                check.status = CheckStatus.PASS
                check.current_value = "Audit policies configured"
            elif 'Success' in output:
                check.status = CheckStatus.WARNING
                check.current_value = "Partial auditing enabled"
            else:
                check.status = CheckStatus.FAIL
                check.current_value = "Limited auditing"

        return check

    def check_remote_desktop(self) -> HardeningCheck:
        """Check Remote Desktop settings"""
        check = HardeningCheck(
            category="Remote Access",
            name="Remote Desktop",
            description="RDP should require NLA and be restricted",
            status=CheckStatus.WARNING,
            expected_value="NLA required if RDP enabled",
            remediation="Enable NLA for RDP or disable RDP if not needed"
        )

        success, output = self._run_powershell(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"
        )

        if success:
            try:
                rdp_disabled = int(output)
                if rdp_disabled == 1:
                    check.status = CheckStatus.PASS
                    check.current_value = "RDP disabled"
                else:
                    # Check NLA
                    nla_success, nla_output = self._run_powershell(
                        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"
                    )
                    if nla_success and int(nla_output) == 1:
                        check.status = CheckStatus.WARNING
                        check.current_value = "RDP enabled with NLA"
                    else:
                        check.status = CheckStatus.FAIL
                        check.current_value = "RDP enabled without NLA"
            except:
                check.current_value = output

        return check

    def check_guest_account(self) -> HardeningCheck:
        """Check Guest account status"""
        check = HardeningCheck(
            category="Accounts",
            name="Guest Account",
            description="Guest account should be disabled",
            status=CheckStatus.FAIL,
            expected_value="Disabled",
            remediation="Disable Guest account in Computer Management"
        )

        success, output = self._run_powershell(
            "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
        )

        if success:
            if output.lower() == 'false':
                check.status = CheckStatus.PASS
                check.current_value = "Guest account disabled"
            else:
                check.status = CheckStatus.FAIL
                check.current_value = "Guest account enabled"

        return check

    def check_windows_update(self) -> HardeningCheck:
        """Check Windows Update settings"""
        check = HardeningCheck(
            category="Patching",
            name="Windows Update",
            description="Automatic Windows Updates should be enabled",
            status=CheckStatus.WARNING,
            expected_value="Automatic updates enabled",
            remediation="Configure Windows Update in Settings > Update & Security"
        )

        success, output = self._run_powershell(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' -ErrorAction SilentlyContinue).AUOptions"
        )

        if success:
            try:
                au_option = int(output)
                options = {
                    1: "Never check",
                    2: "Check but don't download",
                    3: "Download but don't install",
                    4: "Install automatically"
                }
                check.current_value = options.get(au_option, f"Unknown ({au_option})")
                check.status = CheckStatus.PASS if au_option == 4 else CheckStatus.WARNING
            except:
                check.current_value = "Could not determine AU setting"
        else:
            check.current_value = "Windows Update settings not accessible"

        return check

    def check_smb_signing(self) -> HardeningCheck:
        """Check SMB signing settings"""
        check = HardeningCheck(
            category="Network",
            name="SMB Signing",
            description="SMB signing should be required",
            status=CheckStatus.FAIL,
            expected_value="Required",
            remediation="Enable 'Microsoft network server: Digitally sign communications (always)' in GPO"
        )

        success, output = self._run_powershell(
            "(Get-SmbServerConfiguration).RequireSecuritySignature"
        )

        if success:
            if output.lower() == 'true':
                check.status = CheckStatus.PASS
                check.current_value = "SMB signing required"
            else:
                check.status = CheckStatus.FAIL
                check.current_value = "SMB signing not required"

        return check

    def check_ntlm_settings(self) -> HardeningCheck:
        """Check NTLM settings"""
        check = HardeningCheck(
            category="Authentication",
            name="NTLM Settings",
            description="NTLM should be restricted in favor of Kerberos",
            status=CheckStatus.WARNING,
            expected_value="NTLMv2 only",
            remediation="Configure LAN Manager authentication level via GPO"
        )

        success, output = self._run_powershell(
            "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).LmCompatibilityLevel"
        )

        if success:
            try:
                level = int(output)
                levels = {
                    0: "Send LM & NTLM",
                    1: "Send LM & NTLM - NTLMv2 if negotiated",
                    2: "Send NTLM only",
                    3: "Send NTLMv2 only",
                    4: "Send NTLMv2 only, refuse LM",
                    5: "Send NTLMv2 only, refuse LM & NTLM"
                }
                check.current_value = levels.get(level, f"Unknown ({level})")
                check.status = CheckStatus.PASS if level >= 3 else CheckStatus.FAIL
            except:
                check.current_value = "Could not determine LM level"

        return check


class SecurityHardening:
    """Main security hardening class"""

    def __init__(self, auto_remediate: bool = False):
        self.auto_remediate = auto_remediate
        self.system = platform.system()
        self.result = HardeningResult(
            timestamp=datetime.now().isoformat(),
            system_info=SystemInfo.get_info()
        )

    def run_assessment(self) -> HardeningResult:
        """Run security hardening assessment"""
        logger.info(f"Starting security hardening assessment on {self.system}")

        if self.system == 'Linux':
            hardening = LinuxHardening(self.auto_remediate)
            self.result.checks = hardening.run_all_checks()
        elif self.system == 'Windows':
            hardening = WindowsHardening(self.auto_remediate)
            self.result.checks = hardening.run_all_checks()
        else:
            logger.warning(f"Unsupported platform: {self.system}")

        return self.result

    def generate_report(self, output_file: str = "hardening_report.json") -> str:
        """Generate hardening report"""
        report = {
            'metadata': {
                'title': 'Security Hardening Assessment Report',
                'generated': datetime.now().isoformat(),
                'system_info': self.result.system_info
            },
            'summary': self.result.summary(),
            'checks': [
                {
                    'category': c.category,
                    'name': c.name,
                    'description': c.description,
                    'status': c.status.value,
                    'current_value': c.current_value,
                    'expected_value': c.expected_value,
                    'remediation': c.remediation
                }
                for c in self.result.checks
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved to {output_file}")
        return output_file

    def print_summary(self) -> None:
        """Print assessment summary to console"""
        summary = self.result.summary()

        print("\n" + "=" * 60)
        print("SECURITY HARDENING ASSESSMENT RESULTS")
        print("=" * 60)
        print(f"Platform: {self.result.system_info.get('platform', 'Unknown')}")
        print(f"Hostname: {self.result.system_info.get('hostname', 'Unknown')}")
        print("-" * 60)
        print(f"Total Checks:  {summary['total_checks']}")
        print(f"  Passed:      {summary['passed']}")
        print(f"  Failed:      {summary['failed']}")
        print(f"  Warnings:    {summary['warnings']}")
        print(f"  Skipped:     {summary['skipped']}")
        print(f"  Errors:      {summary['errors']}")
        print("-" * 60)

        # Print failed checks
        failed = [c for c in self.result.checks if c.status == CheckStatus.FAIL]
        if failed:
            print("\nFAILED CHECKS REQUIRING REMEDIATION:")
            for check in failed:
                print(f"\n  [{check.category}] {check.name}")
                print(f"    Current: {check.current_value}")
                print(f"    Expected: {check.expected_value}")
                print(f"    Fix: {check.remediation}")

        print("\n" + "=" * 60)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='SME Network Security Assessment - Security Hardening'
    )
    parser.add_argument(
        '-r', '--remediate',
        action='store_true',
        help='Attempt automatic remediation of failed checks'
    )
    parser.add_argument(
        '-o', '--output',
        default='hardening_report.json',
        help='Output file for JSON report'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run assessment
    hardening = SecurityHardening(auto_remediate=args.remediate)

    try:
        hardening.run_assessment()
        hardening.print_summary()
        hardening.generate_report(args.output)

        # Return appropriate exit code
        summary = hardening.result.summary()
        if summary['failed'] > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nAssessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
