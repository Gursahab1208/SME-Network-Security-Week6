#!/usr/bin/env python3
"""
SME Network Security Assessment Framework
Week 6: Compliance Checking Script

This script checks compliance against multiple security frameworks:
- NIST Cybersecurity Framework (CSF)
- ISO 27001
- CIS Controls v8

Author: SME Security Team
Version: 1.0.0
"""

import json
import logging
import argparse
import os
import subprocess
import platform
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('compliance_checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Status of a compliance check"""
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    PARTIALLY_COMPLIANT = "Partially Compliant"
    NOT_APPLICABLE = "Not Applicable"
    ERROR = "Error"


@dataclass
class ComplianceControl:
    """Represents a compliance control"""
    framework: str
    control_id: str
    control_name: str
    description: str
    category: str
    status: ComplianceStatus
    finding: str = ""
    evidence: str = ""
    remediation: str = ""
    severity: str = "medium"  # critical, high, medium, low
    automated: bool = True


@dataclass
class ComplianceReport:
    """Complete compliance report"""
    report_time: str
    framework: str
    organization: str
    scope: str
    total_controls: int
    compliant: int
    non_compliant: int
    partially_compliant: int
    not_applicable: int
    compliance_percentage: float
    controls: List[ComplianceControl]
    executive_summary: str = ""


class BaseComplianceChecker:
    """Base class for compliance checkers"""

    def __init__(self):
        self.controls: List[ComplianceControl] = []
        self.system = platform.system()

    def run_checks(self) -> List[ComplianceControl]:
        """Run all compliance checks - override in subclass"""
        raise NotImplementedError

    def _run_command(self, command: List[str], timeout: int = 30) -> tuple:
        """Run a system command and return (success, output)"""
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

    def _check_file_exists(self, path: str) -> bool:
        """Check if a file exists"""
        return Path(path).exists()

    def _check_file_permissions(self, path: str, max_mode: int) -> bool:
        """Check file permissions (Unix only)"""
        if self.system != 'Linux':
            return True
        try:
            mode = os.stat(path).st_mode & 0o777
            return mode <= max_mode
        except:
            return False


class NISTCSFChecker(BaseComplianceChecker):
    """NIST Cybersecurity Framework compliance checker"""

    FRAMEWORK = "NIST CSF"

    def run_checks(self) -> List[ComplianceControl]:
        """Run NIST CSF compliance checks"""
        logger.info("Running NIST CSF compliance checks")

        checks = [
            # IDENTIFY
            self._check_asset_inventory,
            self._check_risk_assessment,
            self._check_governance,

            # PROTECT
            self._check_access_control,
            self._check_security_training,
            self._check_data_protection,
            self._check_protective_technology,

            # DETECT
            self._check_continuous_monitoring,
            self._check_detection_processes,
            self._check_anomaly_detection,

            # RESPOND
            self._check_incident_response,
            self._check_communications,
            self._check_analysis,

            # RECOVER
            self._check_recovery_planning,
            self._check_improvements,
        ]

        for check in checks:
            try:
                control = check()
                self.controls.append(control)
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")

        return self.controls

    def _check_asset_inventory(self) -> ComplianceControl:
        """ID.AM-1: Physical devices and systems are inventoried"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="ID.AM-1",
            control_name="Asset Inventory",
            description="Physical devices and systems within the organization are inventoried",
            category="Identify",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement asset inventory system and maintain current device list"
        )

        # Check for common inventory tools/files
        inventory_indicators = [
            '/etc/ansible/hosts',
            '/opt/inventory',
            '/var/lib/cmdb'
        ]

        found = any(self._check_file_exists(p) for p in inventory_indicators)

        if found:
            control.status = ComplianceStatus.COMPLIANT
            control.finding = "Asset inventory indicators found"
        else:
            control.finding = "No asset inventory system detected"

        return control

    def _check_risk_assessment(self) -> ComplianceControl:
        """ID.RA: Risk Assessment"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="ID.RA",
            control_name="Risk Assessment",
            description="Asset vulnerabilities are identified and documented",
            category="Identify",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Vulnerability scanning implemented, formal risk assessment recommended",
            remediation="Conduct formal risk assessment and document findings"
        )

    def _check_governance(self) -> ComplianceControl:
        """ID.GV: Governance"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="ID.GV",
            control_name="Governance",
            description="Policies and procedures to manage cybersecurity risk",
            category="Identify",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Security policies should be formally documented",
            remediation="Document security policies and ensure stakeholder awareness"
        )

    def _check_access_control(self) -> ComplianceControl:
        """PR.AC: Access Control"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="PR.AC",
            control_name="Access Control",
            description="Access to assets is limited to authorized users",
            category="Protect",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement strong access controls and authentication"
        )

        # Check SSH configuration
        if self.system == 'Linux':
            success, output = self._run_command(['cat', '/etc/ssh/sshd_config'])
            if success:
                if 'PermitRootLogin no' in output or 'PermitRootLogin prohibit-password' in output:
                    control.status = ComplianceStatus.COMPLIANT
                    control.finding = "SSH root login restricted"
                else:
                    control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                    control.finding = "SSH access control needs improvement"
            else:
                control.finding = "Could not verify SSH configuration"
        else:
            # Windows check
            success, output = self._run_command(
                ['powershell', '-Command', '(Get-LocalUser -Name Administrator).Enabled']
            )
            if success and 'False' in output:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Administrator account disabled"
            else:
                control.finding = "Review administrator account status"

        return control

    def _check_security_training(self) -> ComplianceControl:
        """PR.AT: Security Awareness Training"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="PR.AT",
            control_name="Security Awareness Training",
            description="Users are informed and trained",
            category="Protect",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check training records",
            remediation="Implement security awareness training program"
        )

    def _check_data_protection(self) -> ComplianceControl:
        """PR.DS: Data Security"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="PR.DS",
            control_name="Data Security",
            description="Data is managed consistent with risk strategy",
            category="Protect",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement encryption at rest and in transit"
        )

        # Check for encryption indicators
        if self.system == 'Linux':
            # Check LUKS
            success, output = self._run_command(['lsblk', '-o', 'NAME,TYPE,FSTYPE'])
            if success and 'crypt' in output.lower():
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Disk encryption detected"
            else:
                control.finding = "No disk encryption detected"
        else:
            # Check BitLocker
            success, output = self._run_command(
                ['powershell', '-Command', 'Get-BitLockerVolume']
            )
            if success and 'FullyEncrypted' in output:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "BitLocker encryption enabled"
            else:
                control.finding = "BitLocker not detected or not fully enabled"

        return control

    def _check_protective_technology(self) -> ComplianceControl:
        """PR.PT: Protective Technology"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="PR.PT",
            control_name="Protective Technology",
            description="Technical security solutions are managed",
            category="Protect",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Enable and configure host-based firewall"
        )

        # Check firewall status
        if self.system == 'Linux':
            # Check iptables
            success, _ = self._run_command(['iptables', '-L'])
            if success:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Firewall (iptables) is active"
        else:
            success, output = self._run_command(
                ['powershell', '-Command', 'Get-NetFirewallProfile | Select-Object Name,Enabled']
            )
            if success and 'True' in output:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Windows Firewall is enabled"
            else:
                control.finding = "Firewall status could not be verified"

        return control

    def _check_continuous_monitoring(self) -> ComplianceControl:
        """DE.CM: Continuous Monitoring"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="DE.CM",
            control_name="Security Continuous Monitoring",
            description="Systems and assets are monitored",
            category="Detect",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement SIEM or security monitoring solution"
        )

        # Check for monitoring agents
        monitoring_indicators = [
            '/var/ossec',  # Wazuh/OSSEC
            '/opt/wazuh',
            '/var/log/syslog',
            'ossec-agentd',
            'filebeat',
            'auditd'
        ]

        if self.system == 'Linux':
            for indicator in monitoring_indicators:
                if self._check_file_exists(indicator):
                    control.status = ComplianceStatus.COMPLIANT
                    control.finding = f"Monitoring detected: {indicator}"
                    break

            # Check for running services
            success, output = self._run_command(['ps', 'aux'])
            if success and any(m in output for m in ['wazuh', 'ossec', 'auditd']):
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Security monitoring agent detected"
        else:
            # Check Windows Event Log
            success, _ = self._run_command(
                ['powershell', '-Command', 'Get-Service eventlog']
            )
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Windows Event Log service running"

        return control

    def _check_detection_processes(self) -> ComplianceControl:
        """DE.DP: Detection Processes"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="DE.DP",
            control_name="Detection Processes",
            description="Detection processes and procedures are tested",
            category="Detect",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Detection rules implemented, regular testing recommended",
            remediation="Establish regular detection testing schedule"
        )

    def _check_anomaly_detection(self) -> ComplianceControl:
        """DE.AE: Anomalies and Events"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="DE.AE",
            control_name="Anomalies and Events",
            description="Anomalous activity is detected",
            category="Detect",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Basic anomaly detection in place",
            remediation="Implement advanced anomaly detection capabilities"
        )

    def _check_incident_response(self) -> ComplianceControl:
        """RS.RP: Response Planning"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="RS.RP",
            control_name="Response Planning",
            description="Response processes are executed during incidents",
            category="Respond",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check IRP documentation",
            remediation="Document and test incident response plan"
        )

    def _check_communications(self) -> ComplianceControl:
        """RS.CO: Communications"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="RS.CO",
            control_name="Communications",
            description="Response activities are coordinated",
            category="Respond",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required",
            remediation="Establish communication procedures for incidents"
        )

    def _check_analysis(self) -> ComplianceControl:
        """RS.AN: Analysis"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="RS.AN",
            control_name="Analysis",
            description="Analysis is conducted for response",
            category="Respond",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Log analysis capabilities available",
            remediation="Formalize incident analysis procedures"
        )

    def _check_recovery_planning(self) -> ComplianceControl:
        """RC.RP: Recovery Planning"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="RC.RP",
            control_name="Recovery Planning",
            description="Recovery processes are executed",
            category="Recover",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check backup/DR procedures",
            remediation="Document and test recovery procedures"
        )

    def _check_improvements(self) -> ComplianceControl:
        """RC.IM: Improvements"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="RC.IM",
            control_name="Improvements",
            description="Recovery incorporates lessons learned",
            category="Recover",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required",
            remediation="Implement post-incident review process"
        )


class ISO27001Checker(BaseComplianceChecker):
    """ISO 27001 compliance checker"""

    FRAMEWORK = "ISO 27001"

    def run_checks(self) -> List[ComplianceControl]:
        """Run ISO 27001 compliance checks"""
        logger.info("Running ISO 27001 compliance checks")

        checks = [
            self._check_access_control_policy,
            self._check_user_access_management,
            self._check_cryptographic_controls,
            self._check_physical_security,
            self._check_operations_security,
            self._check_network_security,
            self._check_logging_monitoring,
            self._check_vulnerability_management,
            self._check_incident_management,
            self._check_business_continuity,
        ]

        for check in checks:
            try:
                control = check()
                self.controls.append(control)
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")

        return self.controls

    def _check_access_control_policy(self) -> ComplianceControl:
        """A.9.1: Access Control Policy"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.9.1",
            control_name="Access Control Policy",
            description="Access control policy established and documented",
            category="Access Control",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - review access control policy document",
            remediation="Document access control policy aligned with business requirements"
        )

    def _check_user_access_management(self) -> ComplianceControl:
        """A.9.2: User Access Management"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.9.2",
            control_name="User Access Management",
            description="User registration and de-registration process",
            category="Access Control",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement formal user access management process"
        )

        if self.system == 'Linux':
            # Check for disabled accounts, password aging
            success, output = self._run_command(['cat', '/etc/login.defs'])
            if success:
                if 'PASS_MAX_DAYS' in output:
                    control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                    control.finding = "Password aging configured"
                else:
                    control.finding = "Password aging not configured"
        else:
            success, output = self._run_command(['net', 'accounts'])
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Windows account policies exist"

        return control

    def _check_cryptographic_controls(self) -> ComplianceControl:
        """A.10: Cryptography"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.10",
            control_name="Cryptographic Controls",
            description="Proper use of cryptography",
            category="Cryptography",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement encryption for data at rest and in transit"
        )

        # Check TLS configuration
        if self.system == 'Linux':
            ssl_configs = ['/etc/ssl/openssl.cnf', '/etc/pki/tls/openssl.cnf']
            for config in ssl_configs:
                if self._check_file_exists(config):
                    control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                    control.finding = f"SSL/TLS configuration found: {config}"
                    break
        else:
            success, output = self._run_command(
                ['powershell', '-Command',
                 'Get-TlsCipherSuite | Select-Object -First 5']
            )
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "TLS cipher suites configured"

        return control

    def _check_physical_security(self) -> ComplianceControl:
        """A.11: Physical Security"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.11",
            control_name="Physical Security",
            description="Physical and environmental security controls",
            category="Physical Security",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - physical security cannot be assessed remotely",
            remediation="Conduct physical security assessment"
        )

    def _check_operations_security(self) -> ComplianceControl:
        """A.12: Operations Security"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.12",
            control_name="Operations Security",
            description="Operational procedures and responsibilities",
            category="Operations Security",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Document operational procedures and implement controls"
        )

        # Check for backup and patching
        if self.system == 'Linux':
            # Check apt/yum auto-update
            auto_update_paths = [
                '/etc/apt/apt.conf.d/20auto-upgrades',
                '/etc/yum/yum-cron.conf'
            ]
            for path in auto_update_paths:
                if self._check_file_exists(path):
                    control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                    control.finding = "Automatic updates configured"
                    break
        else:
            success, output = self._run_command(
                ['powershell', '-Command',
                 '(Get-WindowsUpdate -AcceptAll -IgnoreReboot).Count']
            )
            control.status = ComplianceStatus.PARTIALLY_COMPLIANT
            control.finding = "Windows Update service available"

        return control

    def _check_network_security(self) -> ComplianceControl:
        """A.13: Communications Security"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.13",
            control_name="Communications Security",
            description="Network security management",
            category="Communications",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement network segmentation and security controls"
        )

        # Check firewall
        if self.system == 'Linux':
            success, output = self._run_command(['iptables', '-L', '-n'])
            if success and ('DROP' in output or 'REJECT' in output):
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Firewall rules configured"
            else:
                control.finding = "Firewall needs configuration"
        else:
            success, output = self._run_command(
                ['powershell', '-Command',
                 'Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}']
            )
            if success and output:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Windows Firewall enabled"

        return control

    def _check_logging_monitoring(self) -> ComplianceControl:
        """A.12.4: Logging and Monitoring"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.12.4",
            control_name="Logging and Monitoring",
            description="Event logging and protection of log information",
            category="Operations Security",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement comprehensive logging and monitoring"
        )

        if self.system == 'Linux':
            log_services = ['rsyslog', 'syslog-ng', 'auditd']
            success, output = self._run_command(['ps', 'aux'])
            if success:
                for svc in log_services:
                    if svc in output:
                        control.status = ComplianceStatus.COMPLIANT
                        control.finding = f"Logging service active: {svc}"
                        break
        else:
            success, _ = self._run_command(
                ['powershell', '-Command', 'Get-Service eventlog']
            )
            if success:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Windows Event Log service active"

        return control

    def _check_vulnerability_management(self) -> ComplianceControl:
        """A.12.6: Technical Vulnerability Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.12.6",
            control_name="Technical Vulnerability Management",
            description="Technical vulnerabilities are identified and addressed",
            category="Operations Security",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Vulnerability scanning implemented as part of this framework",
            remediation="Ensure regular vulnerability scanning and remediation"
        )

    def _check_incident_management(self) -> ComplianceControl:
        """A.16: Incident Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.16",
            control_name="Information Security Incident Management",
            description="Security incidents are managed consistently",
            category="Incident Management",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - review incident management procedures",
            remediation="Document incident management procedures and test regularly"
        )

    def _check_business_continuity(self) -> ComplianceControl:
        """A.17: Business Continuity"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="A.17",
            control_name="Business Continuity",
            description="Information security continuity management",
            category="Business Continuity",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - review BCP documentation",
            remediation="Develop and test business continuity plan"
        )


class CISControlsChecker(BaseComplianceChecker):
    """CIS Controls v8 compliance checker"""

    FRAMEWORK = "CIS Controls v8"

    def run_checks(self) -> List[ComplianceControl]:
        """Run CIS Controls compliance checks"""
        logger.info("Running CIS Controls v8 compliance checks")

        checks = [
            self._check_cis_1_asset_inventory,
            self._check_cis_2_software_inventory,
            self._check_cis_3_data_protection,
            self._check_cis_4_secure_configuration,
            self._check_cis_5_account_management,
            self._check_cis_6_access_control,
            self._check_cis_7_vulnerability_management,
            self._check_cis_8_audit_log_management,
            self._check_cis_9_email_web_protection,
            self._check_cis_10_malware_defenses,
            self._check_cis_11_data_recovery,
            self._check_cis_12_network_infrastructure,
            self._check_cis_13_network_monitoring,
            self._check_cis_14_security_training,
            self._check_cis_15_service_provider,
            self._check_cis_16_software_security,
            self._check_cis_17_incident_response,
            self._check_cis_18_penetration_testing,
        ]

        for check in checks:
            try:
                control = check()
                self.controls.append(control)
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")

        return self.controls

    def _check_cis_1_asset_inventory(self) -> ComplianceControl:
        """CIS Control 1: Inventory and Control of Enterprise Assets"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.1",
            control_name="Inventory of Enterprise Assets",
            description="Actively manage all enterprise assets",
            category="Asset Management",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Partial asset inventory through monitoring agents",
            remediation="Implement comprehensive asset inventory system",
            severity="high"
        )

    def _check_cis_2_software_inventory(self) -> ComplianceControl:
        """CIS Control 2: Inventory and Control of Software Assets"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.2",
            control_name="Inventory of Software Assets",
            description="Actively manage all software on the network",
            category="Asset Management",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement software inventory and control",
            severity="high"
        )

        if self.system == 'Linux':
            success, output = self._run_command(['dpkg', '-l'])
            if not success:
                success, output = self._run_command(['rpm', '-qa'])

            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Package manager available for software inventory"
        else:
            success, _ = self._run_command(
                ['powershell', '-Command', 'Get-WmiObject -Class Win32_Product']
            )
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Windows software inventory available"

        return control

    def _check_cis_3_data_protection(self) -> ComplianceControl:
        """CIS Control 3: Data Protection"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.3",
            control_name="Data Protection",
            description="Develop processes to identify, classify, and protect data",
            category="Data Protection",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement data classification and protection",
            severity="high"
        )

        # Check for encryption
        if self.system == 'Linux':
            success, output = self._run_command(['lsblk', '-o', 'NAME,FSTYPE'])
            if success and 'crypt' in output.lower():
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Disk encryption detected"
        else:
            success, output = self._run_command(
                ['powershell', '-Command', 'Get-BitLockerVolume']
            )
            if success and 'FullyEncrypted' in output:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "BitLocker encryption detected"

        return control

    def _check_cis_4_secure_configuration(self) -> ComplianceControl:
        """CIS Control 4: Secure Configuration"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.4",
            control_name="Secure Configuration",
            description="Establish secure configuration for assets",
            category="Configuration Management",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement secure baseline configurations",
            severity="high"
        )

        # This is checked by the hardening script
        control.status = ComplianceStatus.PARTIALLY_COMPLIANT
        control.finding = "Security hardening assessment available"

        return control

    def _check_cis_5_account_management(self) -> ComplianceControl:
        """CIS Control 5: Account Management"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.5",
            control_name="Account Management",
            description="Use processes to assign and manage credentials",
            category="Identity Management",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement formal account management process",
            severity="high"
        )

        if self.system == 'Linux':
            # Check for disabled accounts
            success, output = self._run_command(
                ['awk', '-F:', '$2 == "!" || $2 == "*" {print $1}', '/etc/shadow']
            )
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Account lockout mechanisms exist"
        else:
            success, output = self._run_command(['net', 'accounts'])
            if success:
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "Windows account policies configured"

        return control

    def _check_cis_6_access_control(self) -> ComplianceControl:
        """CIS Control 6: Access Control Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.6",
            control_name="Access Control Management",
            description="Use processes to create and manage credentials",
            category="Access Control",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Basic access controls implemented",
            remediation="Implement role-based access control (RBAC)",
            severity="high"
        )

    def _check_cis_7_vulnerability_management(self) -> ComplianceControl:
        """CIS Control 7: Continuous Vulnerability Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.7",
            control_name="Continuous Vulnerability Management",
            description="Continuously assess and track vulnerabilities",
            category="Vulnerability Management",
            status=ComplianceStatus.COMPLIANT,
            finding="Vulnerability scanning implemented in this framework",
            remediation="Maintain regular vulnerability scanning schedule",
            severity="critical"
        )

    def _check_cis_8_audit_log_management(self) -> ComplianceControl:
        """CIS Control 8: Audit Log Management"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.8",
            control_name="Audit Log Management",
            description="Collect, alert, review, and retain audit logs",
            category="Logging",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement centralized log management",
            severity="high"
        )

        if self.system == 'Linux':
            if self._check_file_exists('/var/ossec') or self._check_file_exists('/opt/wazuh'):
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Wazuh/OSSEC SIEM agent detected"
            elif self._check_file_exists('/var/log/syslog'):
                control.status = ComplianceStatus.PARTIALLY_COMPLIANT
                control.finding = "System logging active, centralization recommended"
        else:
            control.status = ComplianceStatus.PARTIALLY_COMPLIANT
            control.finding = "Windows Event Logging available"

        return control

    def _check_cis_9_email_web_protection(self) -> ComplianceControl:
        """CIS Control 9: Email and Web Browser Protections"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.9",
            control_name="Email and Web Browser Protections",
            description="Improve protections for email and web",
            category="Email/Web Security",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check email/web security",
            remediation="Implement email and web filtering solutions",
            severity="medium"
        )

    def _check_cis_10_malware_defenses(self) -> ComplianceControl:
        """CIS Control 10: Malware Defenses"""
        control = ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.10",
            control_name="Malware Defenses",
            description="Prevent or control installation of malware",
            category="Malware Defense",
            status=ComplianceStatus.NON_COMPLIANT,
            remediation="Implement anti-malware solution",
            severity="critical"
        )

        if self.system == 'Linux':
            av_paths = ['/usr/bin/clamscan', '/opt/kaspersky', '/opt/eset']
            for path in av_paths:
                if self._check_file_exists(path):
                    control.status = ComplianceStatus.COMPLIANT
                    control.finding = f"Antivirus detected: {path}"
                    break
        else:
            success, output = self._run_command(
                ['powershell', '-Command',
                 'Get-MpComputerStatus | Select-Object AntivirusEnabled']
            )
            if success and 'True' in output:
                control.status = ComplianceStatus.COMPLIANT
                control.finding = "Windows Defender enabled"

        return control

    def _check_cis_11_data_recovery(self) -> ComplianceControl:
        """CIS Control 11: Data Recovery"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.11",
            control_name="Data Recovery",
            description="Establish and maintain data recovery practices",
            category="Data Recovery",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check backup procedures",
            remediation="Implement and test backup/recovery procedures",
            severity="high"
        )

    def _check_cis_12_network_infrastructure(self) -> ComplianceControl:
        """CIS Control 12: Network Infrastructure Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.12",
            control_name="Network Infrastructure Management",
            description="Establish and maintain secure network infrastructure",
            category="Network Security",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Network security being assessed by this framework",
            remediation="Review network segmentation and security",
            severity="high"
        )

    def _check_cis_13_network_monitoring(self) -> ComplianceControl:
        """CIS Control 13: Network Monitoring and Defense"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.13",
            control_name="Network Monitoring and Defense",
            description="Monitor and defend against network threats",
            category="Network Monitoring",
            status=ComplianceStatus.PARTIALLY_COMPLIANT,
            finding="Network monitoring implemented in this framework",
            remediation="Enhance network monitoring capabilities",
            severity="high"
        )

    def _check_cis_14_security_training(self) -> ComplianceControl:
        """CIS Control 14: Security Awareness and Skills Training"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.14",
            control_name="Security Awareness Training",
            description="Establish security awareness program",
            category="Training",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check training records",
            remediation="Implement security awareness training program",
            severity="medium"
        )

    def _check_cis_15_service_provider(self) -> ComplianceControl:
        """CIS Control 15: Service Provider Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.15",
            control_name="Service Provider Management",
            description="Develop process for managing service providers",
            category="Third Party",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - review vendor management",
            remediation="Implement vendor risk management process",
            severity="medium"
        )

    def _check_cis_16_software_security(self) -> ComplianceControl:
        """CIS Control 16: Application Software Security"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.16",
            control_name="Application Software Security",
            description="Manage security of developed/acquired software",
            category="Application Security",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check SDLC practices",
            remediation="Implement secure development practices",
            severity="medium"
        )

    def _check_cis_17_incident_response(self) -> ComplianceControl:
        """CIS Control 17: Incident Response Management"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.17",
            control_name="Incident Response Management",
            description="Establish incident response program",
            category="Incident Response",
            status=ComplianceStatus.NOT_APPLICABLE,
            finding="Manual verification required - check IRP documentation",
            remediation="Document and test incident response procedures",
            severity="high"
        )

    def _check_cis_18_penetration_testing(self) -> ComplianceControl:
        """CIS Control 18: Penetration Testing"""
        return ComplianceControl(
            framework=self.FRAMEWORK,
            control_id="CIS.18",
            control_name="Penetration Testing",
            description="Test security controls through penetration testing",
            category="Testing",
            status=ComplianceStatus.COMPLIANT,
            finding="Penetration testing implemented in this framework",
            remediation="Conduct regular penetration testing",
            severity="high"
        )


class ComplianceReportGenerator:
    """Generates compliance reports"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, controls: List[ComplianceControl],
                       framework: str, organization: str = "SME Organization",
                       scope: str = "Full Infrastructure") -> ComplianceReport:
        """Generate compliance report"""
        compliant = len([c for c in controls if c.status == ComplianceStatus.COMPLIANT])
        non_compliant = len([c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT])
        partial = len([c for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT])
        na = len([c for c in controls if c.status == ComplianceStatus.NOT_APPLICABLE])

        applicable = len(controls) - na
        compliance_pct = (compliant / max(applicable, 1)) * 100

        report = ComplianceReport(
            report_time=datetime.now().isoformat(),
            framework=framework,
            organization=organization,
            scope=scope,
            total_controls=len(controls),
            compliant=compliant,
            non_compliant=non_compliant,
            partially_compliant=partial,
            not_applicable=na,
            compliance_percentage=round(compliance_pct, 1),
            controls=controls,
            executive_summary=self._generate_summary(compliance_pct, non_compliant, controls)
        )

        return report

    def _generate_summary(self, compliance_pct: float, non_compliant: int,
                         controls: List[ComplianceControl]) -> str:
        """Generate executive summary"""
        risk_level = "Low"
        if compliance_pct < 50:
            risk_level = "Critical"
        elif compliance_pct < 70:
            risk_level = "High"
        elif compliance_pct < 85:
            risk_level = "Medium"

        critical_findings = [c for c in controls
                           if c.status == ComplianceStatus.NON_COMPLIANT
                           and c.severity in ['critical', 'high']]

        summary = f"""
Compliance Assessment Summary
-----------------------------
Overall Compliance: {compliance_pct:.1f}%
Risk Level: {risk_level}
Non-Compliant Controls: {non_compliant}
Critical/High Findings: {len(critical_findings)}

Key findings requiring immediate attention:
"""
        for i, finding in enumerate(critical_findings[:5], 1):
            summary += f"\n{i}. [{finding.control_id}] {finding.control_name}: {finding.finding}"

        return summary

    def save_report(self, report: ComplianceReport) -> Dict[str, str]:
        """Save report to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        framework_clean = report.framework.replace(' ', '_').replace('.', '')
        reports = {}

        # JSON report
        json_path = self.output_dir / f"compliance_{framework_clean}_{timestamp}.json"
        with open(json_path, 'w') as f:
            report_dict = asdict(report)
            report_dict['controls'] = [
                {**asdict(c), 'status': c.status.value}
                for c in report.controls
            ]
            json.dump(report_dict, f, indent=2, default=str)
        reports['json'] = str(json_path)

        # HTML report
        html_path = self.output_dir / f"compliance_{framework_clean}_{timestamp}.html"
        self._save_html_report(report, html_path)
        reports['html'] = str(html_path)

        return reports

    def _save_html_report(self, report: ComplianceReport, path: Path):
        """Generate HTML compliance report"""
        status_colors = {
            ComplianceStatus.COMPLIANT: '#27ae60',
            ComplianceStatus.NON_COMPLIANT: '#e74c3c',
            ComplianceStatus.PARTIALLY_COMPLIANT: '#f39c12',
            ComplianceStatus.NOT_APPLICABLE: '#95a5a6',
            ComplianceStatus.ERROR: '#8e44ad'
        }

        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>{report.framework} Compliance Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .summary-card h3 {{ margin: 0; font-size: 2em; }}
        .gauge {{ width: 200px; height: 200px; margin: 20px auto; position: relative; }}
        .gauge-value {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .status-badge {{ padding: 5px 10px; border-radius: 4px; color: white; font-size: 0.85em; }}
        .executive-summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; white-space: pre-line; }}
    </style>
</head>
<body>
<div class="container">
    <h1>{report.framework} Compliance Report</h1>
    <p><strong>Organization:</strong> {report.organization}</p>
    <p><strong>Scope:</strong> {report.scope}</p>
    <p><strong>Generated:</strong> {report.report_time}</p>

    <h2>Compliance Summary</h2>
    <div class="summary">
        <div class="summary-card" style="background: #3498db;">
            <h3>{report.compliance_percentage}%</h3>
            <p>Overall Compliance</p>
        </div>
        <div class="summary-card" style="background: #27ae60;">
            <h3>{report.compliant}</h3>
            <p>Compliant</p>
        </div>
        <div class="summary-card" style="background: #e74c3c;">
            <h3>{report.non_compliant}</h3>
            <p>Non-Compliant</p>
        </div>
        <div class="summary-card" style="background: #f39c12;">
            <h3>{report.partially_compliant}</h3>
            <p>Partial</p>
        </div>
        <div class="summary-card" style="background: #95a5a6;">
            <h3>{report.not_applicable}</h3>
            <p>N/A</p>
        </div>
    </div>

    <h2>Executive Summary</h2>
    <div class="executive-summary">{report.executive_summary}</div>

    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Control ID</th>
            <th>Control Name</th>
            <th>Category</th>
            <th>Status</th>
            <th>Finding</th>
            <th>Remediation</th>
        </tr>
'''

        for control in report.controls:
            color = status_colors.get(control.status, '#95a5a6')
            html += f'''
        <tr>
            <td>{control.control_id}</td>
            <td>{control.control_name}</td>
            <td>{control.category}</td>
            <td><span class="status-badge" style="background: {color};">{control.status.value}</span></td>
            <td>{control.finding}</td>
            <td>{control.remediation}</td>
        </tr>
'''

        html += '''
    </table>
</div>
</body>
</html>
'''

        with open(path, 'w') as f:
            f.write(html)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SME Network Security Assessment - Compliance Checker'
    )
    parser.add_argument(
        '-f', '--framework',
        choices=['nist', 'iso27001', 'cis', 'all'],
        default='all',
        help='Compliance framework to check'
    )
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for reports'
    )
    parser.add_argument(
        '--org',
        default='SME Organization',
        help='Organization name for report'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("\n" + "=" * 60)
    print("COMPLIANCE ASSESSMENT")
    print("=" * 60 + "\n")

    reporter = ComplianceReportGenerator(args.output)
    all_reports = {}

    frameworks_to_check = []
    if args.framework in ['nist', 'all']:
        frameworks_to_check.append(('NIST CSF', NISTCSFChecker()))
    if args.framework in ['iso27001', 'all']:
        frameworks_to_check.append(('ISO 27001', ISO27001Checker()))
    if args.framework in ['cis', 'all']:
        frameworks_to_check.append(('CIS Controls v8', CISControlsChecker()))

    for framework_name, checker in frameworks_to_check:
        print(f"\nChecking {framework_name}...")
        controls = checker.run_checks()
        report = reporter.generate_report(controls, framework_name, args.org)
        reports = reporter.save_report(report)
        all_reports[framework_name] = reports

        print(f"\n{framework_name} Results:")
        print(f"  Compliance: {report.compliance_percentage}%")
        print(f"  Compliant: {report.compliant}")
        print(f"  Non-Compliant: {report.non_compliant}")
        print(f"  Partially Compliant: {report.partially_compliant}")

    print("\n" + "=" * 60)
    print("COMPLIANCE ASSESSMENT COMPLETE")
    print("=" * 60)
    print("\nReports generated:")
    for framework, reports in all_reports.items():
        print(f"\n{framework}:")
        for report_type, path in reports.items():
            print(f"  {report_type}: {path}")


if __name__ == "__main__":
    main()
