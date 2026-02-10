#!/usr/bin/env python3
"""
SME Network Security Assessment Framework
Week 6: Final Security Assessment Report Generator

This script generates comprehensive final reports combining:
- Vulnerability assessment results
- Compliance status
- Hardening verification
- Performance metrics
- Recommendations

Author: SME Security Team
Version: 1.0.0
"""

import json
import logging
import argparse
import os
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from collections import Counter
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('final_report_generator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class AssessmentMetrics:
    """Overall assessment metrics"""
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    hosts_scanned: int = 0
    compliance_score: float = 0.0
    hardening_score: float = 0.0
    risk_score: float = 0.0
    remediation_rate: float = 0.0


@dataclass
class ExecutiveSummary:
    """Executive summary data"""
    assessment_period: str
    scope: str
    overall_risk_level: str
    key_findings: List[str]
    critical_actions: List[str]
    achievements: List[str]
    next_steps: List[str]


@dataclass
class FinalReport:
    """Complete final assessment report"""
    report_id: str
    organization: str
    generated_date: str
    assessment_period: str
    executive_summary: ExecutiveSummary
    metrics: AssessmentMetrics
    vulnerability_summary: Dict
    compliance_summary: Dict
    hardening_summary: Dict
    performance_summary: Dict
    detailed_findings: List[Dict]
    recommendations: List[Dict]
    appendices: List[Dict]


class DataCollector:
    """Collects data from various assessment outputs"""

    def __init__(self, data_dir: str = "reports"):
        self.data_dir = Path(data_dir)
        self.data = {}

    def collect_all(self) -> Dict:
        """Collect all available assessment data"""
        logger.info(f"Collecting data from {self.data_dir}")

        self.data['vulnerabilities'] = self._collect_vulnerability_data()
        self.data['compliance'] = self._collect_compliance_data()
        self.data['hardening'] = self._collect_hardening_data()
        self.data['performance'] = self._collect_performance_data()
        self.data['pentest'] = self._collect_pentest_data()

        return self.data

    def _collect_vulnerability_data(self) -> Dict:
        """Collect vulnerability scan data"""
        vuln_data = {
            'total': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_host': {},
            'top_vulnerabilities': [],
            'scan_date': None
        }

        # Look for vulnerability reports
        for pattern in ['pentest_report_*.json', 'vuln_*.json', 'scan_*.json']:
            for file in self.data_dir.glob(pattern):
                try:
                    with open(file, 'r') as f:
                        data = json.load(f)

                    # Extract vulnerability data
                    if 'findings' in data:
                        findings = data['findings']
                    elif 'vulnerabilities' in data:
                        findings = data['vulnerabilities']
                    elif 'scan_results' in data:
                        findings = []
                        for result in data['scan_results']:
                            findings.extend(result.get('vulnerabilities', []))
                    else:
                        continue

                    vuln_data['total'] = len(findings)
                    vuln_data['scan_date'] = data.get('report_metadata', {}).get('generated')

                    for finding in findings:
                        severity = finding.get('severity', 'medium').lower()
                        if severity in vuln_data['by_severity']:
                            vuln_data['by_severity'][severity] += 1

                        host = finding.get('affected_host', 'unknown')
                        vuln_data['by_host'][host] = vuln_data['by_host'].get(host, 0) + 1

                    # Get top vulnerabilities
                    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                    sorted_findings = sorted(
                        findings,
                        key=lambda x: severity_order.get(x.get('severity', 'medium').lower(), 2)
                    )
                    vuln_data['top_vulnerabilities'] = sorted_findings[:10]

                    logger.info(f"Loaded vulnerability data from {file}")
                    break

                except Exception as e:
                    logger.debug(f"Error reading {file}: {e}")

        return vuln_data

    def _collect_compliance_data(self) -> Dict:
        """Collect compliance assessment data"""
        compliance_data = {
            'frameworks': {},
            'overall_score': 0,
            'controls_assessed': 0,
            'controls_compliant': 0,
            'controls_non_compliant': 0
        }

        for file in self.data_dir.glob('compliance_*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)

                framework = data.get('framework', 'Unknown')
                compliance_data['frameworks'][framework] = {
                    'score': data.get('compliance_percentage', 0),
                    'compliant': data.get('compliant', 0),
                    'non_compliant': data.get('non_compliant', 0),
                    'partial': data.get('partially_compliant', 0)
                }

                compliance_data['controls_assessed'] += data.get('total_controls', 0)
                compliance_data['controls_compliant'] += data.get('compliant', 0)
                compliance_data['controls_non_compliant'] += data.get('non_compliant', 0)

                logger.info(f"Loaded compliance data from {file}")

            except Exception as e:
                logger.debug(f"Error reading {file}: {e}")

        # Calculate overall score
        if compliance_data['frameworks']:
            scores = [f['score'] for f in compliance_data['frameworks'].values()]
            compliance_data['overall_score'] = sum(scores) / len(scores)

        return compliance_data

    def _collect_hardening_data(self) -> Dict:
        """Collect hardening assessment data"""
        hardening_data = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'score': 0,
            'categories': {}
        }

        for file in self.data_dir.glob('hardening_*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)

                summary = data.get('summary', {})
                hardening_data['total_checks'] = summary.get('total_checks', 0)
                hardening_data['passed'] = summary.get('passed', 0)
                hardening_data['failed'] = summary.get('failed', 0)
                hardening_data['warnings'] = summary.get('warnings', 0)

                if hardening_data['total_checks'] > 0:
                    hardening_data['score'] = (
                        hardening_data['passed'] / hardening_data['total_checks'] * 100
                    )

                # Group by category
                for check in data.get('checks', []):
                    category = check.get('category', 'Other')
                    if category not in hardening_data['categories']:
                        hardening_data['categories'][category] = {'passed': 0, 'failed': 0}

                    if check.get('status') == 'PASS':
                        hardening_data['categories'][category]['passed'] += 1
                    else:
                        hardening_data['categories'][category]['failed'] += 1

                logger.info(f"Loaded hardening data from {file}")
                break

            except Exception as e:
                logger.debug(f"Error reading {file}: {e}")

        return hardening_data

    def _collect_performance_data(self) -> Dict:
        """Collect performance monitoring data"""
        perf_data = {
            'system_metrics': {},
            'scan_performance': {},
            'alert_metrics': {}
        }

        for file in self.data_dir.glob('performance_*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)

                perf_data['system_metrics'] = data.get('system_metrics_summary', {})
                perf_data['scan_performance'] = data.get('scan_metrics', [])
                perf_data['alert_metrics'] = data.get('alert_metrics_summary', {})

                logger.info(f"Loaded performance data from {file}")
                break

            except Exception as e:
                logger.debug(f"Error reading {file}: {e}")

        return perf_data

    def _collect_pentest_data(self) -> Dict:
        """Collect penetration test data"""
        pentest_data = {
            'findings': [],
            'summary': {}
        }

        for file in self.data_dir.glob('pentest_*.json'):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)

                pentest_data['summary'] = data.get('executive_summary', {})
                pentest_data['findings'] = data.get('findings', [])

                logger.info(f"Loaded pentest data from {file}")
                break

            except Exception as e:
                logger.debug(f"Error reading {file}: {e}")

        return pentest_data


class ReportGenerator:
    """Generates final assessment reports"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(__file__).parent / "templates"

    def generate_report(self, data: Dict, organization: str = "SME Organization",
                       assessment_period: str = "Week 1-6") -> FinalReport:
        """Generate comprehensive final report"""
        logger.info("Generating final report")

        # Calculate metrics
        metrics = self._calculate_metrics(data)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(data, metrics)

        # Compile detailed findings
        detailed_findings = self._compile_detailed_findings(data)

        # Generate recommendations
        recommendations = self._generate_recommendations(data, metrics)

        # Create report
        report = FinalReport(
            report_id=f"SMESEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            organization=organization,
            generated_date=datetime.now().isoformat(),
            assessment_period=assessment_period,
            executive_summary=executive_summary,
            metrics=metrics,
            vulnerability_summary=data.get('vulnerabilities', {}),
            compliance_summary=data.get('compliance', {}),
            hardening_summary=data.get('hardening', {}),
            performance_summary=data.get('performance', {}),
            detailed_findings=detailed_findings,
            recommendations=recommendations,
            appendices=[]
        )

        return report

    def _calculate_metrics(self, data: Dict) -> AssessmentMetrics:
        """Calculate overall assessment metrics"""
        vuln = data.get('vulnerabilities', {})
        compliance = data.get('compliance', {})
        hardening = data.get('hardening', {})

        by_severity = vuln.get('by_severity', {})

        # Calculate risk score (weighted)
        risk_score = (
            by_severity.get('critical', 0) * 10 +
            by_severity.get('high', 0) * 5 +
            by_severity.get('medium', 0) * 2 +
            by_severity.get('low', 0) * 0.5
        )

        # Normalize to 0-100
        max_risk = max(vuln.get('total', 1), 1) * 10
        normalized_risk = min(100, (risk_score / max_risk) * 100)

        return AssessmentMetrics(
            total_vulnerabilities=vuln.get('total', 0),
            critical_vulnerabilities=by_severity.get('critical', 0),
            high_vulnerabilities=by_severity.get('high', 0),
            medium_vulnerabilities=by_severity.get('medium', 0),
            low_vulnerabilities=by_severity.get('low', 0),
            hosts_scanned=len(vuln.get('by_host', {})),
            compliance_score=compliance.get('overall_score', 0),
            hardening_score=hardening.get('score', 0),
            risk_score=normalized_risk,
            remediation_rate=0  # Would need before/after data
        )

    def _generate_executive_summary(self, data: Dict,
                                   metrics: AssessmentMetrics) -> ExecutiveSummary:
        """Generate executive summary"""
        # Determine risk level
        if metrics.risk_score > 70 or metrics.critical_vulnerabilities > 0:
            risk_level = "HIGH"
        elif metrics.risk_score > 40 or metrics.high_vulnerabilities > 3:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Key findings
        key_findings = []
        if metrics.critical_vulnerabilities > 0:
            key_findings.append(
                f"{metrics.critical_vulnerabilities} critical vulnerabilities require immediate attention"
            )
        if metrics.high_vulnerabilities > 0:
            key_findings.append(
                f"{metrics.high_vulnerabilities} high-severity vulnerabilities identified"
            )
        if metrics.compliance_score < 70:
            key_findings.append(
                f"Compliance score ({metrics.compliance_score:.1f}%) below target of 70%"
            )
        if metrics.hardening_score < 80:
            key_findings.append(
                f"System hardening score ({metrics.hardening_score:.1f}%) needs improvement"
            )

        # Critical actions
        critical_actions = []
        if metrics.critical_vulnerabilities > 0:
            critical_actions.append("Remediate critical vulnerabilities within 24-48 hours")
        if metrics.high_vulnerabilities > 0:
            critical_actions.append("Plan remediation for high-severity findings within 1 week")
        critical_actions.append("Review and implement firewall hardening recommendations")
        critical_actions.append("Enable enhanced logging and monitoring")

        # Achievements
        achievements = []
        if metrics.total_vulnerabilities < 50:
            achievements.append("Vulnerability count maintained below threshold")
        if metrics.compliance_score >= 70:
            achievements.append(f"Achieved {metrics.compliance_score:.1f}% compliance score")
        achievements.append("Completed comprehensive security assessment")
        achievements.append("Established security baseline for continuous improvement")

        # Next steps
        next_steps = [
            "Implement remediation plan for identified vulnerabilities",
            "Schedule follow-up assessment to verify improvements",
            "Establish regular vulnerability scanning schedule",
            "Conduct security awareness training for staff",
            "Review and update security policies"
        ]

        return ExecutiveSummary(
            assessment_period="Week 1-6",
            scope="Full network infrastructure assessment",
            overall_risk_level=risk_level,
            key_findings=key_findings,
            critical_actions=critical_actions,
            achievements=achievements,
            next_steps=next_steps
        )

    def _compile_detailed_findings(self, data: Dict) -> List[Dict]:
        """Compile detailed findings from all sources"""
        findings = []

        # Vulnerability findings
        vuln_data = data.get('vulnerabilities', {})
        for vuln in vuln_data.get('top_vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'severity': vuln.get('severity', 'medium'),
                'title': vuln.get('title', vuln.get('name', 'Unknown')),
                'description': vuln.get('description', ''),
                'affected': vuln.get('affected_host', ''),
                'remediation': vuln.get('remediation', vuln.get('solution', '')),
                'cves': vuln.get('cve_ids', [])
            })

        # Pentest findings
        pentest_data = data.get('pentest', {})
        for finding in pentest_data.get('findings', [])[:10]:
            findings.append({
                'type': 'pentest',
                'severity': finding.get('severity', 'medium'),
                'title': finding.get('title', 'Unknown'),
                'description': finding.get('description', ''),
                'affected': finding.get('affected_host', ''),
                'remediation': finding.get('remediation', ''),
                'evidence': finding.get('evidence', '')
            })

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'medium').lower(), 2))

        return findings

    def _generate_recommendations(self, data: Dict,
                                 metrics: AssessmentMetrics) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []

        # Priority 1: Critical vulnerabilities
        if metrics.critical_vulnerabilities > 0:
            recommendations.append({
                'priority': 1,
                'category': 'Vulnerability Management',
                'title': 'Remediate Critical Vulnerabilities',
                'description': f'Address {metrics.critical_vulnerabilities} critical vulnerabilities immediately',
                'effort': 'High',
                'timeline': '24-48 hours'
            })

        # Priority 2: High vulnerabilities
        if metrics.high_vulnerabilities > 0:
            recommendations.append({
                'priority': 2,
                'category': 'Vulnerability Management',
                'title': 'Address High-Severity Vulnerabilities',
                'description': f'Remediate {metrics.high_vulnerabilities} high-severity findings',
                'effort': 'High',
                'timeline': '1 week'
            })

        # Priority 3: Compliance gaps
        if metrics.compliance_score < 80:
            recommendations.append({
                'priority': 3,
                'category': 'Compliance',
                'title': 'Close Compliance Gaps',
                'description': 'Address non-compliant controls to improve compliance score',
                'effort': 'Medium',
                'timeline': '30 days'
            })

        # Priority 4: Hardening
        if metrics.hardening_score < 80:
            recommendations.append({
                'priority': 4,
                'category': 'System Hardening',
                'title': 'Implement System Hardening',
                'description': 'Apply security hardening configurations',
                'effort': 'Medium',
                'timeline': '2 weeks'
            })

        # Standard recommendations
        recommendations.extend([
            {
                'priority': 5,
                'category': 'Monitoring',
                'title': 'Enhance Security Monitoring',
                'description': 'Deploy comprehensive logging and alerting',
                'effort': 'Medium',
                'timeline': '2 weeks'
            },
            {
                'priority': 6,
                'category': 'Training',
                'title': 'Security Awareness Training',
                'description': 'Conduct security awareness training for all staff',
                'effort': 'Low',
                'timeline': '30 days'
            },
            {
                'priority': 7,
                'category': 'Process',
                'title': 'Establish Regular Assessments',
                'description': 'Schedule quarterly vulnerability assessments',
                'effort': 'Low',
                'timeline': 'Ongoing'
            }
        ])

        return recommendations

    def save_reports(self, report: FinalReport) -> Dict[str, str]:
        """Save report in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        # JSON report
        json_path = self.output_dir / f"final_report_{timestamp}.json"
        self._save_json(report, json_path)
        reports['json'] = str(json_path)

        # HTML report
        html_path = self.output_dir / f"final_report_{timestamp}.html"
        self._save_html(report, html_path)
        reports['html'] = str(html_path)

        # Executive summary
        exec_path = self.output_dir / f"executive_summary_{timestamp}.html"
        self._save_executive_html(report, exec_path)
        reports['executive'] = str(exec_path)

        return reports

    def _save_json(self, report: FinalReport, path: Path):
        """Save JSON report"""
        report_dict = asdict(report)
        with open(path, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)

    def _save_html(self, report: FinalReport, path: Path):
        """Save comprehensive HTML report"""
        metrics = report.metrics
        summary = report.executive_summary

        # Severity colors
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d'
        }

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report.organization}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f4f4f4; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .header .meta {{ margin-top: 20px; font-size: 0.9em; opacity: 0.8; }}
        .section {{ padding: 30px 40px; border-bottom: 1px solid #eee; }}
        .section h2 {{ color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }}
        .section h3 {{ color: #34495e; margin: 20px 0 10px 0; }}

        .risk-banner {{ padding: 20px; text-align: center; color: white; font-size: 1.2em; }}
        .risk-high {{ background: linear-gradient(135deg, #c0392b, #e74c3c); }}
        .risk-medium {{ background: linear-gradient(135deg, #d35400, #e67e22); }}
        .risk-low {{ background: linear-gradient(135deg, #27ae60, #2ecc71); }}

        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: #f8f9fa; padding: 25px; border-radius: 10px; text-align: center; border-left: 4px solid #3498db; }}
        .metric-card.critical {{ border-left-color: #dc3545; }}
        .metric-card.high {{ border-left-color: #fd7e14; }}
        .metric-card.warning {{ border-left-color: #ffc107; }}
        .metric-card.success {{ border-left-color: #28a745; }}
        .metric-card h3 {{ font-size: 2.5em; color: #2c3e50; margin-bottom: 5px; }}
        .metric-card p {{ color: #666; font-size: 0.9em; }}

        .finding {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 15px 0; border-left: 4px solid #3498db; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #17a2b8; }}

        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; color: white; font-size: 0.8em; font-weight: bold; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #17a2b8; }}

        .recommendation {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 15px 0; }}
        .recommendation .priority {{ display: inline-block; width: 30px; height: 30px; border-radius: 50%; background: #3498db; color: white; text-align: center; line-height: 30px; font-weight: bold; margin-right: 15px; }}

        .chart-container {{ height: 200px; display: flex; align-items: flex-end; justify-content: center; gap: 30px; margin: 30px 0; }}
        .chart-bar {{ width: 60px; background: linear-gradient(to top, #3498db, #2ecc71); border-radius: 5px 5px 0 0; transition: all 0.3s; position: relative; }}
        .chart-bar:hover {{ transform: scaleY(1.05); }}
        .chart-label {{ text-align: center; margin-top: 10px; font-size: 0.85em; color: #666; }}
        .chart-value {{ position: absolute; top: -25px; left: 50%; transform: translateX(-50%); font-weight: bold; color: #2c3e50; }}

        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:nth-child(even) {{ background: #f8f9fa; }}
        tr:hover {{ background: #e8f4f8; }}

        ul {{ margin: 15px 0 15px 30px; }}
        li {{ margin: 8px 0; }}

        .footer {{ background: #2c3e50; color: white; padding: 30px; text-align: center; }}
        .footer p {{ margin: 5px 0; opacity: 0.8; }}

        @media print {{
            .container {{ box-shadow: none; }}
            .section {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">{report.organization}</div>
            <div class="meta">
                Report ID: {report.report_id} | Assessment Period: {report.assessment_period} | Generated: {report.generated_date[:10]}
            </div>
        </div>

        <div class="risk-banner risk-{summary.overall_risk_level.lower()}">
            Overall Risk Level: {summary.overall_risk_level}
        </div>

        <div class="section">
            <h2>Executive Summary</h2>

            <h3>Key Findings</h3>
            <ul>
'''

        for finding in summary.key_findings:
            html += f'<li>{finding}</li>\n'

        html += '''
            </ul>

            <h3>Critical Actions Required</h3>
            <ul>
'''

        for action in summary.critical_actions:
            html += f'<li>{action}</li>\n'

        html += '''
            </ul>

            <h3>Achievements</h3>
            <ul>
'''

        for achievement in summary.achievements:
            html += f'<li>{achievement}</li>\n'

        html += f'''
            </ul>
        </div>

        <div class="section">
            <h2>Assessment Metrics</h2>
            <div class="metrics-grid">
                <div class="metric-card {'critical' if metrics.critical_vulnerabilities > 0 else ''}">
                    <h3>{metrics.total_vulnerabilities}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="metric-card critical">
                    <h3>{metrics.critical_vulnerabilities}</h3>
                    <p>Critical</p>
                </div>
                <div class="metric-card high">
                    <h3>{metrics.high_vulnerabilities}</h3>
                    <p>High</p>
                </div>
                <div class="metric-card warning">
                    <h3>{metrics.medium_vulnerabilities}</h3>
                    <p>Medium</p>
                </div>
                <div class="metric-card">
                    <h3>{metrics.hosts_scanned}</h3>
                    <p>Hosts Scanned</p>
                </div>
                <div class="metric-card {'success' if metrics.compliance_score >= 70 else 'warning'}">
                    <h3>{metrics.compliance_score:.0f}%</h3>
                    <p>Compliance Score</p>
                </div>
                <div class="metric-card {'success' if metrics.hardening_score >= 70 else 'warning'}">
                    <h3>{metrics.hardening_score:.0f}%</h3>
                    <p>Hardening Score</p>
                </div>
                <div class="metric-card {'critical' if metrics.risk_score > 70 else 'warning' if metrics.risk_score > 40 else 'success'}">
                    <h3>{metrics.risk_score:.0f}</h3>
                    <p>Risk Score</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>
'''

        for finding in report.detailed_findings[:15]:
            severity = finding.get('severity', 'medium').lower()
            html += f'''
            <div class="finding {severity}">
                <span class="badge badge-{severity}">{severity.upper()}</span>
                <strong>{finding.get('title', 'Unknown')}</strong>
                <p style="margin: 10px 0; color: #666;">{finding.get('description', '')[:300]}...</p>
                <p><strong>Affected:</strong> {finding.get('affected', 'N/A')}</p>
                {'<p><strong>CVEs:</strong> ' + ', '.join(finding.get('cves', [])) + '</p>' if finding.get('cves') else ''}
                <p><strong>Remediation:</strong> {finding.get('remediation', 'See detailed report')}</p>
            </div>
'''

        html += '''
        </div>

        <div class="section">
            <h2>Recommendations</h2>
'''

        for rec in report.recommendations:
            html += f'''
            <div class="recommendation">
                <span class="priority">{rec['priority']}</span>
                <strong>{rec['title']}</strong>
                <span class="badge" style="background: #3498db; margin-left: 10px;">{rec['category']}</span>
                <p style="margin: 10px 0 0 45px;">{rec['description']}</p>
                <p style="margin: 5px 0 0 45px; color: #666; font-size: 0.9em;">
                    <strong>Effort:</strong> {rec['effort']} | <strong>Timeline:</strong> {rec['timeline']}
                </p>
            </div>
'''

        html += f'''
        </div>

        <div class="section">
            <h2>Next Steps</h2>
            <ul>
'''

        for step in summary.next_steps:
            html += f'<li>{step}</li>\n'

        html += f'''
            </ul>
        </div>

        <div class="footer">
            <p><strong>SME Network Security Assessment Framework</strong></p>
            <p>Report ID: {report.report_id}</p>
            <p>Generated: {report.generated_date}</p>
            <p>This report is confidential and intended for authorized recipients only.</p>
        </div>
    </div>
</body>
</html>
'''

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _save_executive_html(self, report: FinalReport, path: Path):
        """Save executive summary HTML"""
        summary = report.executive_summary
        metrics = report.metrics

        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Executive Summary - {report.organization}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: white; color: #333; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .header h1 {{ color: #2c3e50; margin-bottom: 10px; }}
        .risk-indicator {{ display: inline-block; padding: 10px 30px; border-radius: 5px; color: white; font-size: 1.2em; }}
        .risk-high {{ background: #e74c3c; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #27ae60; }}
        .metrics {{ display: flex; justify-content: space-around; margin: 30px 0; flex-wrap: wrap; }}
        .metric {{ text-align: center; padding: 20px; min-width: 150px; }}
        .metric h2 {{ font-size: 3em; color: #3498db; margin: 0; }}
        .section {{ margin: 30px 0; }}
        .section h3 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        ul {{ margin: 15px 0; }}
        li {{ margin: 10px 0; }}
        .footer {{ margin-top: 50px; text-align: center; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Executive Summary</h1>
        <p>{report.organization} | {report.assessment_period}</p>
        <div class="risk-indicator risk-{summary.overall_risk_level.lower()}">
            Risk Level: {summary.overall_risk_level}
        </div>
    </div>

    <div class="metrics">
        <div class="metric">
            <h2>{metrics.total_vulnerabilities}</h2>
            <p>Total Vulnerabilities</p>
        </div>
        <div class="metric">
            <h2 style="color: #e74c3c;">{metrics.critical_vulnerabilities}</h2>
            <p>Critical</p>
        </div>
        <div class="metric">
            <h2>{metrics.compliance_score:.0f}%</h2>
            <p>Compliance</p>
        </div>
        <div class="metric">
            <h2>{metrics.hardening_score:.0f}%</h2>
            <p>Hardening</p>
        </div>
    </div>

    <div class="section">
        <h3>Key Findings</h3>
        <ul>
'''

        for finding in summary.key_findings:
            html += f'<li>{finding}</li>\n'

        html += '''
        </ul>
    </div>

    <div class="section">
        <h3>Critical Actions Required</h3>
        <ul>
'''

        for action in summary.critical_actions:
            html += f'<li>{action}</li>\n'

        html += '''
        </ul>
    </div>

    <div class="section">
        <h3>Top Recommendations</h3>
        <ol>
'''

        for rec in report.recommendations[:5]:
            html += f'<li><strong>{rec["title"]}</strong> - {rec["description"]} (Timeline: {rec["timeline"]})</li>\n'

        html += f'''
        </ol>
    </div>

    <div class="footer">
        <p>Report ID: {report.report_id} | Generated: {report.generated_date[:10]}</p>
        <p>Full detailed report available upon request</p>
    </div>
</body>
</html>
'''

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SME Network Security Assessment - Final Report Generator'
    )
    parser.add_argument(
        '-d', '--data-dir',
        default='reports',
        help='Directory containing assessment data'
    )
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for final reports'
    )
    parser.add_argument(
        '--org',
        default='SME Organization',
        help='Organization name'
    )
    parser.add_argument(
        '--period',
        default='Week 1-6',
        help='Assessment period'
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
    print("FINAL SECURITY ASSESSMENT REPORT GENERATION")
    print("=" * 60 + "\n")

    # Collect data
    print("Collecting assessment data...")
    collector = DataCollector(args.data_dir)
    data = collector.collect_all()

    # Generate report
    print("Generating final report...")
    generator = ReportGenerator(args.output)
    report = generator.generate_report(data, args.org, args.period)

    # Save reports
    print("Saving reports...")
    reports = generator.save_reports(report)

    # Print summary
    print("\n" + "=" * 60)
    print("FINAL REPORT GENERATED")
    print("=" * 60)
    print(f"\nOrganization: {report.organization}")
    print(f"Report ID: {report.report_id}")
    print(f"Risk Level: {report.executive_summary.overall_risk_level}")
    print(f"\nMetrics:")
    print(f"  Total Vulnerabilities: {report.metrics.total_vulnerabilities}")
    print(f"  Critical: {report.metrics.critical_vulnerabilities}")
    print(f"  High: {report.metrics.high_vulnerabilities}")
    print(f"  Compliance Score: {report.metrics.compliance_score:.1f}%")
    print(f"  Hardening Score: {report.metrics.hardening_score:.1f}%")

    print(f"\nReports generated:")
    for report_type, path in reports.items():
        print(f"  {report_type}: {path}")


if __name__ == "__main__":
    main()
