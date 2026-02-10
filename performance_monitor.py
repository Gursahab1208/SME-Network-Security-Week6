#!/usr/bin/env python3
"""
SME Network Security Assessment Framework
Week 6: Performance Monitoring Script

This script monitors and measures:
- System resource usage (CPU, memory, disk)
- Security scan performance
- Alert processing times
- Overall system health metrics

Author: SME Security Team
Version: 1.0.0
"""

import os
import sys
import json
import time
import logging
import argparse
import threading
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from collections import deque
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('performance_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Try to import psutil, fallback to basic implementation if not available
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed - using basic monitoring")


@dataclass
class SystemMetrics:
    """System resource metrics"""
    timestamp: str
    cpu_percent: float
    cpu_count: int
    memory_total_gb: float
    memory_used_gb: float
    memory_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_percent: float
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    processes_count: int = 0


@dataclass
class ScanMetrics:
    """Security scan performance metrics"""
    scan_type: str
    start_time: str
    end_time: str
    duration_seconds: float
    targets_scanned: int
    findings_count: int
    errors_count: int
    avg_target_time: float


@dataclass
class AlertMetrics:
    """Alert processing metrics"""
    timestamp: str
    alerts_total: int
    alerts_per_minute: float
    avg_processing_time_ms: float
    queue_depth: int
    false_positive_rate: float


@dataclass
class PerformanceReport:
    """Complete performance report"""
    report_time: str
    monitoring_duration_hours: float
    system_metrics_summary: Dict
    scan_metrics: List[ScanMetrics]
    alert_metrics_summary: Dict
    recommendations: List[str]


class SystemMonitor:
    """Monitors system resources"""

    def __init__(self, sample_interval: int = 5):
        self.sample_interval = sample_interval
        self.metrics_history: deque = deque(maxlen=1000)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        if HAS_PSUTIL:
            return self._get_metrics_psutil()
        else:
            return self._get_metrics_basic()

    def _get_metrics_psutil(self) -> SystemMetrics:
        """Get metrics using psutil"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()

        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu_percent,
            cpu_count=psutil.cpu_count(),
            memory_total_gb=memory.total / (1024**3),
            memory_used_gb=memory.used / (1024**3),
            memory_percent=memory.percent,
            disk_total_gb=disk.total / (1024**3),
            disk_used_gb=disk.used / (1024**3),
            disk_percent=disk.percent,
            network_bytes_sent=net_io.bytes_sent,
            network_bytes_recv=net_io.bytes_recv,
            processes_count=len(psutil.pids())
        )

    def _get_metrics_basic(self) -> SystemMetrics:
        """Get basic metrics without psutil"""
        # Basic CPU info (Linux)
        cpu_percent = 0.0
        cpu_count = os.cpu_count() or 1

        try:
            # Try to get load average on Unix
            if hasattr(os, 'getloadavg'):
                load1, load5, load15 = os.getloadavg()
                cpu_percent = (load1 / cpu_count) * 100
        except:
            pass

        # Memory info (Linux)
        memory_total = 0
        memory_used = 0
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        memory_total = int(line.split()[1]) * 1024
                    elif 'MemAvailable' in line:
                        memory_available = int(line.split()[1]) * 1024
                        memory_used = memory_total - memory_available
                        break
        except:
            # Windows fallback
            try:
                result = subprocess.run(
                    ['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/VALUE'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'TotalVisibleMemorySize' in line:
                        memory_total = int(line.split('=')[1].strip()) * 1024
                    elif 'FreePhysicalMemory' in line:
                        free = int(line.split('=')[1].strip()) * 1024
                        memory_used = memory_total - free
            except:
                memory_total = 8 * (1024**3)  # Default 8GB
                memory_used = 4 * (1024**3)

        memory_percent = (memory_used / max(memory_total, 1)) * 100

        # Disk info
        disk_total = 0
        disk_used = 0
        try:
            statvfs = os.statvfs('/')
            disk_total = statvfs.f_frsize * statvfs.f_blocks
            disk_used = disk_total - (statvfs.f_frsize * statvfs.f_bavail)
        except:
            try:
                result = subprocess.run(
                    ['wmic', 'logicaldisk', 'get', 'size,freespace', '/VALUE'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'Size=' in line:
                        disk_total = int(line.split('=')[1].strip() or 0)
                    elif 'FreeSpace=' in line:
                        free = int(line.split('=')[1].strip() or 0)
                        disk_used = disk_total - free
                        break
            except:
                disk_total = 500 * (1024**3)
                disk_used = 200 * (1024**3)

        disk_percent = (disk_used / max(disk_total, 1)) * 100

        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            memory_total_gb=memory_total / (1024**3),
            memory_used_gb=memory_used / (1024**3),
            memory_percent=memory_percent,
            disk_total_gb=disk_total / (1024**3),
            disk_used_gb=disk_used / (1024**3),
            disk_percent=disk_percent,
            network_bytes_sent=0,
            network_bytes_recv=0,
            processes_count=0
        )

    def start_monitoring(self):
        """Start background monitoring thread"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("System monitoring started")

    def stop_monitoring(self):
        """Stop background monitoring"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("System monitoring stopped")

    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._running:
            try:
                metrics = self.get_current_metrics()
                self.metrics_history.append(metrics)
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")

            time.sleep(self.sample_interval)

    def get_summary(self) -> Dict:
        """Get summary of collected metrics"""
        if not self.metrics_history:
            return {}

        metrics_list = list(self.metrics_history)

        return {
            'samples_collected': len(metrics_list),
            'time_range': {
                'start': metrics_list[0].timestamp,
                'end': metrics_list[-1].timestamp
            },
            'cpu': {
                'avg_percent': statistics.mean(m.cpu_percent for m in metrics_list),
                'max_percent': max(m.cpu_percent for m in metrics_list),
                'min_percent': min(m.cpu_percent for m in metrics_list)
            },
            'memory': {
                'avg_percent': statistics.mean(m.memory_percent for m in metrics_list),
                'max_percent': max(m.memory_percent for m in metrics_list),
                'avg_used_gb': statistics.mean(m.memory_used_gb for m in metrics_list)
            },
            'disk': {
                'avg_percent': statistics.mean(m.disk_percent for m in metrics_list),
                'max_percent': max(m.disk_percent for m in metrics_list)
            }
        }


class ScanPerformanceTracker:
    """Tracks security scan performance"""

    def __init__(self):
        self.scans: List[ScanMetrics] = []
        self._current_scan: Optional[Dict] = None

    def start_scan(self, scan_type: str, targets: int):
        """Mark the start of a scan"""
        self._current_scan = {
            'scan_type': scan_type,
            'start_time': datetime.now(),
            'targets': targets,
            'findings': 0,
            'errors': 0
        }
        logger.info(f"Started tracking {scan_type} scan of {targets} targets")

    def record_finding(self):
        """Record a finding during scan"""
        if self._current_scan:
            self._current_scan['findings'] += 1

    def record_error(self):
        """Record an error during scan"""
        if self._current_scan:
            self._current_scan['errors'] += 1

    def end_scan(self) -> Optional[ScanMetrics]:
        """Mark the end of a scan and return metrics"""
        if not self._current_scan:
            return None

        end_time = datetime.now()
        start_time = self._current_scan['start_time']
        duration = (end_time - start_time).total_seconds()

        metrics = ScanMetrics(
            scan_type=self._current_scan['scan_type'],
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=duration,
            targets_scanned=self._current_scan['targets'],
            findings_count=self._current_scan['findings'],
            errors_count=self._current_scan['errors'],
            avg_target_time=duration / max(self._current_scan['targets'], 1)
        )

        self.scans.append(metrics)
        self._current_scan = None

        logger.info(f"Scan completed: {metrics.duration_seconds:.2f}s, "
                   f"{metrics.findings_count} findings, {metrics.errors_count} errors")

        return metrics

    def get_summary(self) -> Dict:
        """Get summary of all scans"""
        if not self.scans:
            return {}

        return {
            'total_scans': len(self.scans),
            'total_duration_seconds': sum(s.duration_seconds for s in self.scans),
            'total_targets': sum(s.targets_scanned for s in self.scans),
            'total_findings': sum(s.findings_count for s in self.scans),
            'total_errors': sum(s.errors_count for s in self.scans),
            'avg_scan_duration': statistics.mean(s.duration_seconds for s in self.scans),
            'avg_target_time': statistics.mean(s.avg_target_time for s in self.scans),
            'by_type': self._group_by_type()
        }

    def _group_by_type(self) -> Dict:
        """Group scan metrics by type"""
        by_type = {}
        for scan in self.scans:
            if scan.scan_type not in by_type:
                by_type[scan.scan_type] = {
                    'count': 0,
                    'total_duration': 0,
                    'total_findings': 0
                }
            by_type[scan.scan_type]['count'] += 1
            by_type[scan.scan_type]['total_duration'] += scan.duration_seconds
            by_type[scan.scan_type]['total_findings'] += scan.findings_count

        return by_type


class AlertPerformanceTracker:
    """Tracks alert processing performance"""

    def __init__(self):
        self.metrics_history: deque = deque(maxlen=1000)
        self._alert_times: deque = deque(maxlen=1000)

    def record_alert(self, processing_time_ms: float, is_false_positive: bool = False):
        """Record an alert processing event"""
        self._alert_times.append({
            'timestamp': datetime.now(),
            'processing_time_ms': processing_time_ms,
            'false_positive': is_false_positive
        })

    def calculate_metrics(self) -> AlertMetrics:
        """Calculate current alert metrics"""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)

        # Filter alerts from last minute
        recent = [a for a in self._alert_times if a['timestamp'] >= minute_ago]

        alerts_per_minute = len(recent)
        avg_processing = statistics.mean(
            a['processing_time_ms'] for a in recent
        ) if recent else 0

        fp_count = sum(1 for a in recent if a['false_positive'])
        fp_rate = (fp_count / max(len(recent), 1)) * 100

        return AlertMetrics(
            timestamp=now.isoformat(),
            alerts_total=len(self._alert_times),
            alerts_per_minute=alerts_per_minute,
            avg_processing_time_ms=avg_processing,
            queue_depth=len(recent),
            false_positive_rate=fp_rate
        )

    def get_summary(self) -> Dict:
        """Get summary of alert metrics"""
        if not self._alert_times:
            return {}

        all_times = list(self._alert_times)

        return {
            'total_alerts': len(all_times),
            'avg_processing_time_ms': statistics.mean(
                a['processing_time_ms'] for a in all_times
            ),
            'max_processing_time_ms': max(
                a['processing_time_ms'] for a in all_times
            ),
            'false_positive_count': sum(1 for a in all_times if a['false_positive']),
            'false_positive_rate': (
                sum(1 for a in all_times if a['false_positive']) / len(all_times) * 100
            ) if all_times else 0
        }


class PerformanceMonitor:
    """Main performance monitoring coordinator"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.system_monitor = SystemMonitor()
        self.scan_tracker = ScanPerformanceTracker()
        self.alert_tracker = AlertPerformanceTracker()

        self.start_time = datetime.now()

    def start(self):
        """Start all monitoring"""
        self.system_monitor.start_monitoring()
        logger.info("Performance monitoring started")

    def stop(self):
        """Stop all monitoring"""
        self.system_monitor.stop_monitoring()
        logger.info("Performance monitoring stopped")

    def generate_report(self) -> PerformanceReport:
        """Generate comprehensive performance report"""
        duration = (datetime.now() - self.start_time).total_seconds() / 3600

        # Collect summaries
        system_summary = self.system_monitor.get_summary()
        scan_summary = self.scan_tracker.get_summary()
        alert_summary = self.alert_tracker.get_summary()

        # Generate recommendations
        recommendations = self._generate_recommendations(
            system_summary, scan_summary, alert_summary
        )

        report = PerformanceReport(
            report_time=datetime.now().isoformat(),
            monitoring_duration_hours=duration,
            system_metrics_summary=system_summary,
            scan_metrics=[asdict(s) for s in self.scan_tracker.scans],
            alert_metrics_summary=alert_summary,
            recommendations=recommendations
        )

        return report

    def _generate_recommendations(self, system: Dict, scan: Dict, alert: Dict) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []

        # System resource recommendations
        if system:
            if system.get('cpu', {}).get('avg_percent', 0) > 80:
                recommendations.append(
                    "HIGH CPU: Average CPU usage above 80%. Consider scaling resources "
                    "or optimizing scan schedules."
                )

            if system.get('memory', {}).get('avg_percent', 0) > 85:
                recommendations.append(
                    "HIGH MEMORY: Average memory usage above 85%. Consider adding RAM "
                    "or reducing concurrent operations."
                )

            if system.get('disk', {}).get('avg_percent', 0) > 90:
                recommendations.append(
                    "HIGH DISK: Disk usage above 90%. Archive old logs and scan results."
                )

        # Scan performance recommendations
        if scan:
            avg_duration = scan.get('avg_scan_duration', 0)
            if avg_duration > 3600:
                recommendations.append(
                    f"SLOW SCANS: Average scan duration is {avg_duration/60:.0f} minutes. "
                    "Consider parallelizing scans or reducing scope."
                )

            error_rate = scan.get('total_errors', 0) / max(scan.get('total_scans', 1), 1)
            if error_rate > 0.1:
                recommendations.append(
                    f"HIGH ERROR RATE: {error_rate*100:.1f}% of scans have errors. "
                    "Check network connectivity and scan configurations."
                )

        # Alert recommendations
        if alert:
            fp_rate = alert.get('false_positive_rate', 0)
            if fp_rate > 30:
                recommendations.append(
                    f"HIGH FALSE POSITIVES: {fp_rate:.1f}% false positive rate. "
                    "Review and tune detection rules."
                )

            avg_processing = alert.get('avg_processing_time_ms', 0)
            if avg_processing > 1000:
                recommendations.append(
                    f"SLOW ALERT PROCESSING: Average {avg_processing:.0f}ms per alert. "
                    "Consider optimizing alert pipelines."
                )

        if not recommendations:
            recommendations.append(
                "System is performing within normal parameters. Continue monitoring."
            )

        return recommendations

    def save_report(self, report: PerformanceReport) -> Dict[str, str]:
        """Save report to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reports = {}

        # JSON report
        json_path = self.output_dir / f"performance_report_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        reports['json'] = str(json_path)

        # HTML report
        html_path = self.output_dir / f"performance_report_{timestamp}.html"
        self._save_html_report(report, html_path)
        reports['html'] = str(html_path)

        # CSV metrics
        csv_path = self.output_dir / f"system_metrics_{timestamp}.csv"
        self._save_metrics_csv(csv_path)
        reports['csv'] = str(csv_path)

        return reports

    def _save_html_report(self, report: PerformanceReport, path: Path):
        """Generate HTML report"""
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Performance Monitoring Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-card.warning {{ background: #f39c12; }}
        .metric-card.danger {{ background: #e74c3c; }}
        .metric-card.success {{ background: #27ae60; }}
        .metric-card h3 {{ margin: 0; font-size: 2em; }}
        .recommendations {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .recommendations.success {{ background: #d4edda; border-color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Performance Monitoring Report</h1>
    <p>Generated: {report.report_time}</p>
    <p>Monitoring Duration: {report.monitoring_duration_hours:.2f} hours</p>

    <h2>System Resources</h2>
    <div class="metrics-grid">
'''
        summary = report.system_metrics_summary
        if summary:
            cpu_class = 'danger' if summary.get('cpu', {}).get('avg_percent', 0) > 80 else 'success'
            mem_class = 'danger' if summary.get('memory', {}).get('avg_percent', 0) > 85 else 'success'
            disk_class = 'danger' if summary.get('disk', {}).get('avg_percent', 0) > 90 else 'success'

            html += f'''
        <div class="metric-card {cpu_class}">
            <h3>{summary.get('cpu', {}).get('avg_percent', 0):.1f}%</h3>
            <p>Avg CPU Usage</p>
        </div>
        <div class="metric-card {mem_class}">
            <h3>{summary.get('memory', {}).get('avg_percent', 0):.1f}%</h3>
            <p>Avg Memory Usage</p>
        </div>
        <div class="metric-card {disk_class}">
            <h3>{summary.get('disk', {}).get('avg_percent', 0):.1f}%</h3>
            <p>Disk Usage</p>
        </div>
        <div class="metric-card">
            <h3>{summary.get('samples_collected', 0)}</h3>
            <p>Samples Collected</p>
        </div>
'''

        html += '''
    </div>

    <h2>Scan Performance</h2>
    <table>
        <tr><th>Scan Type</th><th>Duration</th><th>Targets</th><th>Findings</th><th>Errors</th></tr>
'''

        for scan in report.scan_metrics:
            html += f'''
        <tr>
            <td>{scan['scan_type']}</td>
            <td>{scan['duration_seconds']:.1f}s</td>
            <td>{scan['targets_scanned']}</td>
            <td>{scan['findings_count']}</td>
            <td>{scan['errors_count']}</td>
        </tr>
'''

        html += '''
    </table>

    <h2>Alert Processing</h2>
'''

        alert = report.alert_metrics_summary
        if alert:
            html += f'''
    <div class="metrics-grid">
        <div class="metric-card">
            <h3>{alert.get('total_alerts', 0)}</h3>
            <p>Total Alerts</p>
        </div>
        <div class="metric-card">
            <h3>{alert.get('avg_processing_time_ms', 0):.0f}ms</h3>
            <p>Avg Processing Time</p>
        </div>
        <div class="metric-card {'danger' if alert.get('false_positive_rate', 0) > 30 else 'success'}">
            <h3>{alert.get('false_positive_rate', 0):.1f}%</h3>
            <p>False Positive Rate</p>
        </div>
    </div>
'''

        # Recommendations
        rec_class = 'success' if len(report.recommendations) == 1 and 'normal' in report.recommendations[0].lower() else ''
        html += f'''
    <h2>Recommendations</h2>
    <div class="recommendations {rec_class}">
        <ul>
'''
        for rec in report.recommendations:
            html += f"<li>{rec}</li>\n"

        html += '''
        </ul>
    </div>
</div>
</body>
</html>
'''

        with open(path, 'w') as f:
            f.write(html)

    def _save_metrics_csv(self, path: Path):
        """Save system metrics to CSV"""
        metrics = list(self.system_monitor.metrics_history)
        if not metrics:
            return

        with open(path, 'w') as f:
            headers = ['timestamp', 'cpu_percent', 'memory_percent', 'memory_used_gb',
                      'disk_percent', 'network_sent', 'network_recv']
            f.write(','.join(headers) + '\n')

            for m in metrics:
                row = [
                    m.timestamp,
                    str(m.cpu_percent),
                    str(m.memory_percent),
                    f"{m.memory_used_gb:.2f}",
                    str(m.disk_percent),
                    str(m.network_bytes_sent),
                    str(m.network_bytes_recv)
                ]
                f.write(','.join(row) + '\n')


def run_demo(duration_seconds: int = 60):
    """Run a demonstration of the performance monitor"""
    print("\n" + "=" * 60)
    print("PERFORMANCE MONITORING DEMONSTRATION")
    print("=" * 60)

    monitor = PerformanceMonitor()
    monitor.start()

    print(f"\nMonitoring for {duration_seconds} seconds...")
    print("Simulating security scans and alert processing...\n")

    # Simulate scans
    scan_types = ['vulnerability', 'compliance', 'network']

    for i, scan_type in enumerate(scan_types):
        print(f"Simulating {scan_type} scan...")
        monitor.scan_tracker.start_scan(scan_type, targets=10 + i * 5)

        # Simulate scan duration
        time.sleep(5)

        # Record some findings
        for _ in range(3 + i * 2):
            monitor.scan_tracker.record_finding()

        monitor.scan_tracker.end_scan()

    # Simulate alerts
    print("\nSimulating alert processing...")
    import random
    for _ in range(50):
        processing_time = random.uniform(50, 500)
        is_fp = random.random() < 0.25  # 25% false positive rate
        monitor.alert_tracker.record_alert(processing_time, is_fp)

    # Wait for remaining monitoring time
    remaining = max(0, duration_seconds - 20)
    if remaining > 0:
        print(f"\nCollecting metrics for {remaining} more seconds...")
        time.sleep(remaining)

    monitor.stop()

    # Generate report
    print("\nGenerating performance report...")
    report = monitor.generate_report()
    reports = monitor.save_report(report)

    # Print summary
    print("\n" + "=" * 60)
    print("PERFORMANCE SUMMARY")
    print("=" * 60)

    summary = report.system_metrics_summary
    if summary:
        print(f"\nSystem Metrics (avg):")
        print(f"  CPU: {summary.get('cpu', {}).get('avg_percent', 0):.1f}%")
        print(f"  Memory: {summary.get('memory', {}).get('avg_percent', 0):.1f}%")
        print(f"  Disk: {summary.get('disk', {}).get('avg_percent', 0):.1f}%")

    print(f"\nScans Performed: {len(report.scan_metrics)}")
    for scan in report.scan_metrics:
        print(f"  - {scan['scan_type']}: {scan['duration_seconds']:.1f}s, "
              f"{scan['findings_count']} findings")

    alert = report.alert_metrics_summary
    if alert:
        print(f"\nAlert Processing:")
        print(f"  Total Alerts: {alert.get('total_alerts', 0)}")
        print(f"  Avg Processing: {alert.get('avg_processing_time_ms', 0):.0f}ms")
        print(f"  False Positive Rate: {alert.get('false_positive_rate', 0):.1f}%")

    print(f"\nRecommendations:")
    for rec in report.recommendations:
        print(f"  - {rec}")

    print(f"\nReports saved:")
    for report_type, path in reports.items():
        print(f"  {report_type}: {path}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SME Network Security Assessment - Performance Monitor'
    )
    parser.add_argument(
        '-d', '--duration',
        type=int,
        default=60,
        help='Monitoring duration in seconds (default: 60)'
    )
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Sampling interval in seconds (default: 5)'
    )
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for reports'
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demonstration mode'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.demo:
        run_demo(args.duration)
    else:
        # Basic monitoring mode
        monitor = PerformanceMonitor(args.output)
        monitor.system_monitor.sample_interval = args.interval

        print(f"Starting performance monitoring for {args.duration} seconds...")
        monitor.start()

        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:
            print("\nMonitoring interrupted")

        monitor.stop()

        report = monitor.generate_report()
        reports = monitor.save_report(report)

        print("\nMonitoring complete. Reports saved:")
        for report_type, path in reports.items():
            print(f"  {report_type}: {path}")


if __name__ == "__main__":
    main()
