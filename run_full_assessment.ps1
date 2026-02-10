#Requires -Version 5.1
<#
.SYNOPSIS
    SME Network Security Assessment Framework
    Week 6: Complete Security Assessment Script (PowerShell)

.DESCRIPTION
    This script runs the complete security assessment including:
    - Penetration testing
    - Security hardening checks
    - Compliance assessment
    - Performance monitoring
    - Final report generation

.PARAMETER Targets
    Target IP addresses or hostnames to scan

.PARAMETER Organization
    Organization name for reports

.PARAMETER SkipPentest
    Skip penetration testing module

.PARAMETER SkipHardening
    Skip hardening assessment

.PARAMETER SkipCompliance
    Skip compliance checking

.PARAMETER SkipPerformance
    Skip performance monitoring

.PARAMETER Quick
    Run in quick assessment mode

.EXAMPLE
    .\run_full_assessment.ps1
    .\run_full_assessment.ps1 -Targets "192.168.1.0/24" -Organization "My Company"
    .\run_full_assessment.ps1 -Quick -SkipPentest

.NOTES
    Author: SME Security Team
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Targets = "localhost",

    [Parameter(Mandatory=$false)]
    [string]$Organization = "SME Organization",

    [switch]$SkipPentest,
    [switch]$SkipHardening,
    [switch]$SkipCompliance,
    [switch]$SkipPerformance,
    [switch]$Quick
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ErrorActionPreference = "Continue"
$Script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ReportsDir = Join-Path $ScriptDir "reports"
$Script:Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:LogFile = Join-Path $ScriptDir "assessment_$Script:Timestamp.log"

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
    Write-Log "INFO" $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
    Write-Log "SUCCESS" $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
    Write-Log "WARNING" $Message
}

function Write-Error {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
    Write-Log "ERROR" $Message
}

function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  SME NETWORK SECURITY ASSESSMENT FRAMEWORK" -ForegroundColor Cyan
    Write-Host "  Week 6: Complete Security Assessment" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Organization: $Organization" -ForegroundColor White
    Write-Host "  Timestamp:    $Script:Timestamp" -ForegroundColor White
    Write-Host "  Log File:     $Script:LogFile" -ForegroundColor White
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Test-Dependencies {
    Write-Status "Checking dependencies..."

    # Check Python
    $pythonCmd = $null
    if (Get-Command "python" -ErrorAction SilentlyContinue) {
        $pythonCmd = "python"
    } elseif (Get-Command "python3" -ErrorAction SilentlyContinue) {
        $pythonCmd = "python3"
    }

    if (-not $pythonCmd) {
        Write-Error "Python not found. Please install Python 3.8+"
        return $false
    }

    # Check Python version
    $version = & $pythonCmd --version 2>&1
    Write-Status "Found: $version"

    # Install requirements if pip is available
    try {
        $reqFile = Join-Path $Script:ScriptDir "requirements.txt"
        if (Test-Path $reqFile) {
            Write-Status "Installing Python requirements..."
            & $pythonCmd -m pip install -r $reqFile --quiet 2>$null
        }
    } catch {
        Write-Warning "Could not install Python requirements: $_"
    }

    $Script:PythonCmd = $pythonCmd
    Write-Success "Dependencies check complete"
    return $true
}

function Initialize-Directories {
    Write-Status "Creating output directories..."

    $directories = @(
        $Script:ReportsDir,
        (Join-Path $Script:ReportsDir "pentest"),
        (Join-Path $Script:ReportsDir "compliance"),
        (Join-Path $Script:ReportsDir "hardening"),
        (Join-Path $Script:ReportsDir "performance"),
        (Join-Path $Script:ReportsDir "final")
    )

    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    Write-Success "Directories created"
}

# ============================================================================
# ASSESSMENT FUNCTIONS
# ============================================================================

function Invoke-PentestModule {
    Write-Status "Running penetration testing module..."

    $scriptPath = Join-Path $Script:ScriptDir "pentest_automation.py"
    if (Test-Path $scriptPath) {
        try {
            $outputDir = Join-Path $Script:ReportsDir "pentest"
            & $Script:PythonCmd $scriptPath $Targets -t quick -o $outputDir 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Penetration testing complete"
        } catch {
            Write-Warning "Pentest module encountered issues: $_"
        }
    } else {
        Write-Warning "Pentest module not found, skipping..."
    }
}

function Invoke-HardeningCheck {
    Write-Status "Running security hardening assessment..."

    $scriptPath = Join-Path $Script:ScriptDir "security_hardening.py"
    if (Test-Path $scriptPath) {
        try {
            $outputFile = Join-Path $Script:ReportsDir "hardening" "hardening_report_$Script:Timestamp.json"
            & $Script:PythonCmd $scriptPath -o $outputFile 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Hardening assessment complete"
        } catch {
            Write-Warning "Hardening check encountered issues: $_"
        }
    } else {
        Write-Warning "Hardening module not found, skipping..."
    }
}

function Invoke-ComplianceCheck {
    Write-Status "Running compliance assessment..."

    $scriptPath = Join-Path $Script:ScriptDir "compliance_checker.py"
    if (Test-Path $scriptPath) {
        try {
            $outputDir = Join-Path $Script:ReportsDir "compliance"
            & $Script:PythonCmd $scriptPath -f all -o $outputDir --org $Organization 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Compliance assessment complete"
        } catch {
            Write-Warning "Compliance check encountered issues: $_"
        }
    } else {
        Write-Warning "Compliance module not found, skipping..."
    }
}

function Invoke-PerformanceMonitor {
    Write-Status "Running performance monitoring (30 seconds)..."

    $scriptPath = Join-Path $Script:ScriptDir "performance_monitor.py"
    if (Test-Path $scriptPath) {
        try {
            $outputDir = Join-Path $Script:ReportsDir "performance"
            & $Script:PythonCmd $scriptPath -d 30 -o $outputDir --demo 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Performance monitoring complete"
        } catch {
            Write-Warning "Performance monitoring encountered issues: $_"
        }
    } else {
        Write-Warning "Performance module not found, skipping..."
    }
}

function Invoke-WazuhTuning {
    Write-Status "Running Wazuh rule tuning analysis..."

    $scriptPath = Join-Path $Script:ScriptDir "wazuh_tuning.py"
    if (Test-Path $scriptPath) {
        try {
            $rulesFile = Join-Path $Script:ScriptDir "rules" "tuned_rules.xml"
            & $Script:PythonCmd $scriptPath -o $Script:ReportsDir -r $rulesFile --hours 24 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Wazuh tuning analysis complete"
        } catch {
            Write-Warning "Wazuh tuning encountered issues: $_"
        }
    } else {
        Write-Warning "Wazuh tuning module not found, skipping..."
    }
}

function Invoke-VulnerabilityComparison {
    Write-Status "Running vulnerability comparison..."

    $scriptPath = Join-Path $Script:ScriptDir "vulnerability_comparison.py"
    if (Test-Path $scriptPath) {
        try {
            & $Script:PythonCmd $scriptPath --demo -o $Script:ReportsDir 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Vulnerability comparison complete"
        } catch {
            Write-Warning "Vulnerability comparison encountered issues: $_"
        }
    } else {
        Write-Warning "Vulnerability comparison module not found, skipping..."
    }
}

function Invoke-FinalReportGeneration {
    Write-Status "Generating final assessment report..."

    $scriptPath = Join-Path $Script:ScriptDir "final_report_generator.py"
    if (Test-Path $scriptPath) {
        try {
            $outputDir = Join-Path $Script:ReportsDir "final"
            & $Script:PythonCmd $scriptPath -d $Script:ReportsDir -o $outputDir --org $Organization --period "Week 1-6" 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Final report generated"
        } catch {
            Write-Warning "Final report generation encountered issues: $_"
        }
    } else {
        Write-Warning "Final report generator not found, skipping..."
    }
}

function Invoke-HardeningTests {
    Write-Status "Running hardening validation tests..."

    $scriptPath = Join-Path $Script:ScriptDir "test_hardening.py"
    if (Test-Path $scriptPath) {
        try {
            & $Script:PythonCmd $scriptPath 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Hardening validation complete"
        } catch {
            Write-Warning "Hardening tests encountered issues: $_"
        }
    } else {
        Write-Warning "Hardening test module not found, skipping..."
    }
}

function Invoke-FirewallHardening {
    Write-Status "Running Windows Firewall hardening (test mode)..."

    $scriptPath = Join-Path $Script:ScriptDir "firewall_rules.ps1"
    if (Test-Path $scriptPath) {
        try {
            & $scriptPath -Action Test 2>&1 |
                Tee-Object -Append -FilePath $Script:LogFile

            Write-Success "Firewall hardening test complete"
        } catch {
            Write-Warning "Firewall hardening encountered issues: $_"
        }
    } else {
        Write-Warning "Firewall hardening script not found, skipping..."
    }
}

# ============================================================================
# MAIN
# ============================================================================

function Main {
    $startTime = Get-Date

    # Display banner
    Show-Banner

    # Check dependencies
    if (-not (Test-Dependencies)) {
        Write-Error "Dependency check failed. Exiting."
        exit 1
    }

    # Create directories
    Initialize-Directories

    # Run assessment modules
    if (-not $SkipPentest) {
        Invoke-PentestModule
    }

    if (-not $SkipHardening) {
        Invoke-HardeningCheck
    }

    if (-not $SkipCompliance) {
        Invoke-ComplianceCheck
    }

    if (-not $Quick -and -not $SkipPerformance) {
        Invoke-PerformanceMonitor
    }

    # Additional analysis
    Invoke-WazuhTuning
    Invoke-VulnerabilityComparison
    Invoke-HardeningTests
    Invoke-FirewallHardening

    # Generate final report
    Invoke-FinalReportGeneration

    # Calculate duration
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    # Print summary
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  ASSESSMENT COMPLETE" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Duration:     $([math]::Round($duration, 2)) seconds" -ForegroundColor White
    Write-Host "  Reports:      $Script:ReportsDir" -ForegroundColor White
    Write-Host "  Log File:     $Script:LogFile" -ForegroundColor White
    Write-Host ""
    Write-Host "  Generated Reports:" -ForegroundColor Yellow
    Write-Host "  - Penetration Test Report"
    Write-Host "  - Security Hardening Report"
    Write-Host "  - Compliance Assessment Report"
    Write-Host "  - Performance Metrics Report"
    Write-Host "  - Vulnerability Comparison Report"
    Write-Host "  - Final Assessment Report"
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Success "Security assessment completed successfully!"
}

# Run main function
Main
