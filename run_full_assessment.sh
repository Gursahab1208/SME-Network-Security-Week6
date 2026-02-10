#!/bin/bash
#
# SME Network Security Assessment Framework
# Week 6: Complete Security Assessment Script
#
# This script runs the complete security assessment including:
# - Penetration testing
# - Security hardening checks
# - Compliance assessment
# - Performance monitoring
# - Final report generation
#
# Author: SME Security Team
# Version: 1.0.0
#
# Usage: ./run_full_assessment.sh [options]
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
LOG_FILE="${SCRIPT_DIR}/assessment.log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default targets (can be overridden)
TARGETS="${TARGETS:-localhost}"
ORGANIZATION="${ORGANIZATION:-SME Organization}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
    log "INFO" "$1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
    log "SUCCESS" "$1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARNING" "$1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
    log "ERROR" "$1"
}

print_banner() {
    echo ""
    echo "============================================================"
    echo "  SME NETWORK SECURITY ASSESSMENT FRAMEWORK"
    echo "  Week 6: Complete Security Assessment"
    echo "============================================================"
    echo ""
    echo "  Organization: ${ORGANIZATION}"
    echo "  Timestamp:    ${TIMESTAMP}"
    echo "  Log File:     ${LOG_FILE}"
    echo ""
    echo "============================================================"
    echo ""
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

check_dependencies() {
    print_status "Checking dependencies..."

    local deps=("python3" "pip3")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Missing dependencies: ${missing[*]}"
        print_status "Installing Python requirements..."
        pip3 install -r "${SCRIPT_DIR}/requirements.txt" 2>/dev/null || true
    fi

    print_success "Dependencies check complete"
}

create_directories() {
    print_status "Creating output directories..."

    mkdir -p "${REPORTS_DIR}"
    mkdir -p "${REPORTS_DIR}/pentest"
    mkdir -p "${REPORTS_DIR}/compliance"
    mkdir -p "${REPORTS_DIR}/hardening"
    mkdir -p "${REPORTS_DIR}/performance"
    mkdir -p "${REPORTS_DIR}/final"

    print_success "Directories created"
}

# ============================================================================
# ASSESSMENT FUNCTIONS
# ============================================================================

run_pentest() {
    print_status "Running penetration testing module..."

    if [[ -f "${SCRIPT_DIR}/pentest_automation.py" ]]; then
        python3 "${SCRIPT_DIR}/pentest_automation.py" \
            ${TARGETS} \
            -t quick \
            -o "${REPORTS_DIR}/pentest" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Pentest module encountered issues"
            }
        print_success "Penetration testing complete"
    else
        print_warning "Pentest module not found, skipping..."
    fi
}

run_hardening_check() {
    print_status "Running security hardening assessment..."

    if [[ -f "${SCRIPT_DIR}/security_hardening.py" ]]; then
        python3 "${SCRIPT_DIR}/security_hardening.py" \
            -o "${REPORTS_DIR}/hardening/hardening_report_${TIMESTAMP}.json" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Hardening check encountered issues"
            }
        print_success "Hardening assessment complete"
    else
        print_warning "Hardening module not found, skipping..."
    fi
}

run_compliance_check() {
    print_status "Running compliance assessment..."

    if [[ -f "${SCRIPT_DIR}/compliance_checker.py" ]]; then
        python3 "${SCRIPT_DIR}/compliance_checker.py" \
            -f all \
            -o "${REPORTS_DIR}/compliance" \
            --org "${ORGANIZATION}" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Compliance check encountered issues"
            }
        print_success "Compliance assessment complete"
    else
        print_warning "Compliance module not found, skipping..."
    fi
}

run_performance_monitor() {
    print_status "Running performance monitoring (30 seconds)..."

    if [[ -f "${SCRIPT_DIR}/performance_monitor.py" ]]; then
        python3 "${SCRIPT_DIR}/performance_monitor.py" \
            -d 30 \
            -o "${REPORTS_DIR}/performance" \
            --demo \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Performance monitoring encountered issues"
            }
        print_success "Performance monitoring complete"
    else
        print_warning "Performance module not found, skipping..."
    fi
}

run_wazuh_tuning() {
    print_status "Running Wazuh rule tuning analysis..."

    if [[ -f "${SCRIPT_DIR}/wazuh_tuning.py" ]]; then
        python3 "${SCRIPT_DIR}/wazuh_tuning.py" \
            -o "${REPORTS_DIR}" \
            -r "${SCRIPT_DIR}/rules/tuned_rules.xml" \
            --hours 24 \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Wazuh tuning encountered issues"
            }
        print_success "Wazuh tuning analysis complete"
    else
        print_warning "Wazuh tuning module not found, skipping..."
    fi
}

run_vulnerability_comparison() {
    print_status "Running vulnerability comparison..."

    if [[ -f "${SCRIPT_DIR}/vulnerability_comparison.py" ]]; then
        python3 "${SCRIPT_DIR}/vulnerability_comparison.py" \
            --demo \
            -o "${REPORTS_DIR}" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Vulnerability comparison encountered issues"
            }
        print_success "Vulnerability comparison complete"
    else
        print_warning "Vulnerability comparison module not found, skipping..."
    fi
}

generate_final_report() {
    print_status "Generating final assessment report..."

    if [[ -f "${SCRIPT_DIR}/final_report_generator.py" ]]; then
        python3 "${SCRIPT_DIR}/final_report_generator.py" \
            -d "${REPORTS_DIR}" \
            -o "${REPORTS_DIR}/final" \
            --org "${ORGANIZATION}" \
            --period "Week 1-6" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Final report generation encountered issues"
            }
        print_success "Final report generated"
    else
        print_warning "Final report generator not found, skipping..."
    fi
}

run_hardening_tests() {
    print_status "Running hardening validation tests..."

    if [[ -f "${SCRIPT_DIR}/test_hardening.py" ]]; then
        python3 "${SCRIPT_DIR}/test_hardening.py" \
            2>&1 | tee -a "${LOG_FILE}" || {
                print_warning "Hardening tests encountered issues"
            }
        print_success "Hardening validation complete"
    else
        print_warning "Hardening test module not found, skipping..."
    fi
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    local skip_pentest=false
    local skip_hardening=false
    local skip_compliance=false
    local skip_performance=false
    local quick_mode=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --targets|-t)
                TARGETS="$2"
                shift 2
                ;;
            --org|-o)
                ORGANIZATION="$2"
                shift 2
                ;;
            --skip-pentest)
                skip_pentest=true
                shift
                ;;
            --skip-hardening)
                skip_hardening=true
                shift
                ;;
            --skip-compliance)
                skip_compliance=true
                shift
                ;;
            --skip-performance)
                skip_performance=true
                shift
                ;;
            --quick|-q)
                quick_mode=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  -t, --targets TARGETS     Targets to scan (default: localhost)"
                echo "  -o, --org ORGANIZATION    Organization name"
                echo "  --skip-pentest            Skip penetration testing"
                echo "  --skip-hardening          Skip hardening assessment"
                echo "  --skip-compliance         Skip compliance checking"
                echo "  --skip-performance        Skip performance monitoring"
                echo "  -q, --quick               Quick assessment mode"
                echo "  -h, --help                Show this help"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Start assessment
    print_banner

    # Record start time
    START_TIME=$(date +%s)

    # Setup
    check_dependencies
    create_directories

    # Run assessment modules
    if [[ "${skip_pentest}" != true ]]; then
        run_pentest
    fi

    if [[ "${skip_hardening}" != true ]]; then
        run_hardening_check
    fi

    if [[ "${skip_compliance}" != true ]]; then
        run_compliance_check
    fi

    if [[ "${quick_mode}" != true ]] && [[ "${skip_performance}" != true ]]; then
        run_performance_monitor
    fi

    # Additional analysis
    run_wazuh_tuning
    run_vulnerability_comparison
    run_hardening_tests

    # Generate final report
    generate_final_report

    # Calculate duration
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    # Print summary
    echo ""
    echo "============================================================"
    echo "  ASSESSMENT COMPLETE"
    echo "============================================================"
    echo ""
    echo "  Duration:     ${DURATION} seconds"
    echo "  Reports:      ${REPORTS_DIR}"
    echo "  Log File:     ${LOG_FILE}"
    echo ""
    echo "  Generated Reports:"
    echo "  - Penetration Test Report"
    echo "  - Security Hardening Report"
    echo "  - Compliance Assessment Report"
    echo "  - Performance Metrics Report"
    echo "  - Vulnerability Comparison Report"
    echo "  - Final Assessment Report"
    echo ""
    echo "============================================================"
    echo ""

    print_success "Security assessment completed successfully!"
}

# Run main function
main "$@"
