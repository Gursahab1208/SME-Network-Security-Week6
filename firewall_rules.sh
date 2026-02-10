#!/bin/bash
#
# SME Network Security Assessment Framework
# Week 6: Linux Firewall Hardening Script (iptables/nftables)
#
# This script implements comprehensive firewall hardening including:
# - Security zone definitions
# - Strict ingress/egress filtering
# - Connection tracking
# - Logging of denied connections
# - Rate limiting
#
# Author: SME Security Team
# Version: 1.0.0
#
# Usage: sudo ./firewall_rules.sh [apply|test|backup|restore|status]
#

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

# Network interfaces
WAN_INTERFACE="${WAN_INTERFACE:-eth0}"
LAN_INTERFACE="${LAN_INTERFACE:-eth1}"

# Network definitions
TRUSTED_NETWORKS="${TRUSTED_NETWORKS:-192.168.1.0/24 10.0.0.0/8}"
MANAGEMENT_HOSTS="${MANAGEMENT_HOSTS:-192.168.1.10 192.168.1.11}"
DNS_SERVERS="${DNS_SERVERS:-8.8.8.8 8.8.4.4 1.1.1.1}"
NTP_SERVERS="${NTP_SERVERS:-time.google.com time.cloudflare.com}"

# Service ports
SSH_PORT="${SSH_PORT:-22}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"

# Rate limiting
SSH_RATE_LIMIT="${SSH_RATE_LIMIT:-4/minute}"
HTTP_RATE_LIMIT="${HTTP_RATE_LIMIT:-25/second}"
ICMP_RATE_LIMIT="${ICMP_RATE_LIMIT:-1/second}"

# Logging
LOG_PREFIX="[FIREWALL] "
BACKUP_DIR="/etc/iptables-backup"
RULES_FILE="/etc/iptables/rules.v4"
LOG_FILE="/var/log/firewall-hardening.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${LOG_FILE}" 2>/dev/null || true
}

log_info() {
    log "INFO" "$*"
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$*"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$*"
    echo -e "${RED}[ERROR]${NC} $*"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    local deps=("iptables" "ip6tables")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi

    log_info "All dependencies satisfied"
}

backup_rules() {
    local backup_file="${BACKUP_DIR}/iptables-$(date '+%Y%m%d-%H%M%S').backup"

    mkdir -p "${BACKUP_DIR}"

    log_info "Backing up current iptables rules to ${backup_file}"

    iptables-save > "${backup_file}" 2>/dev/null || true
    ip6tables-save > "${backup_file}.v6" 2>/dev/null || true

    log_info "Backup completed"
}

restore_rules() {
    local backup_file="$1"

    if [[ ! -f "${backup_file}" ]]; then
        log_error "Backup file not found: ${backup_file}"
        exit 1
    fi

    log_info "Restoring rules from ${backup_file}"

    iptables-restore < "${backup_file}"

    if [[ -f "${backup_file}.v6" ]]; then
        ip6tables-restore < "${backup_file}.v6"
    fi

    log_info "Rules restored successfully"
}

# ============================================================================
# FIREWALL RULE FUNCTIONS
# ============================================================================

flush_rules() {
    log_info "Flushing existing firewall rules"

    # IPv4
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t raw -F
    iptables -t raw -X

    # IPv6
    ip6tables -F
    ip6tables -X
    ip6tables -t mangle -F
    ip6tables -t mangle -X
    ip6tables -t raw -F
    ip6tables -t raw -X

    log_info "All rules flushed"
}

set_default_policies() {
    log_info "Setting default policies to DROP"

    # IPv4 - Default DROP
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # IPv6 - Default DROP (adjust if IPv6 needed)
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
}

create_custom_chains() {
    log_info "Creating custom chains"

    # Create custom chains for organization
    iptables -N LOGGING 2>/dev/null || iptables -F LOGGING
    iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
    iptables -N TRUSTED_INPUT 2>/dev/null || iptables -F TRUSTED_INPUT
    iptables -N TRUSTED_OUTPUT 2>/dev/null || iptables -F TRUSTED_OUTPUT
    iptables -N MANAGEMENT 2>/dev/null || iptables -F MANAGEMENT
    iptables -N SERVICES 2>/dev/null || iptables -F SERVICES
    iptables -N ANTI_SPOOFING 2>/dev/null || iptables -F ANTI_SPOOFING
    iptables -N SCANNER_BLOCK 2>/dev/null || iptables -F SCANNER_BLOCK
}

setup_loopback() {
    log_info "Configuring loopback interface"

    # Allow all loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Drop packets claiming to be from loopback on non-loopback interfaces
    iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP
}

setup_connection_tracking() {
    log_info "Configuring connection tracking"

    # Accept established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

    # Enable SYN flood protection
    iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 -j REJECT --reject-with tcp-reset
}

setup_anti_spoofing() {
    log_info "Configuring anti-spoofing rules"

    # RFC 1918 private addresses that shouldn't appear on WAN
    local BOGON_NETS="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"

    for net in ${BOGON_NETS}; do
        iptables -A ANTI_SPOOFING -i "${WAN_INTERFACE}" -s "${net}" -j DROP
    done

    # Block packets with invalid TCP flags
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A ANTI_SPOOFING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

    # Apply anti-spoofing chain to INPUT
    iptables -A INPUT -j ANTI_SPOOFING
}

setup_scanner_detection() {
    log_info "Configuring port scanner detection"

    # Detect and block port scanners
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP

    # NULL scan detection
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL NONE -m limit --limit 1/hour --limit-burst 5 -j LOG --log-prefix "${LOG_PREFIX}NULL_SCAN: "
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL NONE -j DROP

    # XMAS scan detection
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL ALL -m limit --limit 1/hour --limit-burst 5 -j LOG --log-prefix "${LOG_PREFIX}XMAS_SCAN: "
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL ALL -j DROP

    # FIN scan detection
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL FIN -m limit --limit 1/hour --limit-burst 5 -j LOG --log-prefix "${LOG_PREFIX}FIN_SCAN: "
    iptables -A SCANNER_BLOCK -p tcp --tcp-flags ALL FIN -j DROP

    # Apply to INPUT
    iptables -A INPUT -p tcp -j SCANNER_BLOCK
}

setup_rate_limiting() {
    log_info "Configuring rate limiting"

    # SSH rate limiting
    iptables -A RATE_LIMIT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --set --name SSH
    iptables -A RATE_LIMIT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j LOG --log-prefix "${LOG_PREFIX}SSH_BRUTE: "
    iptables -A RATE_LIMIT -p tcp --dport "${SSH_PORT}" -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

    # HTTP rate limiting
    iptables -A RATE_LIMIT -p tcp --dport "${HTTP_PORT}" -m limit --limit ${HTTP_RATE_LIMIT} --limit-burst 50 -j RETURN
    iptables -A RATE_LIMIT -p tcp --dport "${HTTP_PORT}" -j DROP

    # HTTPS rate limiting
    iptables -A RATE_LIMIT -p tcp --dport "${HTTPS_PORT}" -m limit --limit ${HTTP_RATE_LIMIT} --limit-burst 50 -j RETURN
    iptables -A RATE_LIMIT -p tcp --dport "${HTTPS_PORT}" -j DROP

    # ICMP rate limiting
    iptables -A RATE_LIMIT -p icmp --icmp-type echo-request -m limit --limit ${ICMP_RATE_LIMIT} --limit-burst 4 -j ACCEPT
    iptables -A RATE_LIMIT -p icmp --icmp-type echo-request -j DROP

    # Apply rate limiting to INPUT
    iptables -A INPUT -j RATE_LIMIT
}

setup_trusted_networks() {
    log_info "Configuring trusted networks"

    # Allow traffic from trusted networks
    for network in ${TRUSTED_NETWORKS}; do
        iptables -A TRUSTED_INPUT -s "${network}" -j ACCEPT
        iptables -A TRUSTED_OUTPUT -d "${network}" -j ACCEPT
    done

    # Allow management hosts full access
    for host in ${MANAGEMENT_HOSTS}; do
        iptables -A MANAGEMENT -s "${host}" -j ACCEPT
    done
}

setup_service_rules() {
    log_info "Configuring service access rules"

    # SSH - restricted to trusted networks/management hosts
    for host in ${MANAGEMENT_HOSTS}; do
        iptables -A SERVICES -p tcp -s "${host}" --dport "${SSH_PORT}" -j ACCEPT
    done

    # HTTP/HTTPS - public access with rate limiting
    iptables -A SERVICES -p tcp --dport "${HTTP_PORT}" -j ACCEPT
    iptables -A SERVICES -p tcp --dport "${HTTPS_PORT}" -j ACCEPT

    # DNS - outbound only
    for dns in ${DNS_SERVERS}; do
        iptables -A OUTPUT -p udp -d "${dns}" --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "${dns}" --dport 53 -j ACCEPT
    done

    # NTP - outbound only
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

    # ICMP - controlled
    iptables -A SERVICES -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A SERVICES -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A SERVICES -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A SERVICES -p icmp --icmp-type time-exceeded -j ACCEPT

    # Apply services chain to INPUT
    iptables -A INPUT -j SERVICES
}

setup_output_rules() {
    log_info "Configuring outbound rules"

    # Allow DNS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow HTTP/HTTPS (for updates)
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

    # Allow NTP
    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

    # Allow ICMP
    iptables -A OUTPUT -p icmp -j ACCEPT

    # Allow SSH from this host (for management)
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

    # Allow established connections (already added in connection tracking)
}

setup_logging() {
    log_info "Configuring logging for denied packets"

    # Log dropped packets
    iptables -A LOGGING -m limit --limit 5/min -j LOG --log-prefix "${LOG_PREFIX}DROPPED: " --log-level 4
    iptables -A LOGGING -j DROP

    # Add logging chain to end of INPUT and FORWARD
    iptables -A INPUT -j LOGGING
    iptables -A FORWARD -j LOGGING

    # Log dropped OUTPUT (optional - can be verbose)
    iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "${LOG_PREFIX}OUT_DROPPED: " --log-level 4
    iptables -A OUTPUT -j DROP
}

setup_ipv6_rules() {
    log_info "Configuring IPv6 rules (restrictive)"

    # Allow loopback
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMPv6 for proper IPv6 operation
    ip6tables -A INPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 1/s -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

    # Neighbor discovery
    ip6tables -A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbour-solicitation -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbour-advertisement -j ACCEPT

    # Log and drop everything else
    ip6tables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "${LOG_PREFIX}IPv6_DROPPED: " --log-level 4
    ip6tables -A INPUT -j DROP
    ip6tables -A FORWARD -j DROP
    ip6tables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "${LOG_PREFIX}IPv6_OUT_DROPPED: " --log-level 4
    ip6tables -A OUTPUT -j DROP
}

save_rules() {
    log_info "Saving firewall rules"

    # Create directory if needed
    mkdir -p "$(dirname ${RULES_FILE})"

    # Save IPv4 rules
    iptables-save > "${RULES_FILE}"

    # Save IPv6 rules
    ip6tables-save > "${RULES_FILE%.v4}.v6"

    log_info "Rules saved to ${RULES_FILE}"
}

show_status() {
    echo ""
    echo "=============================================="
    echo "         FIREWALL STATUS REPORT"
    echo "=============================================="
    echo ""
    echo "IPv4 Rules:"
    echo "------------"
    iptables -L -n -v --line-numbers
    echo ""
    echo "NAT Rules:"
    echo "------------"
    iptables -t nat -L -n -v --line-numbers
    echo ""
    echo "IPv6 Rules:"
    echo "------------"
    ip6tables -L -n -v --line-numbers
    echo ""
    echo "=============================================="
}

apply_rules() {
    log_info "Applying firewall hardening rules"

    # Backup current rules
    backup_rules

    # Flush existing rules
    flush_rules

    # Set default policies
    set_default_policies

    # Create custom chains
    create_custom_chains

    # Configure rules
    setup_loopback
    setup_connection_tracking
    setup_anti_spoofing
    setup_scanner_detection
    setup_rate_limiting
    setup_trusted_networks
    setup_service_rules
    setup_output_rules
    setup_logging
    setup_ipv6_rules

    # Save rules
    save_rules

    log_info "Firewall hardening completed successfully"

    # Show summary
    echo ""
    echo "=============================================="
    echo "    FIREWALL HARDENING APPLIED SUCCESSFULLY"
    echo "=============================================="
    echo ""
    echo "Configuration Summary:"
    echo "  - Default policy: DROP"
    echo "  - Trusted networks: ${TRUSTED_NETWORKS}"
    echo "  - Management hosts: ${MANAGEMENT_HOSTS}"
    echo "  - SSH port: ${SSH_PORT}"
    echo "  - Rate limiting: Enabled"
    echo "  - Logging: Enabled"
    echo ""
    echo "Logs: ${LOG_FILE}"
    echo "Backup: ${BACKUP_DIR}"
    echo ""
}

test_rules() {
    log_info "Testing firewall rules (dry run)"

    echo ""
    echo "=============================================="
    echo "    FIREWALL RULES TEST (DRY RUN)"
    echo "=============================================="
    echo ""
    echo "The following rules would be applied:"
    echo ""
    echo "1. Default Policies:"
    echo "   - INPUT: DROP"
    echo "   - FORWARD: DROP"
    echo "   - OUTPUT: DROP"
    echo ""
    echo "2. Custom Chains:"
    echo "   - LOGGING"
    echo "   - RATE_LIMIT"
    echo "   - TRUSTED_INPUT"
    echo "   - TRUSTED_OUTPUT"
    echo "   - MANAGEMENT"
    echo "   - SERVICES"
    echo "   - ANTI_SPOOFING"
    echo "   - SCANNER_BLOCK"
    echo ""
    echo "3. Trusted Networks: ${TRUSTED_NETWORKS}"
    echo "4. Management Hosts: ${MANAGEMENT_HOSTS}"
    echo "5. Allowed Services:"
    echo "   - SSH (port ${SSH_PORT}) - Management hosts only"
    echo "   - HTTP (port ${HTTP_PORT}) - Rate limited"
    echo "   - HTTPS (port ${HTTPS_PORT}) - Rate limited"
    echo ""
    echo "6. Rate Limits:"
    echo "   - SSH: ${SSH_RATE_LIMIT}"
    echo "   - HTTP: ${HTTP_RATE_LIMIT}"
    echo "   - ICMP: ${ICMP_RATE_LIMIT}"
    echo ""
    echo "Use './firewall_rules.sh apply' to apply these rules"
    echo ""
}

print_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  apply     Apply firewall hardening rules"
    echo "  test      Show rules that would be applied (dry run)"
    echo "  backup    Backup current firewall rules"
    echo "  restore   Restore rules from backup (requires backup file path)"
    echo "  status    Show current firewall status"
    echo "  flush     Flush all rules and set ACCEPT policy"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  WAN_INTERFACE     External interface (default: eth0)"
    echo "  LAN_INTERFACE     Internal interface (default: eth1)"
    echo "  TRUSTED_NETWORKS  Trusted network ranges"
    echo "  MANAGEMENT_HOSTS  Hosts allowed SSH access"
    echo "  SSH_PORT          SSH port (default: 22)"
    echo ""
    echo "Examples:"
    echo "  $0 apply"
    echo "  $0 test"
    echo "  $0 restore /etc/iptables-backup/iptables-20240115.backup"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    local command="${1:-help}"

    case "${command}" in
        apply)
            check_root
            check_dependencies
            apply_rules
            ;;
        test)
            test_rules
            ;;
        backup)
            check_root
            check_dependencies
            backup_rules
            ;;
        restore)
            check_root
            check_dependencies
            if [[ -z "${2:-}" ]]; then
                log_error "Backup file path required"
                exit 1
            fi
            restore_rules "$2"
            ;;
        status)
            check_root
            show_status
            ;;
        flush)
            check_root
            check_dependencies
            backup_rules
            flush_rules
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            log_info "All rules flushed, policies set to ACCEPT"
            ;;
        help|--help|-h)
            print_usage
            ;;
        *)
            log_error "Unknown command: ${command}"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
