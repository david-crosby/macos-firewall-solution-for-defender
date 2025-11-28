#!/bin/bash

# Network Detection Library
# Determines if the device is on the corporate network
# Returns: "corporate" or "external"

set -euo pipefail

# Configuration variables - Update these for your environment
readonly CORPORATE_SSIDS=("CorpWiFi" "CorpGuest" "CorpSecure")
readonly CORPORATE_SUBNETS=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
readonly CORPORATE_DNS_SUFFIX="corp.internal"
readonly LOG_FILE="/var/log/firewall_management.log"

# Consistent logging function
log_message() {
    local level="$1"
    local message="$2"
    
    if [[ -z "${level:-}" ]] || [[ -z "${message:-}" ]]; then
        return 1
    fi
    
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE" 2>/dev/null || {
        printf '[%s] [ERROR] Failed to write to log file\n' "$(date '+%Y-%m-%d %H:%M:%S')" >&2
        return 1
    }
}

# Check if VPN is active
check_vpn_status() {
    local vpn_status
    
    if ! vpn_status=$(scutil --nc list 2>/dev/null); then
        log_message "DEBUG" "Failed to query VPN status"
        return 1
    fi
    
    if printf '%s\n' "$vpn_status" | grep -q "Connected"; then
        log_message "INFO" "VPN connection detected"
        return 0
    fi
    
    return 1
}

# Check if connected to corporate SSID
check_corporate_ssid() {
    local current_ssid
    local airport_path="/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
    
    if [[ ! -x "$airport_path" ]]; then
        log_message "DEBUG" "Airport utility not found"
        return 1
    fi
    
    if ! current_ssid=$("$airport_path" -I 2>/dev/null | awk -F: '/ SSID:/ {print $2}' | tr -d ' '); then
        log_message "DEBUG" "Failed to query WiFi status"
        return 1
    fi
    
    if [[ -z "$current_ssid" ]]; then
        log_message "DEBUG" "No WiFi connection detected"
        return 1
    fi
    
    for ssid in "${CORPORATE_SSIDS[@]}"; do
        if [[ "$current_ssid" == "$ssid" ]]; then
            log_message "INFO" "Corporate SSID detected: $current_ssid"
            return 0
        fi
    done
    
    log_message "DEBUG" "Non-corporate SSID: $current_ssid"
    return 1
}

# Check if IP address is in corporate subnet
check_corporate_subnet() {
    local ip_addresses
    local ip
    
    if ! ip_addresses=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}'); then
        log_message "DEBUG" "Failed to get IP addresses"
        return 1
    fi
    
    if [[ -z "$ip_addresses" ]]; then
        log_message "DEBUG" "No IP addresses found"
        return 1
    fi
    
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        
        for subnet in "${CORPORATE_SUBNETS[@]}"; do
            if check_ip_in_subnet "$ip" "$subnet"; then
                log_message "INFO" "Corporate subnet detected: $ip in $subnet"
                return 0
            fi
        done
    done <<< "$ip_addresses"
    
    log_message "DEBUG" "No corporate subnet match found"
    return 1
}

# Helper function to check if IP is in subnet
check_ip_in_subnet() {
    local ip="$1"
    local subnet="$2"
    
    if [[ -z "${ip:-}" ]] || [[ -z "${subnet:-}" ]]; then
        return 1
    fi
    
    if ! command -v python3 &>/dev/null; then
        log_message "ERROR" "Python 3 not found for subnet checking"
        return 1
    fi
    
    python3 -c "
import ipaddress
import sys
try:
    if ipaddress.ip_address('$ip') in ipaddress.ip_network('$subnet', strict=False):
        sys.exit(0)
    else:
        sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null
    
    return $?
}

# Check DNS suffix
check_dns_suffix() {
    local dns_domain
    
    if ! dns_domain=$(scutil --dns 2>/dev/null | grep "domain" | head -1 | awk '{print $3}'); then
        log_message "DEBUG" "Failed to query DNS"
        return 1
    fi
    
    if [[ -z "$dns_domain" ]]; then
        log_message "DEBUG" "No DNS domain found"
        return 1
    fi
    
    if [[ "$dns_domain" == *"$CORPORATE_DNS_SUFFIX"* ]]; then
        log_message "INFO" "Corporate DNS suffix detected: $dns_domain"
        return 0
    fi
    
    log_message "DEBUG" "Non-corporate DNS suffix: $dns_domain"
    return 1
}

# Main detection function
detect_network_location() {
    log_message "INFO" "Starting network location detection"
    
    if check_vpn_status; then
        printf '%s\n' "corporate"
        return 0
    fi
    
    if check_corporate_ssid; then
        printf '%s\n' "corporate"
        return 0
    fi
    
    if check_corporate_subnet; then
        printf '%s\n' "corporate"
        return 0
    fi
    
    if check_dns_suffix; then
        printf '%s\n' "corporate"
        return 0
    fi
    
    log_message "INFO" "External network detected"
    printf '%s\n' "external"
    return 0
}

# Execute detection if run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    detect_network_location
fi
