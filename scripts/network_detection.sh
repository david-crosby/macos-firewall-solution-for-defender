#!/bin/zsh

# Network Detection Library
# Determines if the device is on the corporate network
# Returns: "corporate" or "external"

setopt NO_UNSET
setopt PIPE_FAIL

typeset -ar CORPORATE_SSIDS=("CorpWiFi" "CorpGuest" "CorpSecure")
typeset -ar CORPORATE_SUBNETS=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
typeset -r CORPORATE_DNS_SUFFIX="corp.internal"
typeset -r LOG_FILE="/var/log/firewall_management.log"

if [[ ! -w "$LOG_FILE" ]] && [[ ! -w "$(dirname "$LOG_FILE")" ]]; then
    print -u2 "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [WARNING] Cannot write to log file: $LOG_FILE"
fi

log_message() {
    local level="$1"
    local message="$2"
    
    if [[ -z "${level:-}" ]] || [[ -z "${message:-}" ]]; then
        return 1
    fi
    
    print -r "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [$level] $message" >> "$LOG_FILE" 2>/dev/null || {
        print -u2 "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [ERROR] Failed to write to log file"
        return 1
    }
}

check_vpn_status() {
    local vpn_status
    
    if ! vpn_status=$(scutil --nc list 2>/dev/null); then
        log_message "DEBUG" "Failed to query VPN status"
        return 1
    fi

    if print -r "$vpn_status" | grep -qE '^\s*\([0-9]+\).*Connected'; then
        log_message "INFO" "VPN connection detected"
        return 0
    fi
    
    return 1
}

check_corporate_ssid() {
    local current_ssid
    local airport_path="/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
    
    if [[ ! -x "$airport_path" ]]; then
        log_message "DEBUG" "Airport utility not found"
        return 1
    fi

    if ! current_ssid=$("$airport_path" -I 2>/dev/null | awk -F: '/^ *SSID:/ {print $2}' | tr -d ' '); then
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

ip_to_int() {
    local ip="$1"

    if [[ -z "${ip:-}" ]]; then
        return 1
    fi

    local -a octets
    
    IFS='.' read -rA octets <<< "$ip"
    
    if [[ ${#octets[@]} -ne 4 ]]; then
        return 1
    fi

    local octet
    for octet in "${octets[@]}"; do
        if [[ ! "$octet" =~ ^[0-9]+$ ]] || [[ "$octet" =~ ^0[0-9] ]] || (( octet > 255 )); then
            return 1
        fi
    done

    local result=0
    result=$(( (octets[1] << 24) + (octets[2] << 16) + (octets[3] << 8) + octets[4] ))
    print -r "$result"
    
    return 0
}

check_ip_in_subnet() {
    local ip="$1"
    local subnet="$2"
    
    if [[ -z "${ip:-}" ]] || [[ -z "${subnet:-}" ]]; then
        return 1
    fi
    
    local network_part="${subnet%/*}"
    local prefix_length="${subnet#*/}"
    
    if [[ "$network_part" == "$subnet" ]]; then
        return 1
    fi

    # Validate prefix length (1-32 for IPv4, excluding 0 to avoid undefined shift behavior)
    if [[ ! "$prefix_length" =~ ^[0-9]+$ ]] || (( prefix_length < 1 || prefix_length > 32 )); then
        return 1
    fi
    
    local ip_int network_int mask
    
    if ! ip_int=$(ip_to_int "$ip"); then
        return 1
    fi
    
    if ! network_int=$(ip_to_int "$network_part"); then
        return 1
    fi
    
    mask=$(( 0xFFFFFFFF << (32 - prefix_length) ))
    mask=$(( mask & 0xFFFFFFFF ))
    
    local ip_network=$(( ip_int & mask ))
    local subnet_network=$(( network_int & mask ))
    
    if (( ip_network == subnet_network )); then
        return 0
    fi
    
    return 1
}

check_corporate_subnet() {
    local ip_addresses
    local ip
    
    ip_addresses=$(networksetup -listallhardwareports 2>/dev/null | while read -r line; do
        if [[ "$line" =~ '^Device: (.+)$' ]]; then
            ipconfig getifaddr "$match[1]" 2>/dev/null
        fi
    done | grep -v "127.0.0.1")       
    
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

check_dns_suffix() {
    local dns_domain
    
    dns_domain=$(scutil --dns 2>/dev/null | grep "^  domain " | head -1 | awk '{print $3}')

    if [[ $? -ne 0 ]]; then
        log_message "DEBUG" "Failed to query DNS"
        return 1
    fi
    
    if [[ -z "$dns_domain" ]]; then
        log_message "DEBUG" "No DNS domain found"
        return 1
    fi

    # Match exact domain or proper subdomain (prevents matching "corp.internal.malicious.com")
    if [[ "$dns_domain" == "$CORPORATE_DNS_SUFFIX" ]] || [[ "$dns_domain" == *".$CORPORATE_DNS_SUFFIX" ]]; then
        log_message "INFO" "Corporate DNS suffix detected: $dns_domain"
        return 0
    fi
    
    log_message "DEBUG" "Non-corporate DNS suffix: $dns_domain"
    return 1
}

detect_network_location() {
    log_message "INFO" "Starting network location detection"
    
    if check_vpn_status; then
        print -r "corporate"
        return 0
    fi
    
    if check_corporate_ssid; then
        print -r "corporate"
        return 0
    fi
    
    if check_corporate_subnet; then
        print -r "corporate"
        return 0
    fi
    
    if check_dns_suffix; then
        print -r "corporate"
        return 0
    fi
    
    log_message "INFO" "External network detected"
    print -r "external"
    return 0
}

if [[ "${ZSH_EVAL_CONTEXT}" == *:file ]]; then
    detect_network_location
fi
