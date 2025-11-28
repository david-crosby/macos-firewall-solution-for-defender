#!/bin/bash

# Jamf Pro Extension Attribute: Firewall Compliance Status
# Reports current firewall state and compliance to Jamf Pro inventory

readonly STATE_FILE="/var/tmp/firewall_state.json"

get_compliance_status() {
    if [[ ! -f "$STATE_FILE" ]]; then
        printf '%s\n' "Unknown"
        return
    fi
    
    local compliance
    compliance=$(grep -o '"compliance": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$compliance" ]]; then
        printf '%s\n' "Unknown"
    else
        printf '%s\n' "$compliance"
    fi
}

get_network_location() {
    if [[ ! -f "$STATE_FILE" ]]; then
        printf '%s\n' "Unknown"
        return
    fi
    
    local location
    location=$(grep -o '"location": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$location" ]]; then
        printf '%s\n' "Unknown"
    else
        printf '%s\n' "$location"
    fi
}

get_firewall_state() {
    local state
    if ! state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.'); then
        printf '%s\n' "unknown"
        return
    fi
    printf '%s\n' "$state"
}

get_last_check_time() {
    if [[ ! -f "$STATE_FILE" ]]; then
        printf '%s\n' "Never"
        return
    fi
    
    local timestamp
    timestamp=$(grep -o '"timestamp": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$timestamp" ]]; then
        printf '%s\n' "Unknown"
    else
        printf '%s\n' "$timestamp"
    fi
}

main() {
    local compliance
    compliance=$(get_compliance_status)
    
    local location
    location=$(get_network_location)
    
    local firewall_state
    firewall_state=$(get_firewall_state)
    
    local last_check
    last_check=$(get_last_check_time)
    
    printf '<result>Status: %s | Location: %s | Firewall: %s | Last Check: %s</result>\n' "$compliance" "$location" "$firewall_state" "$last_check"
}

main
