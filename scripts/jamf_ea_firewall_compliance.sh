#!/bin/zsh

# Jamf Pro Extension Attribute: Firewall Compliance Status
# Reports current firewall state and compliance to Jamf Pro inventory

typeset -r STATE_FILE="/var/tmp/firewall_state.json"

get_compliance_status() {
    if [[ ! -f "$STATE_FILE" ]]; then
        print -r "Unknown"
        return
    fi
    
    local compliance
    compliance=$(grep -o '"compliance": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$compliance" ]]; then
        print -r "Unknown"
    else
        print -r "$compliance"
    fi
}

get_network_location() {
    if [[ ! -f "$STATE_FILE" ]]; then
        print -r "Unknown"
        return
    fi
    
    local location
    location=$(grep -o '"location": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$location" ]]; then
        print -r "Unknown"
    else
        print -r "$location"
    fi
}

get_firewall_state() {
    local state
    if ! state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.'); then
        print -r "unknown"
        return
    fi
    print -r "$state"
}

get_last_check_time() {
    if [[ ! -f "$STATE_FILE" ]]; then
        print -r "Never"
        return
    fi
    
    local timestamp
    timestamp=$(grep -o '"timestamp": *"[^"]*"' "$STATE_FILE" 2>/dev/null | cut -d'"' -f4)
    
    if [[ -z "$timestamp" ]]; then
        print -r "Unknown"
    else
        print -r "$timestamp"
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
    
    print -r "<result>Status: $compliance | Location: $location | Firewall: $firewall_state | Last Check: $last_check</result>"
}

main
