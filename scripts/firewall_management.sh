#!/bin/bash

# Firewall Management Script
# Manages macOS application firewall based on network location
# Integrates with Microsoft Defender for Endpoint for compliance reporting

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/firewall_management.log"
readonly STATE_FILE="/var/tmp/firewall_state.json"
readonly LAST_LOCATION_FILE="/var/tmp/last_network_location"
readonly SOCKETFILTER="/usr/libexec/ApplicationFirewall/socketfilterfw"

# Check dependencies
if [[ ! -f "${SCRIPT_DIR}/network_detection.sh" ]]; then
    printf '[%s] [ERROR] network_detection.sh not found\n' "$(date '+%Y-%m-%d %H:%M:%S')" >&2
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/firewall_rules.sh" ]]; then
    printf '[%s] [ERROR] firewall_rules.sh not found\n' "$(date '+%Y-%m-%d %H:%M:%S')" >&2
    exit 1
fi

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/network_detection.sh"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/firewall_rules.sh"

# Consistent logging function
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    
    if [[ -z "$message" ]]; then
        return 1
    fi
    
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" | tee -a "$LOG_FILE" >/dev/null 2>&1
}

ensure_firewall_enabled() {
    local current_state
    
    if ! current_state=$("$SOCKETFILTER" --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.'); then
        log_message "ERROR" "Failed to query firewall state"
        return 1
    fi
    
    if [[ "$current_state" != "enabled" ]]; then
        log_message "WARNING" "Firewall is disabled, enabling now"
        
        if ! "$SOCKETFILTER" --setglobalstate on >/dev/null 2>&1; then
            log_message "ERROR" "Failed to enable firewall"
            return 1
        fi
        
        log_message "INFO" "Firewall enabled successfully"
        return 1
    fi
    
    return 0
}

enable_stealth_mode() {
    if ! "$SOCKETFILTER" --setstealthmode on >/dev/null 2>&1; then
        log_message "ERROR" "Failed to enable stealth mode"
        return 1
    fi
    log_message "INFO" "Stealth mode enabled"
    return 0
}

set_logging_mode() {
    if ! "$SOCKETFILTER" --setloggingmode on >/dev/null 2>&1; then
        log_message "ERROR" "Failed to enable logging"
        return 1
    fi
    
    if ! "$SOCKETFILTER" --setloggingopt detail >/dev/null 2>&1; then
        log_message "WARNING" "Failed to set detailed logging"
    fi
    
    log_message "INFO" "Detailed logging enabled"
    return 0
}

block_all_incoming() {
    if ! "$SOCKETFILTER" --setblockall off >/dev/null 2>&1; then
        log_message "ERROR" "Failed to configure block all setting"
        return 1
    fi
    log_message "INFO" "Block all incoming connections disabled (managing via app rules)"
    return 0
}

enable_signed_apps() {
    if ! "$SOCKETFILTER" --setallowsigned on >/dev/null 2>&1; then
        log_message "ERROR" "Failed to enable allow signed setting"
        return 1
    fi
    
    if ! "$SOCKETFILTER" --setallowsignedapp on >/dev/null 2>&1; then
        log_message "ERROR" "Failed to enable allow signed app setting"
        return 1
    fi
    
    log_message "INFO" "Automatically allow signed applications enabled"
    return 0
}

get_current_firewall_apps() {
    local apps
    
    if ! apps=$("$SOCKETFILTER" --listapps 2>/dev/null); then
        log_message "ERROR" "Failed to list firewall applications"
        return 1
    fi
    
    printf '%s\n' "$apps" | grep -v "^$" | grep -v "Firewall" | grep -v "ALF" | awk '{print $3}' | sort
}

clear_all_firewall_rules() {
    log_message "INFO" "Clearing existing firewall rules"
    
    local apps
    if ! apps=$(get_current_firewall_apps); then
        log_message "ERROR" "Failed to get current firewall apps"
        return 1
    fi
    
    while IFS= read -r app; do
        if [[ -n "$app" ]] && [[ -f "$app" ]]; then
            "$SOCKETFILTER" --remove "$app" >/dev/null 2>&1 || true
        fi
    done <<< "$apps"
    
    return 0
}

apply_firewall_rules() {
    local location="${1:-}"
    
    if [[ -z "$location" ]]; then
        log_message "ERROR" "No location provided to apply_firewall_rules"
        return 1
    fi
    
    log_message "INFO" "Applying firewall rules for location: $location"
    
    if ! clear_all_firewall_rules; then
        log_message "ERROR" "Failed to clear existing rules"
        return 1
    fi
    
    local allowed_apps
    if ! allowed_apps=$(get_allowed_apps_for_location "$location"); then
        log_message "ERROR" "Failed to get allowed apps for location: $location"
        return 1
    fi
    
    local added_count=0
    local failed_count=0
    
    while IFS= read -r app; do
        [[ -z "$app" ]] && continue
        
        if [[ -f "$app" ]]; then
            if "$SOCKETFILTER" --add "$app" >/dev/null 2>&1; then
                "$SOCKETFILTER" --unblockapp "$app" >/dev/null 2>&1 || true
                ((added_count++))
            else
                log_message "WARNING" "Failed to add application: $app"
                ((failed_count++))
            fi
        else
            log_message "DEBUG" "Application not found, skipping: $app"
        fi
    done <<< "$allowed_apps"
    
    log_message "INFO" "Firewall rules applied: $added_count added, $failed_count failed"
    
    if [[ -v BUILTIN_SERVICES[@] ]]; then
        for service in "${BUILTIN_SERVICES[@]}"; do
            "$SOCKETFILTER" --add "$service" >/dev/null 2>&1 || true
            "$SOCKETFILTER" --unblockapp "$service" >/dev/null 2>&1 || true
        done
    fi
    
    return 0
}

check_unsigned_apps() {
    log_message "INFO" "Checking for unsigned application attempts"
    
    local firewall_log="/var/log/appfirewall.log"
    
    if [[ ! -f "$firewall_log" ]]; then
        log_message "DEBUG" "Firewall log not found"
        return 0
    fi
    
    local unsigned_attempts
    if unsigned_attempts=$(grep -i "unsigned" "$firewall_log" 2>/dev/null | tail -20); then
        if [[ -n "$unsigned_attempts" ]]; then
            log_message "WARNING" "Unsigned application connection attempts detected"
            printf '%s\n' "$unsigned_attempts" >> "${LOG_FILE}.unsigned_apps"
            return 1
        fi
    fi
    
    return 0
}

get_firewall_state() {
    local state
    
    if ! state=$("$SOCKETFILTER" --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.'); then
        log_message "ERROR" "Failed to get firewall state"
        printf '%s\n' "unknown"
        return 1
    fi
    
    printf '%s\n' "$state"
    return 0
}

verify_rules_compliance() {
    local location="${1:-}"
    local expected_apps
    local current_apps
    
    if [[ -z "$location" ]]; then
        log_message "ERROR" "No location provided to verify_rules_compliance"
        return 1
    fi
    
    if ! expected_apps=$(get_allowed_apps_for_location "$location"); then
        log_message "ERROR" "Failed to get expected apps"
        return 1
    fi
    
    if ! current_apps=$(get_current_firewall_apps); then
        log_message "ERROR" "Failed to get current apps"
        return 1
    fi
    
    local expected_count
    expected_count=$(printf '%s\n' "$expected_apps" | grep -c "." || printf '%s\n' "0")
    
    local current_count
    current_count=$(printf '%s\n' "$current_apps" | grep -c "." || printf '%s\n' "0")
    
    if [[ "$current_count" -lt "$expected_count" ]]; then
        log_message "WARNING" "Rule count mismatch: Expected $expected_count, Found $current_count"
        return 1
    fi
    
    return 0
}

save_state() {
    local location="${1:-}"
    local firewall_state="${2:-}"
    local compliance="${3:-}"
    
    if [[ -z "$location" ]] || [[ -z "$firewall_state" ]] || [[ -z "$compliance" ]]; then
        log_message "ERROR" "Missing parameters for save_state"
        return 1
    fi
    
    local hostname
    hostname=$(hostname 2>/dev/null || printf '%s\n' "unknown")
    
    local serial
    serial=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $4}' || printf '%s\n' "unknown")
    
    cat > "$STATE_FILE" <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "location": "$location",
    "firewall_state": "$firewall_state",
    "compliance": "$compliance",
    "hostname": "$hostname",
    "serial": "$serial"
}
EOF
    
    if [[ $? -ne 0 ]]; then
        log_message "ERROR" "Failed to save state file"
        return 1
    fi
    
    return 0
}

check_location_change() {
    local current_location="${1:-}"
    local last_location=""
    
    if [[ -z "$current_location" ]]; then
        log_message "ERROR" "No location provided to check_location_change"
        return 1
    fi
    
    if [[ -f "$LAST_LOCATION_FILE" ]]; then
        last_location=$(cat "$LAST_LOCATION_FILE" 2>/dev/null || printf '%s\n' "")
    fi
    
    if [[ "$current_location" != "$last_location" ]]; then
        log_message "INFO" "Network location changed: $last_location -> $current_location"
        
        if ! printf '%s\n' "$current_location" > "$LAST_LOCATION_FILE"; then
            log_message "ERROR" "Failed to save location to file"
            return 1
        fi
        
        return 0
    fi
    
    return 1
}

remediate_firewall() {
    local location="${1:-}"
    
    if [[ -z "$location" ]]; then
        log_message "ERROR" "No location provided to remediate_firewall"
        return 1
    fi
    
    log_message "INFO" "Starting firewall remediation"
    
    ensure_firewall_enabled
    enable_stealth_mode
    set_logging_mode
    block_all_incoming
    enable_signed_apps
    apply_firewall_rules "$location"
    
    pkill -HUP socketfilterfw >/dev/null 2>&1 || true
    
    log_message "INFO" "Firewall remediation completed"
}

main() {
    log_message "INFO" "Starting firewall management check"
    
    local location
    if ! location=$(detect_network_location); then
        log_message "ERROR" "Failed to detect network location"
        exit 1
    fi
    
    local firewall_state
    firewall_state=$(get_firewall_state)
    
    local needs_remediation=false
    local compliance_status="compliant"
    
    if [[ "$firewall_state" != "enabled" ]]; then
        log_message "ERROR" "Firewall is disabled"
        needs_remediation=true
        compliance_status="firewall_disabled"
    fi
    
    if ! verify_rules_compliance "$location"; then
        log_message "WARNING" "Firewall rules not compliant"
        needs_remediation=true
        compliance_status="rule_violation"
    fi
    
    if check_location_change "$location"; then
        log_message "INFO" "Location change detected, applying new rules"
        needs_remediation=true
    fi
    
    if ! check_unsigned_apps; then
        compliance_status="unsigned_app_detected"
    fi
    
    if [[ "$needs_remediation" == "true" ]]; then
        remediate_firewall "$location"
        
        if [[ -f "${SCRIPT_DIR}/mde_reporting.sh" ]]; then
            # shellcheck source=/dev/null
            source "${SCRIPT_DIR}/mde_reporting.sh"
            send_mde_signal "$compliance_status" "$location"
        fi
        
        if [[ -f "${SCRIPT_DIR}/user_notification.sh" ]]; then
            # shellcheck source=/dev/null
            source "${SCRIPT_DIR}/user_notification.sh"
            notify_user_remediation "$compliance_status"
        fi
    fi
    
    save_state "$location" "$firewall_state" "$compliance_status"
    
    if [[ -f "${SCRIPT_DIR}/mde_reporting.sh" ]]; then
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/mde_reporting.sh"
        send_mde_signal "compliant" "$location"
    fi
    
    log_message "INFO" "Firewall management check completed"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
