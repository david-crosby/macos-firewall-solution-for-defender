#!/bin/zsh

# Firewall Management Script
# Manages macOS application firewall based on network location
# Integrates with Microsoft Defender for Endpoint for compliance reporting

setopt NO_UNSET
setopt PIPE_FAIL

typeset -r SCRIPT_DIR="${0:a:h}"
typeset -r LOG_FILE="/var/log/firewall_management.log"
typeset -r STATE_FILE="/var/tmp/firewall_state.json"
typeset -r LAST_LOCATION_FILE="/var/tmp/last_network_location"
typeset -r SOCKETFILTER="/usr/libexec/ApplicationFirewall/socketfilterfw"

if [[ ! -f "${SCRIPT_DIR}/network_detection.sh" ]]; then
    print -u2 "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [ERROR] network_detection.sh not found"
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/firewall_rules.sh" ]]; then
    print -u2 "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [ERROR] firewall_rules.sh not found"
    exit 1
fi

source "${SCRIPT_DIR}/network_detection.sh"
source "${SCRIPT_DIR}/firewall_rules.sh"

log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"

    if [[ -z "$message" ]]; then
        return 1
    fi

    print -r "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [$level] $message" | tee -a "$LOG_FILE" >/dev/null 2>&1
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
        return 0
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

    print -r "$apps" | grep -v -E '^$|Firewall|ALF' | awk 'NF >= 3 {print $3}' | sort
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
    done < <(print -r "$apps")

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
    done < <(print -r "$allowed_apps")

    log_message "INFO" "Firewall rules applied: $added_count added, $failed_count failed"

    if [[ -n "${BUILTIN_SERVICES[@]:-}" ]]; then
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
            print -r "$unsigned_attempts" >> "${LOG_FILE}.unsigned_apps"
            return 1
        fi
    fi
    
    return 0
}

get_firewall_state() {
    local state
    
    if ! state=$("$SOCKETFILTER" --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.'); then
        log_message "ERROR" "Failed to get firewall state"
        print -r "unknown"
        return 1
    fi
    
    print -r "$state"
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
    expected_count=$(print -r "$expected_apps" | grep -c "^" || print -r "0")

    local current_count
    current_count=$(print -r "$current_apps" | grep -c "^" || print -r "0")
    
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
    hostname=$(hostname 2>/dev/null || print -r "unknown")
    
    local serial
    serial=$(ioreg -l | awk '/IOPlatformSerialNumber/ {print $4}' | tr -d '"' 2>/dev/null || print -r "unknown")
    
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
    local save_result=$?

    if [[ $save_result -ne 0 ]]; then
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
        last_location=$(cat "$LAST_LOCATION_FILE" 2>/dev/null || print -r "")
    fi
    
    if [[ "$current_location" != "$last_location" ]]; then
        log_message "INFO" "Network location changed: $last_location -> $current_location"
        
        if ! print -r "$current_location" > "$LAST_LOCATION_FILE"; then
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

    local remediation_failed=false

    ensure_firewall_enabled || {
        log_message "ERROR" "Remediation: Failed to enable firewall"
        remediation_failed=true
    }

    enable_stealth_mode || log_message "WARNING" "Remediation: Failed to enable stealth mode"
    set_logging_mode || log_message "WARNING" "Remediation: Failed to set logging mode"
    block_all_incoming || log_message "WARNING" "Remediation: Failed to configure block all setting"
    enable_signed_apps || log_message "WARNING" "Remediation: Failed to enable signed apps"

    apply_firewall_rules "$location" || {
        log_message "ERROR" "Remediation: Failed to apply firewall rules"
        remediation_failed=true
    }

    launchctl kickstart -k system/com.apple.ALF >/dev/null 2>&1 || \
        log_message "WARNING" "Remediation: Failed to reload firewall service"

    if [[ "$remediation_failed" == "true" ]]; then
        log_message "ERROR" "Firewall remediation completed with errors"
        return 1
    fi

    log_message "INFO" "Firewall remediation completed successfully"
    return 0
}

main() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root"
        exit 1
    fi

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
    elif ! verify_rules_compliance "$location"; then
        log_message "WARNING" "Firewall rules not compliant"
        needs_remediation=true
        compliance_status="rule_violation"
    fi

    if check_location_change "$location"; then
        log_message "INFO" "Location change detected, applying new rules"
        needs_remediation=true
    fi

    if ! check_unsigned_apps && [[ "$compliance_status" == "compliant" ]]; then
        compliance_status="unsigned_app_detected"
    fi
    
    if [[ "$needs_remediation" == "true" ]]; then
        remediate_firewall "$location"

        firewall_state=$(get_firewall_state)

        if [[ -f "${SCRIPT_DIR}/user_notification.sh" ]]; then
            source "${SCRIPT_DIR}/user_notification.sh"
            notify_user_remediation "$compliance_status"
        fi
    fi

    save_state "$location" "$firewall_state" "$compliance_status"

    if [[ -f "${SCRIPT_DIR}/mde_reporting.sh" ]]; then
        source "${SCRIPT_DIR}/mde_reporting.sh"
        send_mde_signal "$compliance_status" "$location"
    fi
    
    log_message "INFO" "Firewall management check completed"
}

if [[ "${ZSH_EVAL_CONTEXT}" == *:file ]]; then
    main "$@"
fi
