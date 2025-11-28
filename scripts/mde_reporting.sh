#!/bin/bash

# Microsoft Defender for Endpoint Custom Signal Reporting
# Sends firewall compliance signals to MDE for centralised monitoring

set -euo pipefail

readonly MDE_CONFIG_FILE="/Library/Application Support/Microsoft/Defender/mde_config.json"
readonly LOG_FILE="/var/log/firewall_management.log"
readonly MDE_SIGNAL_LOG="/var/log/mde_signals.log"
readonly MDE_ALERT_LOG="/var/log/mde_alerts.log"

# Consistent logging function
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    
    if [[ -z "$message" ]]; then
        return 1
    fi
    
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE" 2>/dev/null
}

get_device_info() {
    local serial_number
    serial_number=$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $4}' || printf '%s\n' "unknown")
    
    local hostname
    hostname=$(hostname 2>/dev/null || printf '%s\n' "unknown")
    
    local os_version
    os_version=$(sw_vers -productVersion 2>/dev/null || printf '%s\n' "unknown")
    
    local current_user
    current_user=$(stat -f "%Su" /dev/console 2>/dev/null || printf '%s\n' "unknown")
    
    cat <<EOF
{
    "serial_number": "$serial_number",
    "hostname": "$hostname",
    "os_version": "$os_version",
    "current_user": "$current_user",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

get_severity_level() {
    local compliance_status="${1:-}"
    
    case "$compliance_status" in
        "firewall_disabled")
            printf '%s\n' "High"
            ;;
        "rule_violation")
            printf '%s\n' "Medium"
            ;;
        "unsigned_app_detected")
            printf '%s\n' "Low"
            ;;
        "location_mismatch"|"compliant")
            printf '%s\n' "Informational"
            ;;
        *)
            printf '%s\n' "Informational"
            ;;
    esac
}

get_signal_name() {
    local compliance_status="${1:-}"
    
    case "$compliance_status" in
        "firewall_disabled")
            printf '%s\n' "macOS.Firewall.Disabled"
            ;;
        "rule_violation")
            printf '%s\n' "macOS.Firewall.RuleViolation"
            ;;
        "unsigned_app_detected")
            printf '%s\n' "macOS.Firewall.UnsignedAppBlocked"
            ;;
        "location_mismatch")
            printf '%s\n' "macOS.Firewall.LocationMismatch"
            ;;
        "compliant")
            printf '%s\n' "macOS.Firewall.Compliant"
            ;;
        *)
            printf '%s\n' "macOS.Firewall.Unknown"
            ;;
    esac
}

create_mde_payload() {
    local compliance_status="${1:-}"
    local location="${2:-}"
    local device_info="${3:-}"
    
    local signal_name
    signal_name=$(get_signal_name "$compliance_status")
    
    local severity
    severity=$(get_severity_level "$compliance_status")
    
    cat <<EOF
{
    "SignalType": "CustomDetection",
    "SignalName": "$signal_name",
    "Severity": "$severity",
    "Category": "FirewallCompliance",
    "DetectionTime": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "DeviceInfo": $device_info,
    "AdditionalContext": {
        "network_location": "$location",
        "compliance_status": "$compliance_status",
        "management_system": "Jamf Pro",
        "detection_method": "automated_monitoring"
    }
}
EOF
}

check_mde_installed() {
    if [[ ! -f "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon" ]]; then
        log_message "WARNING" "Microsoft Defender not installed"
        return 1
    fi
    
    if ! pgrep -f "wdavdaemon" >/dev/null 2>&1; then
        log_message "WARNING" "Microsoft Defender not running"
        return 1
    fi
    
    return 0
}

send_mde_signal() {
    local compliance_status="${1:-}"
    local location="${2:-}"
    
    if [[ -z "$compliance_status" ]] || [[ -z "$location" ]]; then
        log_message "ERROR" "Missing parameters for send_mde_signal"
        return 1
    fi
    
    if ! check_mde_installed; then
        log_message "ERROR" "Cannot send MDE signal: Defender not available"
        return 1
    fi
    
    local device_info
    device_info=$(get_device_info)
    
    local payload
    payload=$(create_mde_payload "$compliance_status" "$location" "$device_info")
    
    local signal_file="/tmp/mde_signal_$(date +%s).json"
    printf '%s\n' "$payload" > "$signal_file"
    
    log_message "INFO" "MDE Signal created: $(get_signal_name "$compliance_status") with severity $(get_severity_level "$compliance_status")"
    
    if /usr/local/bin/mdatp diagnostic create --path /tmp/mde_diagnostics >/dev/null 2>&1; then
        log_message "INFO" "MDE signal sent successfully"
    else
        log_message "WARNING" "Failed to trigger MDE diagnostic collection"
    fi
    
    printf '%s\n' "$payload" >> "$MDE_SIGNAL_LOG"
    
    rm -f "$signal_file"
    
    return 0
}

send_mde_alert() {
    local title="${1:-}"
    local description="${2:-}"
    local severity="${3:-}"
    
    if ! check_mde_installed; then
        return 1
    fi
    
    log_message "INFO" "Sending MDE alert: $title (Severity: $severity)"
    
    local device_info
    device_info=$(get_device_info)
    
    local alert_payload
    alert_payload=$(cat <<EOF
{
    "AlertTitle": "$title",
    "AlertDescription": "$description",
    "Severity": "$severity",
    "Category": "FirewallCompliance",
    "Timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "DeviceInfo": $device_info
}
EOF
)
    
    printf '%s\n' "$alert_payload" >> "$MDE_ALERT_LOG"
    
    return 0
}

test_mde_integration() {
    log_message "INFO" "Testing MDE integration"
    
    if ! check_mde_installed; then
        printf '%s\n' "ERROR: Microsoft Defender not installed or not running" >&2
        return 1
    fi
    
    local test_payload
    test_payload=$(cat <<EOF
{
    "SignalType": "Test",
    "SignalName": "macOS.Firewall.Test",
    "Severity": "Informational",
    "DetectionTime": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "Message": "MDE integration test signal"
}
EOF
)
    
    printf '%s\n' "$test_payload" >> "$MDE_SIGNAL_LOG"
    printf '%s\n' "Test signal logged to $MDE_SIGNAL_LOG"
    printf '%s\n' "Check Microsoft Defender Security Center for custom detections"
    
    return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "test" ]]; then
        test_mde_integration
    else
        send_mde_signal "${1:-compliant}" "${2:-unknown}"
    fi
fi
