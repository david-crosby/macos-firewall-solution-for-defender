#!/bin/bash

# User Notification Script
# Displays compliance alerts to users using swiftDialog

set -euo pipefail

readonly SWIFTDIALOG_PATH="/usr/local/bin/dialog"
readonly LOG_FILE="/var/log/firewall_management.log"

SWIFTDIALOG_INSTALLED=false

# Consistent logging function
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    
    if [[ -z "$message" ]]; then
        return 1
    fi
    
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE" 2>/dev/null
}

check_swiftdialog() {
    if [[ -f "$SWIFTDIALOG_PATH" ]]; then
        SWIFTDIALOG_INSTALLED=true
        return 0
    else
        log_message "WARNING" "swiftDialog not installed at $SWIFTDIALOG_PATH"
        SWIFTDIALOG_INSTALLED=false
        return 1
    fi
}

get_current_user() {
    local current_user
    current_user=$(stat -f "%Su" /dev/console 2>/dev/null || printf '%s\n' "")
    printf '%s\n' "$current_user"
}

get_notification_content() {
    local compliance_status="${1:-}"
    
    case "$compliance_status" in
        "firewall_disabled")
            cat <<EOF
{
    "title": "Security Alert: Firewall Disabled",
    "message": "Your device firewall has been disabled. For your security, it has been automatically re-enabled.\\n\\nThe firewall protects your device from unauthorised network access.",
    "icon": "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertStopIcon.icns",
    "button1text": "OK",
    "infobuttontext": "More Information",
    "infobuttonaction": "https://support.apple.com/en-gb/guide/mac-help/mh11783/mac"
}
EOF
            ;;
        "rule_violation")
            cat <<EOF
{
    "title": "Security Alert: Firewall Rules Updated",
    "message": "Your firewall configuration did not match corporate security policy. The correct settings have been automatically applied.\\n\\nThis ensures your device remains protected whilst allowing approved applications.",
    "icon": "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertCautionIcon.icns",
    "button1text": "OK",
    "infobuttontext": "More Information",
    "infobuttonaction": "https://support.apple.com/en-gb/guide/mac-help/mh11783/mac"
}
EOF
            ;;
        "unsigned_app_detected")
            cat <<EOF
{
    "title": "Security Notice: Unsigned Application Blocked",
    "message": "An unsigned application attempted to access the network and was blocked by your firewall.\\n\\nOnly approved and digitally signed applications are permitted to prevent potential security risks.",
    "icon": "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertNoteIcon.icns",
    "button1text": "OK",
    "infobuttontext": "Report Issue",
    "infobuttonaction": "https://yourcompany.service-now.com"
}
EOF
            ;;
        "location_mismatch")
            cat <<EOF
{
    "title": "Network Location Changed",
    "message": "Your network location has changed. Firewall rules have been updated to match your current network environment.\\n\\nThis ensures appropriate security controls are in place.",
    "icon": "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/BookmarkIcon.icns",
    "button1text": "OK"
}
EOF
            ;;
        *)
            cat <<EOF
{
    "title": "Firewall Status",
    "message": "Your firewall is active and protecting your device.\\n\\nNo action required.",
    "icon": "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/ToolbarInfo.icns",
    "button1text": "OK"
}
EOF
            ;;
    esac
}

show_notification() {
    local compliance_status="${1:-}"
    
    if ! check_swiftdialog; then
        log_message "WARNING" "Cannot show notification: swiftDialog not installed"
        send_fallback_notification "$compliance_status"
        return 1
    fi
    
    local current_user
    current_user=$(get_current_user)
    
    if [[ "$current_user" == "root" ]] || [[ "$current_user" == "_mbsetupuser" ]] || [[ -z "$current_user" ]]; then
        log_message "INFO" "No user logged in, skipping notification"
        return 0
    fi
    
    local notification_content
    notification_content=$(get_notification_content "$compliance_status")
    
    local dialog_command="$SWIFTDIALOG_PATH --jsonstring '$notification_content' --moveable --ontop --position centre"
    
    su - "$current_user" -c "$dialog_command" &
    
    log_message "INFO" "Notification displayed to user: $current_user for status: $compliance_status"
    
    return 0
}

send_fallback_notification() {
    local compliance_status="${1:-}"
    local current_user
    current_user=$(get_current_user)
    
    if [[ "$current_user" == "root" ]] || [[ "$current_user" == "_mbsetupuser" ]] || [[ -z "$current_user" ]]; then
        return 0
    fi
    
    local title="Security Alert"
    local message="Your firewall settings have been updated to maintain security compliance."
    
    case "$compliance_status" in
        "firewall_disabled")
            title="Firewall Re-enabled"
            message="Your firewall was disabled and has been automatically re-enabled for your protection."
            ;;
        "rule_violation")
            title="Firewall Rules Updated"
            message="Your firewall configuration has been updated to match corporate security policy."
            ;;
        "unsigned_app_detected")
            title="Unsigned Application Blocked"
            message="An unsigned application was blocked from accessing the network."
            ;;
    esac
    
    su - "$current_user" -c "osascript -e 'display notification \"$message\" with title \"$title\"'" 2>/dev/null || true
    
    log_message "INFO" "Fallback notification sent via osascript"
}

notify_user_remediation() {
    local compliance_status="${1:-}"
    
    if [[ "$compliance_status" == "compliant" ]]; then
        return 0
    fi
    
    show_notification "$compliance_status"
    
    return 0
}

test_notification() {
    local test_status="${1:-firewall_disabled}"
    
    printf '%s\n' "Testing notification for status: $test_status"
    check_swiftdialog
    show_notification "$test_status"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "${1:-}" == "test" ]]; then
        test_notification "${2:-firewall_disabled}"
    else
        notify_user_remediation "${1:-compliant}"
    fi
fi
