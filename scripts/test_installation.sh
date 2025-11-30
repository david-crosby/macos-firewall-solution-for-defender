#!/bin/zsh

# Installation Testing and Validation Script
# Comprehensive testing for firewall management solution

setopt NO_UNSET

typeset -r SCRIPT_DIR="/usr/local/bin"
typeset -r LAUNCHDAEMON_LABEL="com.company.firewall.management"
typeset -r LOG_DIR="/var/log"
typeset -r STATE_DIR="/var/tmp"

typeset -i TESTS_PASSED=0
typeset -i TESTS_FAILED=0
typeset -i TESTS_WARNING=0

print_header() {
    local title="$1"
    print -r "\n========================================="
    print -r "$title"
    print -r "=========================================\n"
}

print_test() {
    local test_name="$1"
    local status="$2"
    local message="${3:-}"
    
    case "$status" in
        "PASS")
            print -r "[✓] $test_name: PASS"
            ((TESTS_PASSED++))
            ;;
        "FAIL")
            print -r "[✗] $test_name: FAIL"
            if [[ -n "$message" ]]; then
                print -r "    └─ $message"
            fi
            ((TESTS_FAILED++))
            ;;
        "WARN")
            print -r "[!] $test_name: WARNING"
            if [[ -n "$message" ]]; then
                print -r "    └─ $message"
            fi
            ((TESTS_WARNING++))
            ;;
    esac
}

test_prerequisites() {
    print_header "Testing Prerequisites"
    
    if [[ -f "/usr/local/bin/dialog" ]]; then
        print_test "swiftDialog Installation" "PASS"
    else
        print_test "swiftDialog Installation" "FAIL" "swiftDialog not found at /usr/local/bin/dialog"
    fi
    
    if [[ -f "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon" ]]; then
        print_test "Microsoft Defender Installation" "PASS"
        
        if pgrep -f "wdavdaemon" >/dev/null 2>&1; then
            print_test "Microsoft Defender Running" "PASS"
        else
            print_test "Microsoft Defender Running" "WARN" "Defender installed but not running"
        fi
    else
        print_test "Microsoft Defender Installation" "WARN" "MDE not installed, signals will not be sent"
    fi
    
    if [[ -f "/usr/local/bin/jamf" ]]; then
        print_test "Jamf Pro Agent" "PASS"
    else
        print_test "Jamf Pro Agent" "FAIL" "Jamf binary not found"
    fi
}

test_script_installation() {
    print_header "Testing Script Installation"
    
    local scripts=(
        "network_detection.sh"
        "firewall_rules.sh"
        "firewall_management.sh"
        "mde_reporting.sh"
        "user_notification.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
            if [[ -x "${SCRIPT_DIR}/${script}" ]]; then
                print_test "$script" "PASS"
            else
                print_test "$script" "WARN" "Not executable"
            fi
        else
            print_test "$script" "FAIL" "Script not found"
        fi
    done
}

test_launchdaemon() {
    print_header "Testing LaunchDaemon"
    
    local plist_path="/Library/LaunchDaemons/${LAUNCHDAEMON_LABEL}.plist"
    
    if [[ -f "$plist_path" ]]; then
        print_test "LaunchDaemon Plist Exists" "PASS"
        
        local perms
        perms=$(stat -f "%p" "$plist_path")
        if [[ "$perms" == "100644" ]]; then
            print_test "LaunchDaemon Permissions" "PASS"
        else
            print_test "LaunchDaemon Permissions" "WARN" "Permissions are $perms, should be 644"
        fi
    else
        print_test "LaunchDaemon Plist Exists" "FAIL" "Plist not found"
        return
    fi
    
    if launchctl list | grep -q "$LAUNCHDAEMON_LABEL"; then
        print_test "LaunchDaemon Loaded" "PASS"
    else
        print_test "LaunchDaemon Loaded" "FAIL" "LaunchDaemon not loaded"
    fi
}

test_log_files() {
    print_header "Testing Log Files"
    
    local logs=(
        "firewall_management.log"
        "mde_signals.log"
    )
    
    for log in "${logs[@]}"; do
        if [[ -f "${LOG_DIR}/${log}" ]]; then
            print_test "${log}" "PASS"
        else
            print_test "${log}" "WARN" "Log file not created yet"
        fi
    done
}

test_network_detection() {
    print_header "Testing Network Detection"
    
    if [[ -x "${SCRIPT_DIR}/network_detection.sh" ]]; then
        local location
        location=$("${SCRIPT_DIR}/network_detection.sh" 2>/dev/null)
        
        if [[ "$location" == "corporate" ]] || [[ "$location" == "external" ]]; then
            print_test "Network Detection Function" "PASS" "Detected: $location"
        else
            print_test "Network Detection Function" "FAIL" "Invalid location: $location"
        fi
    else
        print_test "Network Detection Function" "FAIL" "Script not executable"
    fi
}

test_firewall_state() {
    print_header "Testing Firewall State"
    
    local state
    state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | awk '{print $NF}' | tr -d '.')
    
    if [[ "$state" == "enabled" ]]; then
        print_test "Firewall Enabled" "PASS"
    else
        print_test "Firewall Enabled" "FAIL" "Firewall is $state"
    fi
    
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | awk '{print $NF}' | tr -d '.')
    
    if [[ "$stealth" == "enabled" ]]; then
        print_test "Stealth Mode Enabled" "PASS"
    else
        print_test "Stealth Mode Enabled" "WARN" "Stealth mode is $stealth"
    fi
}

test_firewall_rules() {
    print_header "Testing Firewall Rules"
    
    local apps_count
    apps_count=$(/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | grep -c "ALF" || print -r "0")
    
    if (( apps_count > 0 )); then
        print_test "Firewall Rules Applied" "PASS" "$apps_count applications configured"
    else
        print_test "Firewall Rules Applied" "WARN" "No applications found in firewall rules"
    fi
}

test_mde_integration() {
    print_header "Testing MDE Integration"
    
    if [[ -f "${SCRIPT_DIR}/mde_reporting.sh" ]]; then
        if [[ -f "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon" ]]; then
            print_test "MDE Reporting Script" "PASS"
            
            if [[ -f "${LOG_DIR}/mde_signals.log" ]]; then
                local signal_count
                signal_count=$(wc -l < "${LOG_DIR}/mde_signals.log" 2>/dev/null || print -r "0")
                print_test "MDE Signals Logged" "PASS" "$signal_count signals recorded"
            else
                print_test "MDE Signals Logged" "WARN" "No signals logged yet"
            fi
        else
            print_test "MDE Reporting Script" "WARN" "MDE not installed, cannot test"
        fi
    else
        print_test "MDE Reporting Script" "FAIL" "Script not found"
    fi
}

test_user_notifications() {
    print_header "Testing User Notifications"
    
    if [[ -x "${SCRIPT_DIR}/user_notification.sh" ]]; then
        if [[ -f "/usr/local/bin/dialog" ]]; then
            print_test "User Notification Script" "PASS"
        else
            print_test "User Notification Script" "WARN" "swiftDialog not installed"
        fi
    else
        print_test "User Notification Script" "FAIL" "Script not executable"
    fi
}

test_state_files() {
    print_header "Testing State Files"
    
    if [[ -f "${STATE_DIR}/firewall_state.json" ]]; then
        print_test "State File Exists" "PASS"
        
        if grep -q "timestamp" "${STATE_DIR}/firewall_state.json" 2>/dev/null; then
            print_test "State File Valid" "PASS"
        else
            print_test "State File Valid" "FAIL" "State file appears corrupt"
        fi
    else
        print_test "State File Exists" "WARN" "State file not created yet"
    fi
    
    if [[ -f "${STATE_DIR}/last_network_location" ]]; then
        local location
        location=$(cat "${STATE_DIR}/last_network_location" 2>/dev/null)
        print_test "Network Location Cache" "PASS" "Last location: $location"
    else
        print_test "Network Location Cache" "WARN" "Location cache not created yet"
    fi
}

test_functional() {
    print_header "Functional Testing"
    
    if [[ -x "${SCRIPT_DIR}/firewall_management.sh" ]]; then
        print -r "Running firewall management check..."
        
        if "${SCRIPT_DIR}/firewall_management.sh" >/dev/null 2>&1; then
            print_test "Firewall Management Execution" "PASS"
        else
            print_test "Firewall Management Execution" "FAIL" "Script execution failed"
        fi
    else
        print_test "Firewall Management Execution" "FAIL" "Script not executable"
    fi
}

print_summary() {
    print_header "Test Summary"
    
    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))
    
    print -r "Total Tests:    $total"
    print -r "Passed:         $TESTS_PASSED"
    print -r "Failed:         $TESTS_FAILED"
    print -r "Warnings:       $TESTS_WARNING"
    print -r ""
    
    if (( TESTS_FAILED == 0 )); then
        print -r "Status: ✓ All critical tests passed"
        if (( TESTS_WARNING > 0 )); then
            print -r "Note: Some warnings present, review above for details"
        fi
        return 0
    else
        print -r "Status: ✗ Some tests failed, review above for details"
        return 1
    fi
}

main() {
    print -r "Firewall Management Solution - Installation Test"
    print -r "=================================================="
    print -r "Started: $(date '+%Y-%m-%d %H:%M:%S')"
    
    test_prerequisites
    test_script_installation
    test_launchdaemon
    test_log_files
    test_network_detection
    test_firewall_state
    test_firewall_rules
    test_mde_integration
    test_user_notifications
    test_state_files
    test_functional
    
    print_summary
    
    local exit_code=$?
    
    print -r "\nCompleted: $(date '+%Y-%m-%d %H:%M:%S')"
    
    exit $exit_code
}

main "$@"
