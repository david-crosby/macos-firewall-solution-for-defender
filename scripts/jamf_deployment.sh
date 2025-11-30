#!/bin/zsh

# Jamf Pro Deployment Script
# Deploys firewall management solution via Jamf Pro policy

setopt ERR_EXIT
setopt NO_UNSET
setopt PIPE_FAIL

typeset -r SCRIPT_DIR="/usr/local/bin"
typeset -r LAUNCHDAEMON_DIR="/Library/LaunchDaemons"
typeset -r LAUNCHDAEMON_LABEL="com.company.firewall.management"
typeset -r LOG_DIR="/var/log"
typeset -r STATE_DIR="/var/tmp"

log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    
    print -r "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message"
}

check_prerequisites() {
    log_message "INFO" "Checking prerequisites"
    
    local missing_prereqs=false
    
    if [[ ! -f "/usr/local/bin/dialog" ]]; then
        log_message "ERROR" "swiftDialog not installed"
        missing_prereqs=true
    else
        log_message "INFO" "swiftDialog found"
    fi
    
    if [[ ! -f "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon" ]]; then
        log_message "WARNING" "Microsoft Defender not installed"
    else
        log_message "INFO" "Microsoft Defender found"
    fi
    
    if [[ ! -f "/usr/local/bin/jamf" ]]; then
        log_message "ERROR" "Jamf Pro agent not installed"
        missing_prereqs=true
    else
        log_message "INFO" "Jamf Pro agent found"
    fi
    
    if [[ "$missing_prereqs" == "true" ]]; then
        log_message "ERROR" "Missing required prerequisites"
        return 1
    fi
    
    return 0
}

create_directories() {
    log_message "INFO" "Creating required directories"
    
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    
    chmod 755 "$LOG_DIR" 2>/dev/null || true
    chmod 755 "$STATE_DIR" 2>/dev/null || true
}

install_scripts() {
    log_message "INFO" "Installing firewall management scripts"
    
    local source_dir="/tmp/firewall_scripts/scripts"
    
    if [[ ! -d "$source_dir" ]]; then
        log_message "ERROR" "Source scripts directory not found: $source_dir"
        return 1
    fi
    
    local scripts=(
        "network_detection.sh"
        "firewall_rules.sh"
        "firewall_management.sh"
        "mde_reporting.sh"
        "user_notification.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "${source_dir}/${script}" ]]; then
            cp "${source_dir}/${script}" "${SCRIPT_DIR}/${script}"
            chmod 755 "${SCRIPT_DIR}/${script}"
            chown root:wheel "${SCRIPT_DIR}/${script}"
            log_message "INFO" "Installed: ${script}"
        else
            log_message "ERROR" "Script not found: ${script}"
            return 1
        fi
    done
    
    return 0
}

install_launchdaemon() {
    log_message "INFO" "Installing LaunchDaemon"
    
    local plist_source="/tmp/firewall_scripts/launchDaemons/${LAUNCHDAEMON_LABEL}.plist"
    local plist_dest="${LAUNCHDAEMON_DIR}/${LAUNCHDAEMON_LABEL}.plist"
    
    if [[ ! -f "$plist_source" ]]; then
        log_message "ERROR" "LaunchDaemon plist not found: $plist_source"
        return 1
    fi
    
    cp "$plist_source" "$plist_dest"
    chmod 644 "$plist_dest"
    chown root:wheel "$plist_dest"
    
    log_message "INFO" "LaunchDaemon installed: $plist_dest"
    return 0
}

load_launchdaemon() {
    log_message "INFO" "Loading LaunchDaemon"
    
    local plist_path="${LAUNCHDAEMON_DIR}/${LAUNCHDAEMON_LABEL}.plist"
    
    if launchctl list | grep -q "$LAUNCHDAEMON_LABEL"; then
        log_message "INFO" "LaunchDaemon already loaded, unloading first"
        launchctl unload "$plist_path" 2>/dev/null || true
        sleep 2
    fi
    
    if ! launchctl load "$plist_path"; then
        log_message "ERROR" "Failed to load LaunchDaemon"
        return 1
    fi
    
    sleep 2
    
    if launchctl list | grep -q "$LAUNCHDAEMON_LABEL"; then
        log_message "INFO" "LaunchDaemon loaded successfully"
        return 0
    else
        log_message "ERROR" "LaunchDaemon not running after load"
        return 1
    fi
}

configure_firewall_baseline() {
    log_message "INFO" "Configuring firewall baseline settings"
    
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on >/dev/null 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on >/dev/null 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingopt detail >/dev/null 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on >/dev/null 2>&1
    /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on >/dev/null 2>&1
    
    log_message "INFO" "Firewall baseline configured"
}

run_initial_check() {
    log_message "INFO" "Running initial firewall configuration"
    
    if [[ -f "${SCRIPT_DIR}/firewall_management.sh" ]]; then
        "${SCRIPT_DIR}/firewall_management.sh"
        log_message "INFO" "Initial configuration completed"
    else
        log_message "ERROR" "firewall_management.sh not found"
        return 1
    fi
}

verify_installation() {
    log_message "INFO" "Verifying installation"
    
    local verification_failed=false
    
    if [[ ! -f "${SCRIPT_DIR}/firewall_management.sh" ]]; then
        log_message "ERROR" "firewall_management.sh not installed"
        verification_failed=true
    fi
    
    if [[ ! -f "${LAUNCHDAEMON_DIR}/${LAUNCHDAEMON_LABEL}.plist" ]]; then
        log_message "ERROR" "LaunchDaemon plist not installed"
        verification_failed=true
    fi
    
    if ! launchctl list | grep -q "$LAUNCHDAEMON_LABEL"; then
        log_message "ERROR" "LaunchDaemon not loaded"
        verification_failed=true
    fi
    
    if [[ "$verification_failed" == "true" ]]; then
        log_message "ERROR" "Installation verification failed"
        return 1
    fi
    
    log_message "INFO" "Installation verified successfully"
    return 0
}

main() {
    log_message "INFO" "Starting firewall management deployment"
    
    if ! check_prerequisites; then
        log_message "ERROR" "Prerequisites check failed"
        exit 1
    fi
    
    create_directories
    
    if ! install_scripts; then
        log_message "ERROR" "Script installation failed"
        exit 1
    fi
    
    if ! install_launchdaemon; then
        log_message "ERROR" "LaunchDaemon installation failed"
        exit 1
    fi
    
    configure_firewall_baseline
    
    if ! load_launchdaemon; then
        log_message "ERROR" "LaunchDaemon loading failed"
        exit 1
    fi
    
    run_initial_check
    
    if ! verify_installation; then
        log_message "ERROR" "Installation verification failed"
        exit 1
    fi
    
    log_message "INFO" "Firewall management deployment completed successfully"
    exit 0
}

main "$@"
