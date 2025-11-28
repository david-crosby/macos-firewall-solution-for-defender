# Configuration Examples

## Common Enterprise Scenarios

### Example 1: Financial Services Organisation

**Network Detection**:
```bash
# Multiple office locations
CORPORATE_SSIDS=(
    "HQ-Secure" 
    "Branch-Office" 
    "Trading-Floor"
    "Guest-Network"
)

# RFC1918 private ranges
CORPORATE_SUBNETS=(
    "10.50.0.0/16"    # HQ
    "10.51.0.0/16"    # Branch offices
    "10.52.0.0/16"    # Trading floor
)

# Internal domain
CORPORATE_DNS_SUFFIX="corp.financialorg.com"
```

**Additional Applications**:
```bash
# Bloomberg Terminal
"/Applications/Bloomberg/BLOOMBERG PROFESSIONAL.app/Contents/MacOS/BLOOMBERG PROFESSIONAL"

# Trading applications
"/Applications/TradingPlatform.app/Contents/MacOS/TradingPlatform"

# Internal apps
"/Applications/RiskManagement.app/Contents/MacOS/RiskManagement"
```

### Example 2: Healthcare Provider

**Network Detection**:
```bash
# Medical facility networks
CORPORATE_SSIDS=(
    "Hospital-Staff"
    "Medical-Device"
    "Admin-Network"
)

# Dedicated medical subnets
CORPORATE_SUBNETS=(
    "172.20.0.0/16"   # Clinical systems
    "172.21.0.0/16"   # Administrative
    "172.22.0.0/16"   # Medical devices
)

CORPORATE_DNS_SUFFIX="internal.hospital.org"
```

**Additional Applications**:
```bash
# Epic Systems
"/Applications/Epic/Hyperspace.app/Contents/MacOS/Hyperspace"

# Medical imaging
"/Applications/PACS Viewer.app/Contents/MacOS/PACS Viewer"

# Secure messaging
"/Applications/TigerConnect.app/Contents/MacOS/TigerConnect"

# Telemedicine
"/Applications/Zoom Healthcare.app/Contents/MacOS/Zoom Healthcare"
```

### Example 3: Technology Company

**Network Detection**:
```bash
# Tech company WiFi
CORPORATE_SSIDS=(
    "TechCo-Employee"
    "TechCo-IoT"
    "TechCo-Guest"
)

# Modern flat network
CORPORATE_SUBNETS=(
    "10.0.0.0/8"
)

CORPORATE_DNS_SUFFIX="techco.internal"
```

**Additional Applications**:
```bash
# Development tools
"/Applications/Docker.app/Contents/MacOS/Docker"
"/Applications/Visual Studio Code.app/Contents/MacOS/Electron"

# Collaboration
"/Applications/Slack.app/Contents/MacOS/Slack"
"/Applications/Figma.app/Contents/MacOS/Figma"

# VPN clients
"/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/MacOS/Cisco AnyConnect Secure Mobility Client"
```

### Example 4: Manufacturing Company

**Network Detection**:
```bash
# Factory and office networks
CORPORATE_SSIDS=(
    "Factory-Floor"
    "Office-Network"
    "Warehouse"
)

# Segmented by function
CORPORATE_SUBNETS=(
    "192.168.10.0/24"  # Office
    "192.168.20.0/24"  # Factory
    "192.168.30.0/24"  # Warehouse
)

CORPORATE_DNS_SUFFIX="manufacturing.local"
```

**Additional Applications**:
```bash
# ERP systems
"/Applications/SAP/SAP Business One.app/Contents/MacOS/SAP Business One"

# CAD software
"/Applications/AutoCAD.app/Contents/MacOS/AutoCAD"

# Manufacturing execution
"/Applications/MES Client.app/Contents/MacOS/MES Client"
```

### Example 5: Professional Services Firm

**Network Detection**:
```bash
# Multiple client sites
CORPORATE_SSIDS=(
    "Firm-Office"
    "Client-SiteA"
    "Client-SiteB"
)

# Various client networks
CORPORATE_SUBNETS=(
    "10.100.0.0/16"    # Home office
    "172.16.0.0/12"    # Client networks (broad range)
)

CORPORATE_DNS_SUFFIX="firm.local"
```

**Additional Applications**:
```bash
# Video conferencing
"/Applications/Webex.app/Contents/MacOS/Webex"
"/Applications/GoToMeeting.app/Contents/MacOS/GoToMeeting"

# Document management
"/Applications/iManage Work.app/Contents/MacOS/iManage Work"

# Time tracking
"/Applications/TimeTracker.app/Contents/MacOS/TimeTracker"

# Client portals
"/Applications/ClientPortal.app/Contents/MacOS/ClientPortal"
```

## Location-Specific Rules

### Stricter External Network Rules

If you want more restrictive rules when off corporate network:

```bash
get_external_allowed_apps() {
    local apps=()
    # Only essential services when external
    apps+=("${APPLE_SERVICES[@]}")
    apps+=("${MICROSOFT_APPS[@]}")
    apps+=("${DEFENDER_APPS[@]}")
    apps+=("${JAMF_APPS[@]}")
    # Note: Limited browser access, no ServiceNow
    apps+=("/Applications/Safari.app/Contents/MacOS/Safari")
    
    printf '%s\n' "${apps[@]}"
}
```

### Additional Corporate Network Permissions

If you want to allow more on corporate network:

```bash
get_corporate_allowed_apps() {
    local apps=()
    apps+=("${APPLE_SERVICES[@]}")
    apps+=("${MICROSOFT_APPS[@]}")
    apps+=("${SERVICENOW_APPS[@]}")
    apps+=("${WEB_BROWSERS[@]}")
    apps+=("${DEFENDER_APPS[@]}")
    apps+=("${JAMF_APPS[@]}")
    
    # Additional corporate-only apps
    apps+=(
        "/Applications/Internal Tool 1.app/Contents/MacOS/Internal Tool 1"
        "/Applications/Internal Tool 2.app/Contents/MacOS/Internal Tool 2"
    )
    
    printf '%s\n' "${apps[@]}"
}
```

## VPN-Specific Configuration

### Cisco AnyConnect

```bash
check_vpn_status() {
    # Check for Cisco AnyConnect
    if pgrep -f "Cisco AnyConnect" > /dev/null; then
        log_message "INFO" "Cisco AnyConnect VPN detected"
        return 0
    fi
    
    # Standard VPN check
    if scutil --nc list | grep -q "Connected"; then
        log_message "INFO" "VPN connection detected"
        return 0
    fi
    
    return 1
}
```

### GlobalProtect

```bash
check_vpn_status() {
    # Check for GlobalProtect
    if pgrep -f "GlobalProtect" > /dev/null; then
        log_message "INFO" "GlobalProtect VPN detected"
        return 0
    fi
    
    # Standard check
    if scutil --nc list | grep -q "Connected"; then
        log_message "INFO" "VPN connection detected"
        return 0
    fi
    
    return 1
}
```

### WireGuard

```bash
check_vpn_status() {
    # Check for WireGuard interface
    if ifconfig | grep -q "utun.*wireguard"; then
        log_message "INFO" "WireGuard VPN detected"
        return 0
    fi
    
    # Standard check
    if scutil --nc list | grep -q "Connected"; then
        log_message "INFO" "VPN connection detected"
        return 0
    fi
    
    return 1
}
```

## MDE Tenant Configuration

### Custom Signal Naming for Multiple Tenants

If managing multiple tenants:

```bash
# Add tenant identifier to signal names
TENANT_ID="EMEA"

get_signal_name() {
    local compliance_status="$1"
    
    case "$compliance_status" in
        "firewall_disabled")
            echo "macOS.${TENANT_ID}.Firewall.Disabled"
            ;;
        "rule_violation")
            echo "macOS.${TENANT_ID}.Firewall.RuleViolation"
            ;;
        # ... etc
    esac
}
```

## Jamf Pro Smart Group Criteria

### Non-Compliant Devices

```
Extension Attribute: Firewall Compliance Status
Operator: does not contain
Value: compliant
```

### External Network Devices

```
Extension Attribute: Firewall Compliance Status
Operator: contains
Value: Location: external
```

### Firewall Disabled Devices

```
Extension Attribute: Firewall Compliance Status
Operator: contains
Value: Firewall: disabled
```

### Devices Not Checking In

```
Extension Attribute: Firewall Compliance Status
Operator: contains
Value: Never
```

## Notification Customisation

### Custom Company Branding

Edit `user_notification.sh`:

```bash
get_notification_content() {
    local compliance_status="$1"
    
    cat <<EOF
{
    "title": "Security Alert from IT Security",
    "message": "Your message here",
    "icon": "/Library/Application Support/YourCompany/logo.icns",
    "button1text": "Understood",
    "infobuttontext": "Contact IT Support",
    "infobuttonaction": "https://yourcompany.service-now.com/submit-ticket"
}
EOF
}
```

### Different Notification Levels

```bash
# Critical alerts
if [[ "$compliance_status" == "firewall_disabled" ]]; then
    dialog_command="$SWIFTDIALOG_PATH --jsonstring '$notification_content' --moveable --ontop --position centre --blurscreen --timer 300"
fi

# Standard alerts
if [[ "$compliance_status" == "rule_violation" ]]; then
    dialog_command="$SWIFTDIALOG_PATH --jsonstring '$notification_content' --moveable --position topright --timer 60"
fi
```

## Advanced Subnet Detection

### Multiple Subnet Ranges per Location

```bash
# London office
LONDON_SUBNETS=("10.10.0.0/16")

# New York office
NEWYORK_SUBNETS=("10.20.0.0/16")

# All corporate subnets
CORPORATE_SUBNETS=("${LONDON_SUBNETS[@]}" "${NEWYORK_SUBNETS[@]}")

# Detect specific location
detect_office_location() {
    local ip_addresses
    ip_addresses=$(ifconfig | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}')
    
    for ip in $ip_addresses; do
        for subnet in "${LONDON_SUBNETS[@]}"; do
            if check_ip_in_subnet "$ip" "$subnet"; then
                echo "london"
                return 0
            fi
        done
        
        for subnet in "${NEWYORK_SUBNETS[@]}"; do
            if check_ip_in_subnet "$ip" "$subnet"; then
                echo "newyork"
                return 0
            fi
        done
    done
    
    echo "external"
}
```

## Testing Configurations

### Test Network Detection

```bash
# Test from command line
sudo /usr/local/bin/network_detection.sh

# Should output: "corporate" or "external"
```

### Test Specific Detection Methods

```bash
# Test VPN detection
scutil --nc list

# Test SSID
/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I

# Test subnet
ifconfig | grep "inet "

# Test DNS
scutil --dns | grep domain
```

### Test Application Rules

```bash
# Get list of allowed apps for current location
source /usr/local/bin/network_detection.sh
source /usr/local/bin/firewall_rules.sh

location=$(detect_network_location)
get_allowed_apps_for_location "$location"
```

### Test MDE Signals

```bash
# Send test signal
sudo /usr/local/bin/mde_reporting.sh test

# Check log
tail -5 /var/log/mde_signals.log
```

## Troubleshooting Configurations

### Debug Network Detection

Add verbose logging:

```bash
# At start of network_detection.sh
set -x  # Enable debug mode
```

### Application Path Verification

```bash
# Find application path
osascript -e 'tell application "System Events" to get POSIX path of (file of process "Application Name" as alias)'

# Or using mdfind
mdfind "kMDItemKind == 'Application' && kMDItemFSName == 'Application Name.app'"
```

### Testing Rule Application

```bash
# Clear all rules
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove-all

# Run management script
sudo /usr/local/bin/firewall_management.sh

# Verify rules applied
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

---

Remember to test any configuration changes in a non-production environment first.
