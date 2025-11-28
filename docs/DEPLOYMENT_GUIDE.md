# macOS Firewall Management Solution

## Overview

This solution provides enterprise-grade firewall management for macOS devices managed through Jamf Pro, with integrated reporting to Microsoft Defender for Endpoint.

### Key Features

- Automatic firewall enablement and rule management
- Network location-aware firewall policies (corporate vs external)
- Real-time compliance monitoring and self-remediation
- Custom signal reporting to Microsoft Defender for Endpoint
- User notifications via swiftDialog
- Jamf Pro Extension Attribute for inventory reporting
- Comprehensive logging and audit trail

## Architecture

### Components

1. **Network Detection** - Identifies device location (corporate/external)
2. **Firewall Management** - Applies and enforces firewall rules
3. **MDE Reporting** - Sends compliance signals to Defender
4. **User Notifications** - Alerts users to security actions
5. **LaunchDaemon** - Continuous monitoring (every 5 minutes)
6. **Jamf Integration** - Extension Attributes for reporting

### Detection Logic

The solution determines network location using the following priority:

1. VPN connection status (any active VPN = corporate)
2. Corporate SSID match
3. Corporate subnet match
4. Corporate DNS suffix match
5. Default to external if no matches

### Firewall Rules

#### Always Allowed
- Apple system services (Software Update, APNS, iCloud, etc.)
- Microsoft 365 applications (Teams, Outlook, Word, Excel, PowerPoint, OneDrive)
- Microsoft Defender for Endpoint
- Jamf Pro agent
- ServiceNow
- Web browsers (Safari, Chrome, Firefox, Edge)

#### Security Controls
- Stealth mode enabled
- Detailed logging enabled
- Signed applications automatically allowed
- Unsigned applications blocked and reported
- Location-specific rulesets applied automatically

### MDE Signal Types

| Signal Name | Severity | Trigger |
|------------|----------|---------|
| `macOS.Firewall.Disabled` | High | Firewall found disabled |
| `macOS.Firewall.RuleViolation` | Medium | Rules don't match policy |
| `macOS.Firewall.UnsignedAppBlocked` | Low | Unsigned app blocked |
| `macOS.Firewall.LocationMismatch` | Informational | Network location changed |
| `macOS.Firewall.Compliant` | Informational | All checks passed |

## Prerequisites

### Required Software

1. **swiftDialog** (v2.0 or later)
   - Used for user notifications
   - Must be deployed before this solution
   - Download: https://github.com/swiftDialog/swiftDialog

2. **Microsoft Defender for Endpoint**
   - Required for MDE signal reporting
   - Should be installed and onboarded

3. **Jamf Pro Agent**
   - Standard Jamf binary installation
   - Required for deployment and Extension Attributes

4. **Python 3**
   - Built-in on macOS 12.3+
   - Required for subnet calculations

### Permissions Required

- Full Disk Access for scripts (granted via PPPC profile)
- LaunchDaemon execution permissions
- Firewall configuration permissions

## Installation

### Step 1: Prepare Configuration

1. Edit `scripts/network_detection.sh` and update:
   - `CORPORATE_SSIDS` - Your WiFi network names
   - `CORPORATE_SUBNETS` - Your IP ranges
   - `CORPORATE_DNS_SUFFIX` - Your internal DNS domain

2. Edit `scripts/firewall_rules.sh` and update:
   - Application paths if different
   - Add any additional corporate applications

### Step 2: Create Jamf Pro Package

1. Create a package containing all scripts:

```bash
pkgbuild --root ./firewall-solution \
         --identifier com.company.firewall.management \
         --version 1.0.0 \
         --scripts ./scripts \
         firewall-management-1.0.0.pkg
```

2. Upload package to Jamf Pro

### Step 3: Deploy Configuration Profile

1. In Jamf Pro, navigate to Configuration Profiles
2. Create new macOS Configuration Profile
3. Add Security & Privacy payload:
   - Enable Firewall: Checked
   - Enable Stealth Mode: Checked
4. Scope to appropriate computers
5. Deploy profile

### Step 4: Create Privacy Preferences Policy Control (PPPC) Profile

Create a PPPC profile to grant Full Disk Access:

- Identifier: `/usr/local/bin/firewall_management.sh`
- Identifier Type: Path
- Code Requirement: identifier "com.company.firewall.management"
- Access: Allow

### Step 5: Create Jamf Pro Policy

1. Create new policy in Jamf Pro
2. Add package: `firewall-management-1.0.0.pkg`
3. Add script: `jamf_deployment.sh` (set to run after package installation)
4. Set frequency: Once per computer
5. Scope to test computers initially
6. Enable policy

### Step 6: Add Extension Attribute

1. In Jamf Pro, navigate to Extension Attributes
2. Create new Extension Attribute
3. Name: "Firewall Compliance Status"
4. Data Type: String
5. Input Type: Script
6. Paste contents of `jamf_ea_firewall_compliance.sh`
7. Save and enable inventory collection

### Step 7: Testing

1. Deploy to test device
2. Verify installation:

```bash
sudo launchctl list | grep com.company.firewall.management
sudo ls -la /usr/local/bin/*firewall*
sudo cat /var/log/firewall_management.log
```

3. Test network location changes
4. Verify MDE signals in Microsoft 365 Defender portal
5. Check Jamf Pro Extension Attribute data

## Configuration

### Customising Network Detection

Edit `/usr/local/bin/network_detection.sh`:

```bash
CORPORATE_SSIDS=("CorpWiFi" "CorpGuest" "CorpSecure")
CORPORATE_SUBNETS=("10.0.0.0/8" "172.16.0.0/12")
CORPORATE_DNS_SUFFIX="corp.internal"
```

### Adding Applications

Edit `/usr/local/bin/firewall_rules.sh`:

```bash
CUSTOM_APPS=(
    "/Applications/YourApp.app/Contents/MacOS/YourApp"
)
```

Add to appropriate function:
- `get_corporate_allowed_apps` - Corporate network only
- `get_external_allowed_apps` - All networks

### Adjusting Check Frequency

Edit `/Library/LaunchDaemons/com.company.firewall.management.plist`:

```xml
<key>StartInterval</key>
<integer>300</integer>  <!-- Change to desired seconds -->
```

Reload daemon:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.company.firewall.management.plist
sudo launchctl load /Library/LaunchDaemons/com.company.firewall.management.plist
```

## Monitoring

### Log Files

- **Main Log**: `/var/log/firewall_management.log`
- **MDE Signals**: `/var/log/mde_signals.log`
- **MDE Alerts**: `/var/log/mde_alerts.log`
- **LaunchDaemon Output**: `/var/log/firewall_management_stdout.log`
- **LaunchDaemon Errors**: `/var/log/firewall_management_stderr.log`

### Checking Status

```bash
# Current firewall state
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# View current rules
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps

# Check LaunchDaemon status
sudo launchctl list | grep com.company.firewall.management

# View recent logs
tail -50 /var/log/firewall_management.log

# Check compliance state
cat /var/tmp/firewall_state.json
```

### Microsoft Defender Portal

1. Navigate to Microsoft 365 Defender portal
2. Go to Advanced Hunting
3. Query custom detections:

```kusto
DeviceEvents
| where ActionType == "CustomDetection"
| where AdditionalFields contains "macOS.Firewall"
| project Timestamp, DeviceName, ActionType, AdditionalFields
| order by Timestamp desc
```

### Jamf Pro Reporting

1. Navigate to Computers > Search Inventory
2. Add criteria: Extension Attribute "Firewall Compliance Status"
3. Create Smart Group for non-compliant devices
4. Set up notifications for compliance violations

## Troubleshooting

### Firewall Not Enabling

Check System Integrity Protection status:
```bash
csrutil status
```

Verify LaunchDaemon is running:
```bash
sudo launchctl list | grep firewall
```

Check permissions:
```bash
ls -la /usr/local/bin/firewall_management.sh
```

### Rules Not Applying

Check for errors in logs:
```bash
tail -100 /var/log/firewall_management.log | grep ERROR
```

Manually test rule application:
```bash
sudo /usr/local/bin/firewall_management.sh
```

Verify network detection:
```bash
sudo /usr/local/bin/network_detection.sh
```

### MDE Signals Not Appearing

Verify Defender is running:
```bash
ps aux | grep wdavdaemon
```

Check MDE onboarding:
```bash
sudo /usr/local/bin/mdatp health
```

Review signal log:
```bash
cat /var/log/mde_signals.log
```

### User Notifications Not Showing

Verify swiftDialog installation:
```bash
ls -la /usr/local/bin/dialog
```

Test notification manually:
```bash
sudo /usr/local/bin/user_notification.sh test firewall_disabled
```

Check console user:
```bash
stat -f "%Su" /dev/console
```

### Network Location Detection Issues

Test each detection method:

```bash
# Check VPN
scutil --nc list

# Check SSID
/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I

# Check IP addresses
ifconfig | grep "inet "

# Check DNS
scutil --dns | grep domain
```

## Maintenance

### Updating Rules

1. Edit `/usr/local/bin/firewall_rules.sh`
2. Add or remove applications
3. Force immediate update:

```bash
sudo /usr/local/bin/firewall_management.sh
```

### Log Rotation

Logs will grow over time. Implement log rotation:

```bash
# Create logrotate config
cat > /etc/newsyslog.d/firewall_management.conf <<EOF
/var/log/firewall_management.log    644  7    1000  *  J
/var/log/mde_signals.log            644  7    1000  *  J
/var/log/mde_alerts.log             644  7    1000  *  J
EOF
```

### Uninstallation

If removal is required:

```bash
# Stop and unload LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.company.firewall.management.plist

# Remove files
sudo rm /Library/LaunchDaemons/com.company.firewall.management.plist
sudo rm /usr/local/bin/network_detection.sh
sudo rm /usr/local/bin/firewall_rules.sh
sudo rm /usr/local/bin/firewall_management.sh
sudo rm /usr/local/bin/mde_reporting.sh
sudo rm /usr/local/bin/user_notification.sh

# Remove state files
sudo rm /var/tmp/firewall_state.json
sudo rm /var/tmp/last_network_location

# Remove logs (optional)
sudo rm /var/log/firewall_management*.log
sudo rm /var/log/mde_*.log
```

## Security Considerations

### Permissions

- Scripts run as root via LaunchDaemon
- State files stored in `/var/tmp` with restricted permissions
- Logs contain no sensitive user data

### Network Detection

- Detection logic prioritises VPN and known networks
- Falls back to external ruleset if uncertain
- No external network calls required for detection

### User Privacy

- No personal data collected or transmitted
- Device serial number used only for MDE reporting
- Current user identified only for notification delivery

## Support

### Log Collection

For support requests, collect:

```bash
# Collect all relevant logs
tar czf firewall-support-$(hostname)-$(date +%Y%m%d).tar.gz \
    /var/log/firewall_management*.log \
    /var/log/mde_*.log \
    /var/tmp/firewall_state.json \
    /Library/LaunchDaemons/com.company.firewall.management.plist
```

### Common Issues

**Issue**: Firewall keeps disabling
**Solution**: Check for conflicting management profiles or user overrides

**Issue**: Rules apply but applications still blocked
**Solution**: Verify application paths are correct and signed

**Issue**: Network location always shows external
**Solution**: Verify network detection configuration matches environment

**Issue**: MDE signals not reaching portal
**Solution**: Verify Defender onboarding and network connectivity

## Changelog

### Version 1.0.0 (Initial Release)
- Network location-aware firewall management
- Microsoft Defender integration
- swiftDialog user notifications
- Jamf Pro Extension Attributes
- Comprehensive logging and monitoring
- Automated remediation workflows

## Authors

David Crosby (Bing)
LinkedIn: https://www.linkedin.com/in/david-bing-crosby/
GitHub: https://github.com/david-crosby
