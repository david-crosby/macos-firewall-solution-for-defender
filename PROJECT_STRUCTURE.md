# Project Structure

## Overview

Complete macOS Firewall Management Solution with Microsoft Defender for Endpoint integration.

## Directory Structure

```
firewall-solution/
├── README.md                           # Main project documentation
├── docs/                               # Comprehensive documentation
│   ├── DEPLOYMENT_GUIDE.md            # Full deployment instructions
│   ├── QUICK_START.md                 # 30-minute quick start guide
│   └── CONFIGURATION_EXAMPLES.md      # Industry-specific configurations
├── scripts/                            # All executable scripts
│   ├── network_detection.sh           # Network location detection
│   ├── firewall_rules.sh              # Application allowlist configuration
│   ├── firewall_management.sh         # Core management engine
│   ├── mde_reporting.sh               # Microsoft Defender integration
│   ├── user_notification.sh           # swiftDialog notifications
│   ├── jamf_deployment.sh             # Jamf Pro deployment script
│   ├── jamf_ea_firewall_compliance.sh # Extension Attribute script
│   └── test_installation.sh           # Testing and validation
├── launchDaemons/                      # System daemons
│   └── com.company.firewall.management.plist  # Monitoring daemon
└── profiles/                           # Configuration profiles
    └── firewall_configuration_profile.mobileconfig  # Jamf Pro profile
```

## Component Details

### Core Scripts

#### network_detection.sh
**Purpose**: Determines if device is on corporate or external network

**Detection Methods**:
- VPN connection status
- Corporate SSID matching
- Corporate subnet validation
- Corporate DNS suffix detection

**Configuration Required**:
- `CORPORATE_SSIDS`: Array of corporate WiFi networks
- `CORPORATE_SUBNETS`: Array of IP subnets in CIDR notation
- `CORPORATE_DNS_SUFFIX`: Internal DNS domain

**Output**: "corporate" or "external"

#### firewall_rules.sh
**Purpose**: Defines allowed applications for each network location

**Application Categories**:
- Apple system services (always allowed)
- Microsoft 365 applications
- ServiceNow
- Web browsers
- Microsoft Defender for Endpoint
- Jamf Pro agent

**Functions**:
- `get_corporate_allowed_apps()`: Apps allowed on corporate network
- `get_external_allowed_apps()`: Apps allowed on external network
- `get_allowed_apps_for_location()`: Returns appropriate list

**Customisation**: Add your applications to relevant arrays

#### firewall_management.sh
**Purpose**: Core engine that manages firewall state and rules

**Key Functions**:
- `ensure_firewall_enabled()`: Enables firewall if disabled
- `apply_firewall_rules()`: Applies location-specific rules
- `verify_rules_compliance()`: Checks rules match expected state
- `remediate_firewall()`: Auto-remediates non-compliance
- `check_unsigned_apps()`: Monitors for unsigned app attempts

**Execution Flow**:
1. Detect network location
2. Check firewall enabled
3. Verify rules compliance
4. Remediate if needed
5. Report to MDE
6. Notify user if action taken

**Dependencies**:
- network_detection.sh
- firewall_rules.sh
- mde_reporting.sh
- user_notification.sh

#### mde_reporting.sh
**Purpose**: Sends custom signals to Microsoft Defender for Endpoint

**Signal Types**:
- `macOS.Firewall.Disabled` (High severity)
- `macOS.Firewall.RuleViolation` (Medium severity)
- `macOS.Firewall.UnsignedAppBlocked` (Low severity)
- `macOS.Firewall.LocationMismatch` (Informational)
- `macOS.Firewall.Compliant` (Informational)

**Functions**:
- `send_mde_signal()`: Primary signal sending function
- `get_device_info()`: Collects device metadata
- `check_mde_installed()`: Validates Defender presence
- `test_mde_integration()`: Testing utility

**Logs**: `/var/log/mde_signals.log`, `/var/log/mde_alerts.log`

#### user_notification.sh
**Purpose**: Displays compliance notifications using swiftDialog

**Notification Scenarios**:
- Firewall disabled and re-enabled
- Rules updated for compliance
- Unsigned application blocked
- Network location changed

**Functions**:
- `show_notification()`: Primary notification function
- `check_swiftdialog()`: Validates swiftDialog presence
- `send_fallback_notification()`: Uses osascript if swiftDialog unavailable
- `test_notification()`: Testing utility

**Prerequisite**: swiftDialog must be installed

#### jamf_deployment.sh
**Purpose**: Automates deployment via Jamf Pro policy

**Deployment Steps**:
1. Checks prerequisites (swiftDialog, MDE, Python 3)
2. Creates log directories
3. Installs scripts to `/usr/local/bin`
4. Installs LaunchDaemon
5. Loads LaunchDaemon
6. Configures firewall baseline
7. Runs initial configuration
8. Verifies installation

**Usage**: Run as Jamf Pro policy script (After package installation)

#### jamf_ea_firewall_compliance.sh
**Purpose**: Jamf Pro Extension Attribute for inventory reporting

**Reports**:
- Compliance status
- Network location
- Firewall state
- Last check timestamp

**Output Format**: `Status: compliant | Location: corporate | Firewall: enabled | Last Check: 2025-11-28T10:30:00Z`

**Usage**: Add as Extension Attribute in Jamf Pro

#### test_installation.sh
**Purpose**: Comprehensive testing and validation

**Test Categories**:
- Prerequisites (swiftDialog, MDE, Python, Jamf)
- Script installation
- LaunchDaemon status
- Log files
- Network detection
- Firewall state
- Firewall rules
- MDE integration
- User notifications
- State files
- Functional test

**Output**: Pass/Fail/Warning for each test with summary

**Usage**: `sudo /usr/local/bin/test_installation.sh`

### System Components

#### com.company.firewall.management.plist
**Purpose**: LaunchDaemon for continuous monitoring

**Configuration**:
- Runs every 5 minutes (`StartInterval: 300`)
- Runs at system boot (`RunAtLoad: true`)
- Monitors firewall preference changes (`WatchPaths`)
- Background process priority
- Logs to `/var/log/firewall_management_stdout.log`

**Management**:
```bash
# Load
sudo launchctl load /Library/LaunchDaemons/com.company.firewall.management.plist

# Unload
sudo launchctl unload /Library/LaunchDaemons/com.company.firewall.management.plist

# Check status
sudo launchctl list | grep com.company.firewall.management
```

#### firewall_configuration_profile.mobileconfig
**Purpose**: Jamf Pro configuration profile for firewall baseline

**Settings**:
- Enable Firewall: Yes
- Enable Stealth Mode: Yes
- Allow Signed Applications: Yes
- Allow Built-in Software: Yes
- Block All Incoming: No (managed via application rules)

**Deployment**: Upload to Jamf Pro Configuration Profiles

**Note**: UUIDs must be generated before use

### Documentation

#### DEPLOYMENT_GUIDE.md
**Comprehensive deployment documentation including**:
- Architecture overview
- Prerequisites
- Step-by-step installation
- Configuration instructions
- Monitoring procedures
- Troubleshooting guide
- Maintenance procedures
- Uninstallation instructions

#### QUICK_START.md
**30-minute deployment guide including**:
- Pre-deployment checklist
- Quick configuration steps
- Rapid deployment via Jamf Pro
- Verification procedures
- Common first-time issues
- Production rollout plan

#### CONFIGURATION_EXAMPLES.md
**Industry-specific configurations including**:
- Financial services
- Healthcare
- Technology companies
- Manufacturing
- Professional services
- VPN-specific configurations
- Custom network detection
- Testing procedures

## File Locations After Deployment

### Scripts
```
/usr/local/bin/network_detection.sh
/usr/local/bin/firewall_rules.sh
/usr/local/bin/firewall_management.sh
/usr/local/bin/mde_reporting.sh
/usr/local/bin/user_notification.sh
```

### LaunchDaemon
```
/Library/LaunchDaemons/com.company.firewall.management.plist
```

### Logs
```
/var/log/firewall_management.log           # Main operational log
/var/log/firewall_management_stdout.log    # LaunchDaemon output
/var/log/firewall_management_stderr.log    # LaunchDaemon errors
/var/log/mde_signals.log                   # MDE signal history
/var/log/mde_alerts.log                    # MDE alert history
```

### State Files
```
/var/tmp/firewall_state.json               # Current compliance state
/var/tmp/last_network_location             # Last detected location
```

## Data Flow

```
Network Detection → Firewall Management → Rule Application
                           ↓
                    Compliance Check
                           ↓
                   ┌──────┴──────┐
                   ↓              ↓
            MDE Reporting    User Notification
```

## Integration Points

### Jamf Pro
- Package deployment
- Configuration Profiles
- Extension Attributes
- Smart Groups
- Policy triggers

### Microsoft Defender for Endpoint
- Custom signals
- Advanced Hunting queries
- Alert creation
- Security dashboard

### macOS
- Application Firewall (socketfilterfw)
- System logs
- Network detection
- LaunchDaemon

## Security Considerations

### Permissions
- Scripts run as root via LaunchDaemon
- State files: 644 permissions
- Logs: 644 permissions
- LaunchDaemon: 644, root:wheel

### Data Protection
- No credentials stored
- Minimal PII collection (device serial, hostname)
- Local network detection only
- No external API calls for core functionality

### Audit Trail
- All operations logged
- MDE signals provide compliance history
- Jamf Extension Attributes provide point-in-time status

## Customisation Points

### Network Detection
Edit `scripts/network_detection.sh`:
- Corporate SSIDs
- Corporate subnets
- DNS suffix
- VPN detection logic

### Application Rules
Edit `scripts/firewall_rules.sh`:
- Add custom applications
- Modify location-specific rules
- Add application categories

### MDE Signals
Edit `scripts/mde_reporting.sh`:
- Signal naming conventions
- Severity levels
- Additional metadata
- Custom reporting logic

### User Notifications
Edit `scripts/user_notification.sh`:
- Notification text
- Company branding
- Support links
- Notification timing

### Monitoring Frequency
Edit `launchDaemons/com.company.firewall.management.plist`:
- Check interval (default: 300 seconds)
- Startup behaviour
- Logging preferences

## Dependencies

### Required
- macOS 12 (Monterey) or later
- Python 3 (built-in macOS 12.3+)
- Jamf Pro agent
- swiftDialog (for notifications)

### Recommended
- Microsoft Defender for Endpoint (for MDE reporting)

### Optional
- Log aggregation system
- SIEM integration
- ServiceNow integration

## Version Control

When modifying scripts, update version information:

```bash
# Add to top of script
VERSION="1.0.0"
LAST_MODIFIED="2025-11-28"
AUTHOR="David Crosby"
```

Document changes in deployment guide and commit with conventional commits:

```bash
git commit -m "feat: add support for additional VPN client detection"
git commit -m "fix: resolve subnet detection issue for /32 addresses"
git commit -m "docs: update configuration examples for healthcare"
```

## Testing Procedures

### Unit Testing
Test individual components:
```bash
sudo /usr/local/bin/network_detection.sh
sudo /usr/local/bin/user_notification.sh test
sudo /usr/local/bin/mde_reporting.sh test
```

### Integration Testing
Test complete workflow:
```bash
sudo /usr/local/bin/firewall_management.sh
```

### Validation
Run comprehensive tests:
```bash
sudo /usr/local/bin/test_installation.sh
```

## Deployment Workflow

1. **Development**: Modify scripts, test locally
2. **Testing**: Deploy to test device via Jamf
3. **Validation**: Run test_installation.sh
4. **Pilot**: Deploy to small group (10-20 devices)
5. **Monitor**: Watch logs and MDE signals
6. **Production**: Roll out to all devices
7. **Maintain**: Regular monitoring and updates

## Support Resources

### Internal
- IT Service Desk
- Security team
- Jamf administrators

### External
- swiftDialog documentation
- Microsoft Defender documentation
- Jamf Nation community
- Apple Developer documentation

## Licence and Author

**Author**: David Crosby (Bing)
- LinkedIn: [David Bing Crosby](https://www.linkedin.com/in/david-bing-crosby/)
- GitHub: [david-crosby](https://github.com/david-crosby)

