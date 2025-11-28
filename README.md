# macOS Enterprise Firewall Management Solution

Enterprise-grade firewall management for macOS devices with Microsoft Defender for Endpoint integration and Jamf Pro orchestration.

## Quick Start

This solution provides automated firewall management that:

- Detects network location (corporate vs external)
- Applies appropriate firewall rules automatically
- Self-remediates when non-compliant
- Reports compliance to Microsoft Defender for Endpoint
- Notifies users of security actions
- Integrates with Jamf Pro for deployment and reporting

## What's Included

### Scripts

- `network_detection.sh` - Identifies corporate vs external networks
- `firewall_rules.sh` - Defines allowed applications per location
- `firewall_management.sh` - Core management engine
- `mde_reporting.sh` - Microsoft Defender integration
- `user_notification.sh` - swiftDialog notifications
- `jamf_deployment.sh` - Automated deployment
- `jamf_ea_firewall_compliance.sh` - Jamf Extension Attribute

### Configuration

- LaunchDaemon for continuous monitoring
- Sample Configuration Profile for Jamf Pro
- PPPC profile requirements documented

### Documentation

- Comprehensive deployment guide
- Troubleshooting procedures
- Configuration examples
- Monitoring and maintenance instructions

## Prerequisites

Before deployment, ensure:

1. swiftDialog is installed on target devices
2. Microsoft Defender for Endpoint is deployed and onboarded
3. Jamf Pro is managing the devices
4. Python 3 is available (built-in macOS 12.3+)

## Installation

### Quick Deploy via Jamf Pro

1. Package the solution:
   ```bash
   pkgbuild --root ./firewall-solution \
            --identifier com.company.firewall.management \
            --version 1.0.0 \
            firewall-management-1.0.0.pkg
   ```

2. Upload to Jamf Pro

3. Create policy with:
   - Package: firewall-management-1.0.0.pkg
   - Script: jamf_deployment.sh
   - Frequency: Once per computer

4. Deploy Configuration Profile for firewall baseline

5. Add Extension Attribute for reporting

See [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for detailed instructions.

## Configuration

### Network Detection

Edit `scripts/network_detection.sh`:

```bash
CORPORATE_SSIDS=("YourWiFi" "YourGuestWiFi")
CORPORATE_SUBNETS=("10.0.0.0/8" "172.16.0.0/12")
CORPORATE_DNS_SUFFIX="yourdomain.internal"
```

### Application Allow List

Edit `scripts/firewall_rules.sh` to add your applications:

```bash
CUSTOM_APPS=(
    "/Applications/YourApp.app/Contents/MacOS/YourApp"
)
```

## How It Works

### Monitoring Cycle

1. LaunchDaemon runs check every 5 minutes
2. Detects current network location
3. Verifies firewall is enabled
4. Checks rules match expected configuration
5. Remediates if non-compliant
6. Sends status to Microsoft Defender
7. Notifies user if action taken

### Network Location Logic

The solution determines location using priority order:

1. VPN connection (connected = corporate)
2. Corporate SSID match
3. Corporate subnet match
4. Corporate DNS suffix match
5. Default to external if no match

### Remediation Actions

When non-compliant:

- Firewall disabled → Enable immediately
- Rules incorrect → Reapply correct ruleset
- Unsigned app detected → Block and report
- Location changed → Apply new ruleset
- Notify user via swiftDialog
- Send signal to Microsoft Defender

## Microsoft Defender Integration

### Custom Signals

| Signal | Severity | Meaning |
|--------|----------|---------|
| macOS.Firewall.Disabled | High | Firewall was disabled |
| macOS.Firewall.RuleViolation | Medium | Rules don't match policy |
| macOS.Firewall.UnsignedAppBlocked | Low | Unsigned app blocked |
| macOS.Firewall.LocationMismatch | Informational | Location changed |
| macOS.Firewall.Compliant | Informational | All checks passed |

### Viewing Signals

In Microsoft 365 Defender portal, use Advanced Hunting:

```kusto
DeviceEvents
| where ActionType == "CustomDetection"
| where AdditionalFields contains "macOS.Firewall"
| project Timestamp, DeviceName, ActionType, AdditionalFields
| order by Timestamp desc
```

## Jamf Pro Integration

### Extension Attribute

Reports current status to Jamf inventory:

- Compliance status
- Network location
- Firewall state
- Last check timestamp

### Smart Groups

Create Smart Groups based on Extension Attribute:

- Non-compliant devices
- Devices with firewall disabled
- External network devices

## Monitoring

### Logs

Main logs location:

- `/var/log/firewall_management.log` - All operations
- `/var/log/mde_signals.log` - MDE signal history
- `/var/log/mde_alerts.log` - MDE alert history

### Quick Status Check

```bash
# View current compliance state
cat /var/tmp/firewall_state.json

# Check recent activity
tail -50 /var/log/firewall_management.log

# Verify LaunchDaemon
sudo launchctl list | grep com.company.firewall.management
```

## Troubleshooting

### Firewall Won't Stay Enabled

Check for:
- Conflicting configuration profiles
- User overrides (requires admin to disable)
- SIP status: `csrutil status`

### Rules Not Applying

```bash
# Test manually
sudo /usr/local/bin/firewall_management.sh

# Check network detection
sudo /usr/local/bin/network_detection.sh

# Review logs
tail -100 /var/log/firewall_management.log
```

### MDE Signals Not Appearing

```bash
# Verify Defender running
ps aux | grep wdavdaemon

# Check health
sudo mdatp health

# Review signal log
cat /var/log/mde_signals.log
```

### User Notifications Not Showing

```bash
# Check swiftDialog
ls -la /usr/local/bin/dialog

# Test notification
sudo /usr/local/bin/user_notification.sh test firewall_disabled

# Check current user
stat -f "%Su" /dev/console
```

## Security

### Permissions

- Scripts run as root via LaunchDaemon
- No network calls required for core functionality
- State files protected with appropriate permissions
- No sensitive data in logs

### Privacy

- Minimal data collection
- Serial number used only for MDE reporting
- No personal user information collected
- Network detection purely local

## Maintenance

### Updating Application List

1. Edit `/usr/local/bin/firewall_rules.sh`
2. Add/remove applications
3. Force update: `sudo /usr/local/bin/firewall_management.sh`

### Log Rotation

Logs grow over time. Implement rotation:

```bash
cat > /etc/newsyslog.d/firewall_management.conf <<EOF
/var/log/firewall_management.log    644  7    1000  *  J
/var/log/mde_signals.log            644  7    1000  *  J
EOF
```

## Support

For issues or questions:

1. Review [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md)
2. Check troubleshooting section above
3. Collect logs: `/var/log/firewall_management.log`
4. Review MDE signals in Defender portal
5. Check Jamf Pro Extension Attribute data

## Contributing

This is an internal enterprise solution. For modifications:

1. Test changes in development environment
2. Update documentation
3. Test deployment via Jamf Pro
4. Verify MDE integration
5. Roll out to production

## Roadmap

Future enhancements under consideration:

- Enhanced reporting dashboard
- Integration with ServiceNow for ticket creation
- Support for application-specific rules
- Network service detection (DNS, NTP, etc.)
- Advanced threat detection integration

## License

Copyright (c) 2025 Your Company Name. All rights reserved.

Internal use only. Not for distribution.

## Author

**David Crosby (Bing)**

- LinkedIn: [David Bing Crosby](https://www.linkedin.com/in/david-bing-crosby/)
- GitHub: [david-crosby](https://github.com/david-crosby)

Technical Director transitioning to macOS Specialist role, specialising in enterprise Apple device management and automation.

## Acknowledgements

Built with:
- swiftDialog by Bart Reardon
- Microsoft Defender for Endpoint
- Jamf Pro
- macOS Application Firewall (socketfilterfw)
