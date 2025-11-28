# Quick Start Guide

## Overview

Get the macOS Firewall Management Solution deployed in your environment quickly.

## Pre-Deployment Checklist

- [ ] swiftDialog installed on target devices
- [ ] Microsoft Defender for Endpoint deployed and onboarded
- [ ] Jamf Pro managing target devices
- [ ] Admin access to Jamf Pro
- [ ] Test device available

## 30-Minute Deployment

### Step 1: Configure Network Detection (5 minutes)

Edit `scripts/network_detection.sh`:

```bash
# Your corporate WiFi networks
CORPORATE_SSIDS=("CorpWiFi" "CorpGuest")

# Your IP subnets (CIDR notation)
CORPORATE_SUBNETS=("10.0.0.0/8" "172.16.0.0/12")

# Your internal DNS domain
CORPORATE_DNS_SUFFIX="corp.internal"
```

### Step 2: Customise Application Rules (5 minutes)

Edit `scripts/firewall_rules.sh` if you need additional applications:

```bash
# Add your custom applications
CUSTOM_APPS=(
    "/Applications/YourApp.app/Contents/MacOS/YourApp"
)
```

Most common enterprise apps are already included:
- Microsoft 365 suite
- ServiceNow
- Web browsers
- Apple services

### Step 3: Create Jamf Pro Package (5 minutes)

```bash
# Navigate to the solution directory
cd firewall-solution

# Create package
pkgbuild --root . \
         --identifier com.company.firewall.management \
         --version 1.0.0 \
         --install-location /tmp/firewall_scripts \
         firewall-management-1.0.0.pkg
```

Upload package to Jamf Pro:
1. Settings > Computer Management > Packages
2. Click "New"
3. Upload `firewall-management-1.0.0.pkg`

### Step 4: Create Configuration Profile (5 minutes)

In Jamf Pro:

1. Computers > Configuration Profiles > New
2. Name: "Firewall Baseline Configuration"
3. Add payload: **Security & Privacy**
   - Enable Firewall: ✓
   - Enable Stealth Mode: ✓
4. Scope to test device
5. Save

### Step 5: Create PPPC Profile (3 minutes)

Create a new Configuration Profile:

1. Name: "Firewall Management PPPC"
2. Add payload: **Privacy Preferences Policy Control**
3. Add entry:
   - Identifier: `/usr/local/bin/firewall_management.sh`
   - Identifier Type: Path
   - App or Service: SystemPolicyAllFiles
   - Access: Allow
4. Scope to test device
5. Save

### Step 6: Create Deployment Policy (5 minutes)

In Jamf Pro:

1. Computers > Policies > New
2. Name: "Deploy Firewall Management"
3. **Packages** tab:
   - Add: firewall-management-1.0.0.pkg
4. **Scripts** tab:
   - Add: jamf_deployment.sh
   - Priority: After
5. **Scope** tab:
   - Add test device
6. **Frequency**: Once per computer
7. Save and enable

### Step 7: Add Extension Attribute (2 minutes)

1. Settings > Computer Management > Extension Attributes
2. New
3. Display Name: "Firewall Compliance Status"
4. Data Type: String
5. Input Type: Script
6. Paste contents from `scripts/jamf_ea_firewall_compliance.sh`
7. Save

### Step 8: Test Deployment (5 minutes)

On test device:

```bash
# Trigger Jamf policy
sudo jamf policy

# Wait for installation, then verify
sudo /usr/local/bin/test_installation.sh
```

Review test output for any failures.

## Verification

### Check Installation

```bash
# LaunchDaemon loaded?
sudo launchctl list | grep com.company.firewall.management

# Scripts installed?
ls -la /usr/local/bin/*firewall* /usr/local/bin/*mde* /usr/local/bin/*network*

# Logs created?
ls -la /var/log/firewall_management.log
```

### Check Functionality

```bash
# View recent activity
tail -50 /var/log/firewall_management.log

# Check current state
cat /var/tmp/firewall_state.json

# Verify network detection
sudo /usr/local/bin/network_detection.sh

# Test notification (will show to logged in user)
sudo /usr/local/bin/user_notification.sh test firewall_disabled
```

### Check Jamf Pro

1. Search for test device in inventory
2. View Extension Attributes
3. Look for "Firewall Compliance Status"
4. Should show: Status, Location, Firewall state, Last check time

### Check Microsoft Defender

In Microsoft 365 Defender portal:

1. Advanced Hunting
2. Run query:

```kusto
DeviceEvents
| where DeviceName == "your-test-device"
| where ActionType == "CustomDetection"
| where AdditionalFields contains "macOS.Firewall"
| project Timestamp, ActionType, AdditionalFields
| order by Timestamp desc
```

Should see "macOS.Firewall.Compliant" signals.

## Common First-Time Issues

### Issue: Scripts not executable

**Fix**:
```bash
sudo chmod +x /usr/local/bin/network_detection.sh
sudo chmod +x /usr/local/bin/firewall_rules.sh
sudo chmod +x /usr/local/bin/firewall_management.sh
sudo chmod +x /usr/local/bin/mde_reporting.sh
sudo chmod +x /usr/local/bin/user_notification.sh
```

### Issue: LaunchDaemon not loading

**Fix**:
```bash
# Check permissions
sudo chmod 644 /Library/LaunchDaemons/com.company.firewall.management.plist
sudo chown root:wheel /Library/LaunchDaemons/com.company.firewall.management.plist

# Load manually
sudo launchctl load /Library/LaunchDaemons/com.company.firewall.management.plist
```

### Issue: Network always shows "external"

**Fix**: Verify network detection configuration matches your environment:

```bash
# Test each detection method
sudo /usr/local/bin/network_detection.sh

# Check current values
scutil --nc list  # VPN
/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I  # SSID
ifconfig | grep "inet "  # IP addresses
scutil --dns | grep domain  # DNS
```

Update `CORPORATE_SSIDS`, `CORPORATE_SUBNETS`, or `CORPORATE_DNS_SUFFIX` as needed.

### Issue: swiftDialog notifications not showing

**Fix**:
```bash
# Verify installation
ls -la /usr/local/bin/dialog

# Check user logged in
stat -f "%Su" /dev/console

# Test manually as current user
su - $(stat -f "%Su" /dev/console) -c "/usr/local/bin/dialog --title 'Test' --message 'This is a test'"
```

## Production Rollout

Once tested successfully:

1. **Create Smart Groups**:
   - All managed devices
   - Devices with firewall disabled
   - Non-compliant devices

2. **Staged Deployment**:
   - Week 1: IT department (10-20 devices)
   - Week 2: Pilot group (100 devices)
   - Week 3: Full deployment

3. **Update Policy Scope**:
   - Change from test device to appropriate Smart Group
   - Set frequency: Once per computer

4. **Monitor**:
   - Jamf Pro Extension Attributes
   - Microsoft Defender portal
   - Log aggregation (if available)

## Monitoring After Deployment

### Daily Checks

- Review MDE portal for High/Medium severity signals
- Check Jamf Smart Group for non-compliant devices

### Weekly Checks

- Review log files for patterns
- Check Extension Attribute data across estate
- Verify LaunchDaemon running on sample devices

### Monthly Maintenance

- Review and update application allow list
- Check for unsigned application attempts
- Rotate logs if needed
- Update documentation

## Getting Help

### Log Collection

```bash
sudo tar czf firewall-logs-$(hostname)-$(date +%Y%m%d).tar.gz \
    /var/log/firewall_management*.log \
    /var/log/mde_*.log \
    /var/tmp/firewall_state.json
```

### Support Contacts

- **Technical Issues**: Your IT Service Desk
- **Policy Questions**: Security Team
- **Jamf Pro Issues**: Jamf Support
- **MDE Issues**: Microsoft Support

### Additional Resources

- Full documentation: `docs/DEPLOYMENT_GUIDE.md`
- Test script: `scripts/test_installation.sh`
- Source code: All scripts in `scripts/` directory

## Next Steps

After successful deployment:

1. Document your specific configuration
2. Train helpdesk on common issues
3. Create runbook for troubleshooting
4. Schedule regular reviews
5. Consider additional automation opportunities

## Success Criteria

Deployment is successful when:

- [ ] LaunchDaemon running on all devices
- [ ] Firewall enabled and compliant on all devices
- [ ] MDE signals appearing in Defender portal
- [ ] Extension Attribute reporting in Jamf
- [ ] No user complaints about blocked applications
- [ ] Log files showing regular checks
- [ ] Test device passing all validation checks

## Estimated Time Savings

This solution provides:

- **Automated remediation**: Saves ~15 minutes per incident
- **Continuous monitoring**: Replaces manual checks
- **Centralised reporting**: Single pane of glass
- **User awareness**: Reduces helpdesk calls

For 1000 devices with 5% non-compliance rate per month:
- Manual remediation: 50 devices × 15 minutes = 12.5 hours/month
- This solution: Automatic, ~0 hours/month

**ROI**: Immediate time savings plus improved security posture.

---

**Need help?** Review the full deployment guide in `docs/DEPLOYMENT_GUIDE.md`
