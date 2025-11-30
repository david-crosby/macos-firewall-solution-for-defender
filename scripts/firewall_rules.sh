#!/bin/zsh

# This script manages firewall allowlists for different network locations.
# It differentiates between corporate and external network environments to
# enforce appropriate security policies.

setopt ERR_EXIT
setopt NO_UNSET
setopt PIPE_FAIL

typeset -ar APPLE_SERVICES=(
    "/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdate_notify_agent"
    "/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdate_download_service"
    "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/storeuid"
    "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/storeassetd"
    "/usr/libexec/trustd"
    "/usr/sbin/ocspd"
    "/usr/libexec/nsurlsessiond"
    "/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support/appstoreagent"
    "/System/Library/CoreServices/NotificationCenter.app/Contents/MacOS/NotificationCenter"
    "/usr/sbin/softwareupdate"
    "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd"
    "/System/Library/PrivateFrameworks/IMDaemonCore.framework/XPCServices/IMDPersistenceAgent.xpc/Contents/MacOS/IMDPersistenceAgent"
    "/System/Library/CoreServices/AppleIDAuthAgent"
    "/System/Library/PrivateFrameworks/CoreFollowUp.framework/Versions/A/Resources/followupd"
)

typeset -ar MICROSOFT_APPS=(
    "/Applications/Microsoft Teams.app/Contents/MacOS/Teams"
    "/Applications/Microsoft Teams (work or school).app/Contents/MacOS/Teams"  # New Teams
    "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook"
    "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"
    "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel"
    "/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint"
    "/Applications/Microsoft OneNote.app/Contents/MacOS/Microsoft OneNote"
    "/Applications/OneDrive.app/Contents/MacOS/OneDrive"
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"  # Categorized as MS app, not browser
    "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft AutoUpdate"
    "/Applications/Company Portal.app/Contents/MacOS/Company Portal"
    "/Library/Intune/Microsoft Intune Agent.app/Contents/MacOS/IntuneMdmDaemon"
)

typeset -ar SERVICENOW_APPS=(
    "/Applications/ServiceNow.app/Contents/MacOS/ServiceNow"
)

typeset -ar WEB_BROWSERS=(
    "/Applications/Safari.app/Contents/MacOS/Safari"
    "/System/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari"
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    "/Applications/Firefox.app/Contents/MacOS/firefox"
)

typeset -ar DEFENDER_APPS=(
    "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon"
    "/Library/Application Support/Microsoft/Defender/wdavdaemon_enterprise.app/Contents/MacOS/wdavdaemon_enterprise"
)

typeset -ar JAMF_APPS=(
    "/usr/local/jamf/bin/jamf"
    "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon"
    "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfAgent.app/Contents/MacOS/JamfAgent"
    "/Library/Application Support/JamfConnect/Jamf Connect.app/Contents/MacOS/Jamf Connect"
    "/Library/Application Support/JamfConnect/JamfConnectLogin.app/Contents/MacOS/JamfConnectLogin"
    "/Library/Application Support/JamfProtect/Jamf Protect.app/Contents/MacOS/Jamf Protect"
    "/Library/Application Support/JamfProtect/components/JamfProtect.system"
    "/Library/Application Support/JamfProtect/components/UnifiedLogging"
)

# Built-in macOS services (bundle IDs, not file paths)
# Used by firewall_management.sh for service-level firewall rules
typeset -ar BUILTIN_SERVICES=(
    "com.apple.systempreferences.sharedsettingsui"
    "com.apple.sharingd"  # Enables AirDrop, Handoff, Universal Clipboard
)

typeset -ar FILE_SHARING_SERVICES=(
    "/sbin/mount_smbfs"
    "/sbin/mount_nfs"
    "/sbin/mount_afp"
    "/usr/sbin/smbd"
    "/usr/sbin/nmbd"
    "/System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthAgent"
    "/System/Library/Filesystems/smbfs.fs/Contents/Resources/mount_smbfs"
    "/System/Library/Filesystems/nfs.fs/Contents/Resources/mount_nfs"
)

typeset -ar DEV_TOOLS=(
    "/opt/homebrew/bin/brew"
    "/usr/local/bin/brew"
    "/usr/bin/git"
    "/usr/bin/ssh"
    "/usr/bin/curl"
    "/usr/bin/wget"
    "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
    "/Applications/Xcode.app/Contents/MacOS/Xcode"
    "/Applications/iTerm.app/Contents/MacOS/iTerm2"
    "/Applications/Docker.app/Contents/MacOS/Docker"
    "/Applications/Postman.app/Contents/MacOS/Postman"
    "/usr/local/bin/node"
    "/opt/homebrew/bin/node"
    "/usr/local/bin/python3"
    "/opt/homebrew/bin/python3"
)

typeset -ar VPN_APPS=(
    "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/MacOS/Cisco AnyConnect Secure Mobility Client"
    "/Applications/Cisco/Cisco Secure Client.app/Contents/MacOS/Cisco Secure Client"
    "/opt/cisco/anyconnect/bin/vpnagent"
    "/opt/cisco/secureclient/bin/vpnagent"
    "/Applications/GlobalProtect.app/Contents/MacOS/GlobalProtect"
    "/Library/Application Support/Palo Alto Networks/GlobalProtect/PanGPS.app/Contents/MacOS/PanGPS"
    "/Library/Application Support/Palo Alto Networks/GlobalProtect/PanGPA.app/Contents/MacOS/PanGPA"
)

typeset -ar TIME_SERVICES=(
    "/usr/sbin/ntpd"
    "/usr/libexec/timed"
    "/usr/sbin/systemsetup"
)

typeset -ar REMOTE_ADMIN=(
    "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"
    "/System/Library/CoreServices/RemoteManagement/AppleVNCServer.app/Contents/MacOS/AppleVNCServer"
    "/System/Library/CoreServices/Screen Sharing.app/Contents/MacOS/Screen Sharing"
    "/Applications/Microsoft Remote Desktop.app/Contents/MacOS/Microsoft Remote Desktop"
)

typeset -ar PRINTING_SERVICES=(
    "/usr/libexec/cups/backend/ipp"
    "/usr/libexec/cups/backend/lpd"
    "/usr/libexec/cups/backend/smb"
    "/usr/sbin/cupsd"
    "/usr/libexec/cups/daemon/cups-lpd"
)


get_corporate_allowed_apps() {
    local -a apps
    apps=()
    apps+=("${APPLE_SERVICES[@]}")
    apps+=("${MICROSOFT_APPS[@]}")
    apps+=("${SERVICENOW_APPS[@]}")
    apps+=("${WEB_BROWSERS[@]}")
    apps+=("${DEFENDER_APPS[@]}")
    apps+=("${JAMF_APPS[@]}")
    apps+=("${FILE_SHARING_SERVICES[@]}")
    apps+=("${DEV_TOOLS[@]}")
    apps+=("${VPN_APPS[@]}")
    apps+=("${TIME_SERVICES[@]}")
    apps+=("${REMOTE_ADMIN[@]}")
    apps+=("${PRINTING_SERVICES[@]}")

    print -rl -- "${apps[@]}"
}


get_external_allowed_apps() {
    local -a apps
    apps=()
    apps+=("${APPLE_SERVICES[@]}")
    apps+=("${MICROSOFT_APPS[@]}")
    apps+=("${SERVICENOW_APPS[@]}")
    apps+=("${WEB_BROWSERS[@]}")
    apps+=("${DEFENDER_APPS[@]}")
    apps+=("${JAMF_APPS[@]}")
    # Note: FILE_SHARING_SERVICES are NOT included for external networks
    apps+=("${DEV_TOOLS[@]}")
    apps+=("${VPN_APPS[@]}")
    apps+=("${TIME_SERVICES[@]}")
    # Note: REMOTE_ADMIN and PRINTING_SERVICES are NOT included for external networks

    print -rl -- "${apps[@]}"
}


get_allowed_apps_for_location() {
    local location="${1:-}"

    case "$location" in
        corporate)
            get_corporate_allowed_apps
            ;;
        external)
            get_external_allowed_apps
            ;;
        "")
            print -u2 "Error: Location parameter is required"
            print -u2 "Usage: get_allowed_apps_for_location {corporate|external}"
            return 1
            ;;
        *)
            print -u2 "Error: Invalid location '$location'"
            print -u2 "Valid options: 'corporate' or 'external'"
            return 1
            ;;
    esac
}
