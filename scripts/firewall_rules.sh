#!/bin/zsh

# Firewall Rules Configuration
# Defines allowed applications and services for corporate and external networks

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
    "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook"
    "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"
    "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel"
    "/Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint"
    "/Applications/Microsoft OneNote.app/Contents/MacOS/Microsoft OneNote"
    "/Applications/OneDrive.app/Contents/MacOS/OneDrive"
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
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
)

typeset -ar BUILTIN_SERVICES=(
    "com.apple.systempreferences.sharedsettingsui"
    "com.apple.sharingd"
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
    
    print -rl -- "${apps[@]}"
}

get_allowed_apps_for_location() {
    local location="${1:-}"
    
    if [[ -z "$location" ]]; then
        return 1
    fi
    
    if [[ "$location" == "corporate" ]]; then
        get_corporate_allowed_apps
    else
        get_external_allowed_apps
    fi
}
