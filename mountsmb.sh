#!/bin/sh

# mount SMB/CIFS from macOS using AppleScript.
# Ref: https://apple.stackexchange.com/questions/697/how-can-i-mount-an-smb-share-from-the-command-line#comment475611_303595
domnt() {
	local loc="$1" mnt="$2"

	if ! mount | grep -qF " $mnt " ; then
		if timeout 7 osascript -e  'mount volume "'"$loc"'"' ; then
			echo "'$loc' has been mounted at '$mnt'"
		fi
	fi
}

# Check for required environment variables
if [ -z "$SMB_USERNAME" ] || [ -z "$SMB_PASSWORD" ] || [ -z "$SMB_HOST" ]; then
	echo "Error: Missing required environment variables"
	echo "Please set: SMB_USERNAME, SMB_PASSWORD, SMB_HOST"
	echo "Example: export SMB_USERNAME=username"
	echo "         export SMB_PASSWORD=password" 
	echo "         export SMB_HOST=10.0.0.250"
	exit 1
fi

# Use environment variables for credentials
SMB_SHARE=${SMB_SHARE:-media}
MOUNT_POINT=${MOUNT_POINT:-/Volumes/media}

while true; do
	domnt "smb://${SMB_USERNAME}:${SMB_PASSWORD}@${SMB_HOST}/${SMB_SHARE}" "$MOUNT_POINT"
	sleep 15
done
