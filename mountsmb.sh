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

while true; do
	domnt 'smb://mbaya:groteke2892@10.0.0.250/media' /Volumes/media
	sleep 15
done
