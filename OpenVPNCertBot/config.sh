#!/bin/bash

# Check if sudo is installed
if ! command -v "sudo" >/dev/null 2>&1; then
	echo "I need sudo to be installed. Aborting..."
	exit 1
fi

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Create local folders
mkdir "${SCRIPTDIR}/files"
mkdir "${SCRIPTDIR}/ovpns"

# Create new user to execute the bot
sudo useradd -G openvpncertbot,sudo -m openvpncertbot

# Copy conf to tmpfiles.d
sudo cp openvpncertbot.conf /etc/tmpfiles.d/openvpncertbot.conf

# Move all the files to the new user
mv "${SCRIPTDIR}" /home/openvpncertbot/