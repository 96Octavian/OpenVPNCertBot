#!/bin/bash

set -e

# Check if sudo is installed
if ! command -v "sudo" >/dev/null 2>&1; then
	echo "I need sudo to be installed. Aborting..."
	exit 1
fi

if [ "$(id -u)" != "0" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

if [ -z "$1" ]
then
	echo "You must specify a public IPv4 address or a domain name"
	exit 1
fi

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Write the provided server address
sed -i -e "s/IPV4PUB/$1/g" default.txt

# Create local folders
mkdir "${SCRIPTDIR}/files"
mkdir "${SCRIPTDIR}/ovpns"
mkdir "${SCRIPTDIR}/defaults"

# Create new user to execute the bot
useradd -m openvpncertbot

# Change files permissions and ownership
chmod +x *.sh *.py
sudo chown openvpncertbot:openvpncertbot *

# Copy conf to tmpfiles.d
sudo cp openvpncertbot.conf /etc/tmpfiles.d/openvpncertbot.conf

# Move all the files to the new user
mv "${SCRIPTDIR}" /home/openvpncertbot/

# Give the user some info
echo "The file default.txt will be used to provide clients with configuration. Edit it to suit your needs."
echo "In addition, in the \"defaults\\\" folder every user will have its own base file"