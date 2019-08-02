#!/bin/bash

set -e

# Check if sudo is installed
if ! command -v "sudo" >/dev/null 2>&1; then
	echo "I need sudo to be installed. Aborting..."
	exit 1
fi

# Check if we are root
if [ "$(id -u)" != "0" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

# Get server address, token and admin
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -i|--ipaddr)
    ADDRESS="$2"
    shift # past argument
    shift # past value
    ;;
    -T|--Token)
    TOKEN="$2"
    shift # past argument
    shift # past value
    ;;
    -a|--admin)
    ADMIN="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [ -z "${ADDRESS}" ]
then
    echo "Use -i or --ipaddr to specify the server address"
    exit 1
fi
if [ -z "${TOKEN}" ]
then
    echo "Use -T or --Token to specify the bot's token"
    exit 1
fi

if [ -z "${ADMIN}" ]
then
    echo "Use -a or --admin to specify the admin's ID"
    exit 1
fi

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Copy conf to tmpfiles.d
echo "Copying openvpncertbot.conf to /etc/tmpfiles.d/openvpncertbot.conf"
cp openvpncertbot.conf /etc/tmpfiles.d/openvpncertbot.conf
mkdir -p /run/openvpncertbot

# Create new user to execute the bot
if ! id -u openvpncertbot > /dev/null 2>&1
then
    echo "Creating new user..."
    useradd -m openvpncertbot
fi

# Copy all the files to the new user
echo "Copying directory to new user..."
cp -r "${SCRIPTDIR}" /home/openvpncertbot/
cd /home/openvpncertbot/OpenVPNCertBot

# Create local folders
echo "Creating files..."
mkdir -p "files"
if [ ! -f files/users.json ]; then
    echo "{}" > files/users.json
fi
if [ ! -f files/awaiting.json ]; then
    echo "{}" > files/awaiting.json
fi
echo "Creating ovpns..."
mkdir -p "ovpns"
echo "Creating defaults..."
mkdir -p "defaults"

# Change files permissions and ownership
echo "Changing permission and ownership..."
chown -R openvpncertbot:openvpncertbot /home/openvpncertbot/OpenVPNCertBot
chmod +x *.sh *.py

# Write the provided server address
echo "Using server address..."
sed -i -e "s/IPV4PUB/${ADDRESS}/g" default.txt

# Add user to sudoers
echo "Granting user sudoers rights..."
echo "openvpncertbot ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/010_openvpncertbot

# Enable openvpncertbot.service
echo "Usign Token and admin..."
sed -i -e "s/TOKEN/${TOKEN}/g" openvpncertbot.service
sed -i -e "s/ADMIN/${ADMIN}/g" openvpncertbot.service

echo "Setting up systemd unit..."
cp openvpncertbot.service /etc/systemd/system/openvpncertbot.service

# Give the user some info
echo "The file default.txt will be used to provide clients with configuration. Edit it to suit your needs."
echo "In addition, in the \"defaults\" folder every user will have its own base file"
echo "Stop the running bot (if running), run \"systemctl daemon-reload\" and then enable/start the bot with \"systemctl start openvpncertbot\""
