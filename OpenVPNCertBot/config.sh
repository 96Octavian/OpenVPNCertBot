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

if [ -z ${ADDRESS} ]
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

# Create local folders
mkdir "${SCRIPTDIR}/files"
mkdir "${SCRIPTDIR}/ovpns"
mkdir "${SCRIPTDIR}/defaults"

# Copy conf to tmpfiles.d
cp openvpncertbot.conf /etc/tmpfiles.d/openvpncertbot.conf

# Create new user to execute the bot
useradd -m openvpncertbot

# Move all the files to the new user
cp -r "${SCRIPTDIR}" /home/openvpncertbot/

# Change files permissions and ownership
cd /home/openvpncertbot/OpenVPNCertBot
chmod +x *.sh *.py
chown openvpncertbot:openvpncertbot *

# Write the provided server address
sed -i -e "s/IPV4PUB/$1/g" default.txt

# Add user to sudoers
echo "openvpncertbot ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/010_openvpncertbot

# Enable openvpncertbot.service
sed -i -e "s/TOKEN/${TOKEN}/g" openvpncertbot.service
sed -i -e "s/ADMIN/${ADMIN}/g" openvpncertbot.service

cp openvpncertbot.service /etc/systemd/system/openvpncertbot.service

# Give the user some info
echo "The file default.txt will be used to provide clients with configuration. Edit it to suit your needs."
echo "In addition, in the \"defaults\\\" folder every user will have its own base file"