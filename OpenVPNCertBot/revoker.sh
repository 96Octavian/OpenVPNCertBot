#!/bin/bash

NAME=$1
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
EASYRSA=easyrsa
# Check if PiVPN is installed. If it is, use custom easyrsa
if pivpn 2> /dev/null | grep "PiVPN"; then
    echo "Using PiVPN custom easyrsa"
	EASYRSA=./easyrsa
fi

# Revoke the certificate
cd /etc/openvpn/easy-rsa || exit 1

${EASYRSA} --batch revoke "${NAME}" || exit 1
${EASYRSA} gen-crl
rm -rf "pki/reqs/${NAME}.req"
rm -rf "pki/private/${NAME}.key"
rm -rf "pki/issued/${NAME}.crt"
rm -rf "pki/${NAME}.ovpn"
cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
chown nobody:nobody /etc/openvpn/crl.pem

rm -rf "${SCRIPTDIR}/ovpns/${NAME}.ovpn"

# Remove systemd timer
systemctl stop ${NAME}.timer
rm -rf /etc/systemd/system/${NAME}.timer
rm -rf /etc/systemd/system/${NAME}.service

# If bot's PID is given as argument 2, notify the bot
if [ ! -z "$2" ]
then
	echo "${NAME}" >> "${SCRIPTDIR}/files/removed.lst"
	pkill -10 -F /run/openvpncertbot/openvpncertbot.pid
fi
