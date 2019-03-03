#!/bin/bash

# Check if vpn is installed
if ! openvpn --version 2> /dev/null | grep "OpenVPN Inc"; then
    echo "openvpn not installed, aborting..."
	exit 1
fi

EASYRSA=""
# Check if easyrsa is installed
if easyrsa 2> /dev/null | grep "Easy-RSA 3"; then
    EASYRSA=easyrsa
fi
# Check if PiVPN is installed. If it is, use custom easyrsa
if pivpn 2> /dev/null | grep "PiVPN"; then
    echo "Using PiVPN custom easyrsa"
	EASYRSA=./easyrsa
fi
# If no easyrsa is installed, abort
if [ -z "$EASYRSA" ]; then
    echo "No easyrsa found. aborting..."
	exit 1
fi

USERID=$3
PASSWD=$2
NAME=$1
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

DEFAULT="${SCRIPTDIR}/defaults/default_${USERID}.txt"
FILEEXT=".ovpn"
CRT=".crt"
KEY=".key"
CA="ca.crt"
TA="ta.key"

cd /etc/openvpn/easy-rsa || exit 1

# Build the client key and then encrypt the key
expect << EOF
    set timeout -1
    spawn ${EASYRSA} build-client-full "${NAME}"
    expect "Enter PEM pass phrase" { send -- "${PASSWD}\r" }
    expect "Verifying - Enter PEM pass phrase" { send -- "${PASSWD}\r" }
    expect eof
EOF

cd pki || exit 1

# 1st Verify that clients Public Key Exists
if [ ! -f "issued/${NAME}${CRT}" ]; then
    echo "[ERROR]: Client Public Key Certificate not found: $NAME$CRT"
    exit 1
fi
echo "Client's cert found: $NAME$CRT"

# Then, verify that there is a private key for that client
if [ ! -f "private/${NAME}${KEY}" ]; then
    echo "[ERROR]: Client Private Key not found: $NAME$KEY"
    exit 1
fi
echo "Client's Private Key found: $NAME$KEY"

# Confirm the CA public key exists
if [ ! -f "${CA}" ]; then
    echo "[ERROR]: CA Public Key not found: $CA"
    exit 1
fi
echo "CA public Key found: $CA"

# Confirm the tls-auth ta key file exists
if [ ! -f "${TA}" ]; then
    echo "[ERROR]: tls-auth Key not found: $TA"
    exit 1
fi
echo "tls-auth Private Key found: $TA"

# Ready to make a new .ovpn file
{
    # Start by populating with the default file
    cat "${DEFAULT}"

    # Now, append the CA Public Cert
    echo "<ca>"
    cat "${CA}"
    echo "</ca>"

    # Next append the client Public Cert
    echo "<cert>"
    sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' < "issued/${NAME}${CRT}"
    echo "</cert>"

    # Then, append the client Private Key
    echo "<key>"
    cat "private/${NAME}${KEY}"
    echo "</key>"

    # Finally, append the TA Private Key
    echo "<tls-crypt>"
    cat "${TA}"
    echo "</tls-crypt>"

} > "${NAME}${FILEEXT}"

[ -d "${SCRIPTDIR}/ovpns" ] || mkdir -p "${SCRIPTDIR}/ovpns" && chown openvpncertbot:openvpncertbot "${SCRIPTDIR}/ovpns"
cp "${NAME}${FILEEXT}" "${SCRIPTDIR}/ovpns"
chown openvpncertbot:openvpncertbot "${SCRIPTDIR}/ovpns/${NAME}${FILEEXT}"

echo "ovpn created"

# Add a systemd timer to remove the certificate
{
    echo "[Unit]"
    echo "Description=remove certificate ${NAME}" 
    echo ""
    echo "[Timer]"
    echo "OnActiveSec=1w"
} >> /etc/systemd/system/${NAME}.timer

{
    echo "[Unit]"
    echo "Description=remove certificate ${NAME}"
    echo ""
    echo "[Service]"
    echo "Type=oneshot"
    echo "ExecStart=${SCRIPTDIR}/revoker.sh ${NAME} 0"
} >> /etc/systemd/system/${NAME}.service

systemctl start ${NAME}.timer
