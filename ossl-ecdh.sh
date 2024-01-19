#! /bin/bash

help_message() {
printf "Usage:
$0 <arguments>

Arguments:
[ -h ] Show this help
[ -l ] List all supported curves
[ -c CURVE,KEYNAME ] Generate an ECDH key pair
[ -d PRIVKEY,PUBKEY ] Generate a shared secret between a private and public key
"
}

ARGS=$(getopt -n openssl-ecdh -o c:d:lh -- "$@")
eval set -- "$ARGS"

while :
do case "$1" in
	'-c')
		# https://jameshfisher.com/2017/04/14/openssl-ecc/
		# https://unix.stackexchange.com/a/164260
		IFS=','
		eccArgs=($2)
		curve=${eccArgs[0]}
		keyname=${eccArgs[1]}
		unset IFS
		openssl ecparam -name "$curve" -genkey -out "${keyname}.priv"
		openssl ec -in "${keyname}.priv" -pubout -out "${keyname}.pub"
		shift 2
	;;
	'-d')
		IFS=','
		keyArgs=($2)
		privkey=${keyArgs[0]}
		pubkey=${keyArgs[1]}
		unset IFS
		openssl pkeyutl -derive -inkey "$privkey" -peerkey "$pubkey" \
		| openssl enc -base64 -A \
		&& printf '\n'
		shift 2
	;;
	'-l')
		openssl ecparam -list_curves
		exit
	;;
	'-h')
		help_message
		exit
	;;
	--)
		shift
		break
	;;
esac; done