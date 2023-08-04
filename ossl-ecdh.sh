#! /bin/bash

# TODO: add option to encrypt private key

if [[ -z $@ ]]; then
	printf "script.sh <keycurve> <keyname>\n"
	printf "Type 'openssl ecparam -list_curves' to view key curves.\n"
	exit
fi

keycurve=${@:1:1}
keyname=${@:2:1}

openssl ecparam -name $keycurve -genkey -noout > ${keyname}.priv
printf "Created private key '${keyname}.priv'\n"
openssl ec -in ${keyname}.priv -pubout > ${keyname}.pub
printf "Created public key '${keyname}.pub'\n"