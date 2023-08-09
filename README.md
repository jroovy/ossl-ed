# ossl-ed
Bash script utility to encrypt files and folders using OpenSSL

## What each script does
### ossl-ed.sh
is the main encryption/decryption script.

Use this script for encrypting your files (and decrypting them as well).

### ossl-gen.sh
is used for generating cascading parameter files.

Cascading is encrypting a file multiple times to increase security.

### ossl-ecdh.sh
is used for generating ECDH private-public key pairs.

Key pairs are used for sharing passwords securely through insecure channels.

## Customizable variables
You can customize some variables in **ossl-ed.sh** and **ossl-gen.sh**

These variables are located between **#! /bin/bash** and **help_msg()**

## Usage instructions
Usage instructions/examples are included within the scripts.

Simply run any of the scripts with `-h` to read them.
