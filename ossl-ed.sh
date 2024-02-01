#!/usr/bin/env bash

sslPath='openssl'
tmpDir='/tmp'
centralPassDir="${HOME}/.config/ossl-ed"

help_msg() {
printf "
$0 <options> file(s) folder(s) ...
Options:
  [ -e ] Encrypt file(s)
  [ -d ] Decrypt file(s)
  [ -r .EXT ] Only process file(s) with extension .EXT (can be used multiple times)
  [ -b ] Encode output file in Base64
  [ -g ] Process file in $tmpDir instead of pipes
  [ -p PASS ] Password for encryption/decryption
  [ -k privKey,pubKey ] Derive password from an ECDH key pair
  [ -k privKey] Derive a password from your own private key (self encryption)
  [ -f PARAMFILE ] File containing parameters (see -j)
  [ -F PARAM_NAME ] Read parameter file stored in $centralPassDir (overrides -f)
                    PARAM_NAME should not include file extension
  [ -a ALGO ] Encryption algorithm to use
  [ -s HASH ] Hash algorithm to use
  [ -i NUM ] Pasword hash iteration
  [ -t ] Compress file(s) into tar archive
  [ -z ] Extract tar archives into separate folders
  [ -c COMPRESSION ] Compress file(s)
       bzip2, gzip, lz4
       lzop, xz, zstd
  [ -mN ] Set compression level to N number
     -m0: fastest, no compression
     -m9: slowest, best compression
     Some algorithms can go beyond 9 (eg. zstd)
  [ -o DIR ] Set output directory to DIR
             Set output to FILE if using -t
             When using -t, FILE should not include extension
  [ -j ] Show usage examples
  [ -h ] Show this help message
  
"
}

example_msg() {
printf "
## Parameter file:

The file should be in the following format:
[Cascade Encryption Parameters]
0NUM
===============================
1ALGORITHM
2HASH
3ITERATIONS
4PASSWORD

1ALGORITHM
2HASH
3ITERATIONS
4PASSWORD

...etc

## Example:

[Cascade Encryption Parameters]
02
===============================
1aes-256-cbc
2sha512
310000
4Password1

1aes-256-cbc
2sha512
320000
4Password2


## Usage Examples:

# Encrypt
$0 -ep Passw0rd file1 folder2 file3* ...
$0 -ef params.txt file1 folder2 file3* ...
$0 -ea aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...

# Compress + Encrypt
$0 -ecxz -m3 -p Passw0rd file1 folder2 file3* ...
$0 -ecxz -m3 -f params.txt file1 folder2 file3* ...
$0 -ea aes-256-cbc -s sha512 -i 1000 -p Passw0rd -cgz -m3 file1 folder2 file3* ...
$0 -dp Passw0rd file1 folder2 file3* ...

# Tar + Encrypt
$0 -etp Passw0rd file1 folder2 file3* ...
$0 -etf params.txt file1 folder2 file3* ...
$0 -eta aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...

# Tar + Compress + Encrypt
$0 -etcxz -p Passw0rd -o ArchiveName file1 folder2 file3* ...
$0 -etcxz -f params.txt -o ArchiveName file1 folder2 file3* ...
$0 -eta aes-256-cbc -s sha512 -i 1000 -p Passw0rd -cgz -m3 file1 folder2 file3* ...
$0 -dp Passw0rd file1 folder2 file3* ...

# Decrypt (all supported file types)
$0 -df params.txt file1 folder2 file3* ...
$0 -dp Passw0rd archive.tar-osl
$0 -da aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...

"
}

ARGS=$(getopt -n openssl-encrypt -o edr:bgp:k:f:F:a:s:i:tzc:m:o:jh -- "$@")
eval set -- "$ARGS"

while :
do case "$1" in
	'-e')
		if [[ -n $operation ]]; then
			printf "Error: -d cannot be used with -e. Exiting.\n"
			exit 1
		fi
		operation='e'
		shift
	;;
	'-d')
		if [[ -n $operation ]]; then
			printf "Error: -e cannot be used with -d. Exiting.\n"
			exit 1
		fi
		operation='d'
		shift
	;;
	'-r')
		if [[ ${#recurVal[@]} -eq 0 ]]; then
			recurVal+=( '-name' "*$2" )
		else
			recurVal+=( '-o' '-name' "*$2" )
		fi
		shift 2
	;;
	'-b')
		b64='b64-'
		shift
	;;
	'-g')
		operationType='intmp'
		randID=$($sslPath rand -hex 8)
		shift
	;;
	'-p')
		if [[ -n $pass ]]; then
			printf "'-p' cannot be used with '-k'. Exiting.\n"
			exit 1
		fi
		pass="$2"
		shift 2
	;;
	'-k')
		if [[ -n $pass ]]; then
			printf "'-k' cannot be used with '-p'. Exiting.\n"
			exit 1
		fi

		# https://unix.stackexchange.com/a/164260
		IFS=','
		eccArgs=($2)
		privKey=${eccArgs[0]}
		pubKey=${eccArgs[1]}

		if [[ -n $pubKey ]]; then
			# https://jameshfisher.com/2017/04/14/openssl-ecc/
			pass=$($sslPath pkeyutl -derive -inkey "$privKey" -peerkey "$pubKey" | $sslPath enc -base64 -A)
		else
			# https://stackoverflow.com/a/54926249
			pass=$(\
				$sslPath ec -in "$privKey" -pubout 2> /dev/null \
				| $sslPath pkeyutl -derive -inkey "$privKey" -peerkey /dev/stdin \
				| $sslPath enc -base64 -A \
			)
		fi
		unset IFS eccArgs privKey pubKey
		shift 2
	;;
	'-f')
		passFile="$2"
		if ! [[ -f "$passFile" ]]; then
			printf "File '$passFile' not found. Aborting.\n"
			exit 1
		fi
		shift 2
	;;
	'-F')
		if [[ "${2##*.}" == 'txt' ]]; then
			passFile="${centralPassDir}/${2}"
		else
			passFile="${centralPassDir}/${2}.txt"
		fi
		if [[ "$2" == *'/'* ]]; then
			printf '%s\n' "Trying to specify directory to params file." "Use '-f' instead." "Aborting."
			exit
		fi
		if ! [[ -d "$centralPassDir" ]]; then
			mkdir -p "$centralPassDir"
		elif ! [[ -f "$passFile" ]]; then
			printf "Error: '${passFile}' does not exist. Aborting.\n"
			exit 1
		fi
		shift 2
	;;
	'-a')
		algo="$2"
		shift 2
	;;
	'-s')
		hash="$2"
		shift 2
	;;
	'-i')
		iter="$2"
		shift 2
	;;
	'-t')
		useTar='y'
		shift
	;;
	'-z')
		tar2own='y'
		shift
	;;
	'-c')
		cmpType="$2"
		case "$cmpType" in
			'bz2' | 'bzip2')
				cmpExt='bz2'
				tarExt='tbz2'
			;;
			# 'bz3' | 'bzip3')
			# 	cmpExt='bz3'
			# 	tarExt='tbz3'
			# ;;
			'gz' | 'gzip')
				cmpExt='gz'
				tarExt='tgz'
			;;
			'lz4')
				cmpExt='lz4'
				tarExt='tlz4'
			;;
			'lzo' | 'lzop')
				cmpExt='lzo'
				tarExt='tlzo'
			;;
			'xz')
				cmpExt='xz'
				tarExt='txz'
			;;
			'zst' | 'zstd')
				cmpExt='zst'
				tarExt='tzst'
			;;
			*)
				printf "Unknown compression algorithm '${cmpType}'. Exiting.\n"
				exit 1
			;;
		esac
		shift 2
	;;
	'-m')
		complvl="-${2}"
		shift 2
	;;
	'-o')
		out="${2}"
		shift 2
	;;
	'-j')
		example_msg
		exit
	;;
	'-h')
		help_msg
		exit
	;;
	--)
		shift
		break
	;;
esac; done

if [[ -z $@ ]]; then
	help_msg
	exit
fi

# Progress indicator text

staticVals=( 'enc' "-${operation}" '-salt' '-pbkdf2' )
tmpExt='.osltmp'

# https://unix.stackexchange.com/questions/26576/how-to-delete-line-with-echo
clear='\r\033[2K'

# Color codes
reset='\033[0m'
red='\033[0;91m'
green='\033[0;92m'
cyan='\033[0;96m'

work="${cyan}[WORKING]${reset}"
success="${green}[SUCCESS]${reset}"
fail="${red}[FAILED]${reset}"

tarCmp="Create & encrypt"
oslEnc="Encrypt"

tarDec="Decrypt & unpack"
oslDec="Decrypt"

threads="$(nproc)"

# Functions

delete-temp-files() {
	set +o noglob
	if [[ $operation == 'e' ]]; then
		if [[ $operationType == 'intmp' ]]; then
			rm "${tmpDir}/${randID}-"*"${tmpExt}"
		fi
		if [[ -z $useTar ]]; then
			rm "${out}${i1}."*"-osl"
		else
			rm "${out}.t"*"-osl"
		fi
	else
		if [[ $operationType == 'intmp' ]]; then
			rm "${tmpDir}/${randID}-"*"${tmpExt}"
		fi
		if ! [[ "$i2" == 't'*'-osl' ]]; then
			rm "${out}${i1}"
		fi
	fi
	exit
}

gen-ossl-flags() {
	osslArgs=( ${staticVals[@]} "-${algo}" "-md" "$hash" "-iter" "$iter" "-k" "$pass" )
}

passFile-assign-vars() {
	case "${i:0:1}" in
		'1')
			algo="${i:1}"
		;;
		'2')
			hash="${i:1}"
		;;
		'3')
			iter="${i:1}"
		;;
		'4')
			pass="${i:1}"
		;;
	esac
}

passFile-get-params() {
	case "$paramChoice" in
		'passFile-ram')
			# https://askubuntu.com/a/705131
			for i in ${dataArray[@]:${startLine}:${endLine}}; do
				passFile-assign-vars
			done
		;;
		'passFile-sed')
			for i in ${dataArray[@]}; do
				passFile-assign-vars
			done
		;;
	esac
	gen-ossl-flags
}

passFile-ram() {
	case "$filetype" in
		'0')
			startLine=0
			endLine=5
		;;
		'1')
			startLine=$n
			endLine=1
		;;
		'2')
			startLine=$(( 2 * n ))
			endLine=2
		;;
		'3')
			startLine=$(( 3 * n ))
			endLine=3
		;;
		'4')
			startLine=$(( 4 * n ))
			endLine=4
		;;
	esac
	passFile-get-params
	unset startLine endLine
}

passFile-sed() {
	case "$filetype" in
		'0')
			startLine=2
			endLine=6
		;;
		'1')
			startLine=$(( n + 7 ))
			endLine=$startLine
		;;
		'2')
			startLine=$(( (3 * n) + 6 ))
			endLine=$(( startLine + 1 ))
		;;
		'3')
			startLine=$(( (4 * n) + 5 ))
			endLine=$(( startLine + 2 ))
		;;
		'4')
			startLine=$(( (5 * n) + 4 ))
			endLine=$(( startLine + 3 ))
		;;
	esac
	dataArray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$passFile") )
	passFile-get-params
	unset startLine endLine dataArray
}

osl-encrypt-in-ram() {
	$paramChoice

	(( n ++ ))
	(( rcount ++ ))

	if [[ rcount -lt loop ]]; then
		$sslPath ${osslArgs[@]} \
		| osl-encrypt-in-ram
	else
		$sslPath ${osslArgs[@]} $base64Flag
	fi
}

osl-decrypt-in-ram() {
	$paramChoice

	(( n -- ))
	(( rcount ++ ))
	
	if [[ rcount -gt 1 ]]; then
		unset base64Flag
	fi
	if [[ rcount -lt loop ]]; then
		$sslPath ${osslArgs[@]} $base64Flag \
		| osl-decrypt-in-ram
	else
		$sslPath ${osslArgs[@]}
	fi
}

osl-encrypt-in-tmp() {
	for (( rcount = 0; rcount < loop; n ++ )); do
		$paramChoice
		if [[ rcount -eq 0 ]]; then
			$sslPath ${osslArgs[@]} \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}"
		elif ! [[ rcount -eq lastOne ]]; then
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}" \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}"
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		else
			$sslPath ${osslArgs[@]} $base64Flag \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}"
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		fi
		(( rcount ++ ))
	done
}

osl-decrypt-in-tmp() {
	for (( rcount = 0; rcount < loop; n -- )); do
		$paramChoice
		if [[ rcount -eq 0 ]]; then
			$sslPath ${osslArgs[@]} $base64Flag \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}" 
		elif ! [[ rcount -eq lastOne ]]; then
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}" \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}"
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		else
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}" 
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		fi
		(( rcount ++ ))
	done
}

osl-encrypt() {
	n=0
	rcount=0
	if [[ loop -lt 2 || $operationType == 'inram' ]]; then
		osl-encrypt-in-ram
	elif [[ $operationType == 'intmp' ]]; then
		lastOne=$(( loop - 1 ))
		osl-encrypt-in-tmp
	fi
}

osl-decrypt() {
	n=$(( loop - 1 ))
	rcount=0
	if [[ loop -lt 2 || $operationType == 'inram' ]]; then
		osl-decrypt-in-ram
	elif [[ $operationType == 'intmp' ]]; then
		lastOne=$(( loop - 1 ))
		osl-decrypt-in-tmp
	fi
}

tar-unpack() {
	if [[ -z $tar2own ]]; then
		tar -xf - -C "$out"
	else
		mkdir -p "${out}/${i1}"
		tar -xf - -C "${out}/${i1}"
	fi
}

data-compress() {
	case "$cmpType" in
		'bz2' | 'bzip2')
			bzip2 \
			--quiet \
			--compress \
			--keep \
			--stdout \
			$complvl
		;;
		# 'bz3' | 'bzip3')
		# 	if [[ -z $complvl ]]; then
		# 		complvl='-16'
		# 	fi
		# 	bzip3 \
		# 	--encode \
		# 	--keep \
		# 	--stdout \
		# 	--jobs=${threads} \
		# 	--block=${complvl:1}
		# ;;
		'gz' | 'gzip')
			gzip \
			--quiet \
			--stdout \
			--keep \
			$complvl
		;;
		'lz4')
			lz4 \
			-z \
			-c \
			-k \
			$complvl
		;;
		'lzo' | 'lzop')
			lzop \
			-q \
			-c \
			$complvl
		;;
		'xz')
			xz \
			--quiet \
			--no-warn \
			--compress \
			--keep \
			--stdout \
			--threads=${threads} \
			$complvl
		;;
		'zst' | 'zstd')
			zstd \
			--quiet \
			--keep \
			--stdout \
			--ultra \
			-T${threads} \
			$complvl \
			-
		;;
	esac
}

data-decompress() {
	case "$i2" in
		*'bz2'*)
			bzip2 \
			--quiet \
			--decompress \
			--keep \
			--stdout
		;;
		# *'bz3'*)
		# 	bzip3 \
		# 	--decode \
		# 	--keep \
		# 	--stdout \
		# 	--jobs=${threads}
		# ;;
		*'gz'*)
			gzip \
			--quiet \
			--decompress \
			--stdout \
			--keep
		;;
		*'lz4'*)
			lz4 \
			-d \
			-c \
			-k
		;;
		*'lzo'*)
			lzop \
			-q \
			-d \
			-c
		;;
		*'xz'*)
			xz \
			--quiet \
			--no-warn \
			--decompress \
			--keep \
			--stdout \
			--threads=${threads}
		;;
		*'zst'*)
			zstd \
			--quiet \
			--decompress \
			--keep \
			--stdout \
			-T${threads} \
			-
		;;
	esac
}

encrypt-notar() {
	case "$cmpType" in
		'')
			printf "$work $oslEnc '$@'"
			if
				osl-encrypt > "${out}${i}.${b64}enc-osl"
			then
				printf "${clear}$success $oslEnc '$@'\n"
			else
				printf "${clear}$fail $oslEnc '$@'\n"
			fi
		;;
		*)
			printf "$work $oslEnc '$@'"
			if
				data-compress | osl-encrypt > "${out}${i}.${b64}${cmpExt}-osl"
			then
				printf "${clear}$success $oslEnc '$@'\n"
			else
				printf "${clear}$fail $oslEnc '$@'\n"
			fi
		;;
	esac < "$@"
}

encrypt-tar() {
	if [[ ${#recurVal[@]} -eq 0 ]]; then
		tar -cf - "$@"
	else
		# https://stackoverflow.com/questions/18731603/how-to-tar-certain-file-types-in-all-subdirectories
		find "$@" -type f ${recurVal[@]} | tar -cf - -T -
	fi \
	| case "$cmpType" in
		'')
			printf "$work $tarCmp '${out}.tar'"
			if
				osl-encrypt > "${out}.${b64}tar-osl"
			then
				printf "${clear}$success $tarCmp '${out}.tar'\n"
			else
				printf "${clear}$fail $tarCmp '${out}.tar' \n"
			fi
		;;
		*)
			printf "$work $tarCmp '${out}.${tarExt}'"
			if
				data-compress | osl-encrypt > "${out}.${b64}${tarExt}-osl"
			then
				printf "${clear}$success $tarCmp '${out}.${tarExt}'\n"
			else
				printf "${clear}$fail $tarCmp '${out}.${tarExt}'\n"
			fi
		;;
	esac
}

decrypt-all() {
	# https://stackoverflow.com/questions/965053/extract-filename-and-extension-in-bash
	i1=${@%.*}
	i2=${@##*.}
	if [[ "$i2" == 'b64-'* ]]; then
		base64Flag='-base64'
	else
		unset base64Flag
	fi
	trap delete-temp-files SIGINT
	case "$i2" in
		*'tar-osl')
			printf "$work $tarDec '$@'"
			if
				osl-decrypt | tar-unpack
			then
				printf "${clear}$success $tarDec '$@'\n"
			else
				printf "${clear}$fail $tarDec '$@'\n"
			fi
		;;
		*'t'*'z'*'-osl')
			printf "$work $tarDec '$@'"
			if
				osl-decrypt | data-decompress | tar-unpack
			then
				printf "${clear}$success $tarDec '$@'\n"
			else
				printf "${clear}$fail $tarDec '$@'\n"
			fi
		;;
		*'enc-osl')
			printf "$work $oslDec '$@'"
			if
				osl-decrypt > "${out}${i1}"
			then
				printf "${clear}$success $oslDec '$@'\n"
			else
				printf "${clear}$fail $oslDec '$@'\n"
			fi
		;;
		*)
			printf "$work $oslDec '$@'"
			if
				osl-decrypt | data-decompress > "${out}${i1}"
			then
				printf "${clear}$success $oslDec '$@'\n"
			else
				printf "${clear}$fail $oslDec '$@'\n"
			fi
		;;
	esac < "$@"
}

# Check missing variables

if [[ -z $operationType ]]; then
	operationType='inram'
fi

if [[ -z $passFile ]]; then
	if [[ -z $pass ]]; then
		printf 'Using blank password, are you sure? (y/n) '
		read a
		if ! [[ "$a" == [yY] ]]; then
			printf 'Exiting.\n'
			exit
		else
			unset a
		fi
	fi
	if [[ -z $algo ]]; then
		algo='aes-256-cfb'
	fi
	if [[ -z $hash ]]; then
		hash='sha512'
	fi
	if [[ -z $iter ]]; then
		iter='10000'
	fi
	loop=1
	gen-ossl-flags
	unset paramChoice
else
	# https://stackoverflow.com/questions/6022384/bash-tool-to-get-nth-line-from-a-file
	pchk=$(sed '1q;d' "$passFile")

	if ! [[ "$pchk" == '[Cascade Encryption Parameters]' ]]; then
		printf "Error: first line of file must be '[Cascade Encryption Parameters]'. Aborting.\n"
		exit
	fi
	
	filetype=4
	cval=( $(sed -n "2,6p;6q" "$passFile") )
	for i in ${cval[@]}; do
		case "${i:0:1}" in
			'0')
				loop="${i:1}"
			;;
			'1')
				algo="${i:1}"
				(( filetype -- ))
			;;
			'2')
				hash="${i:1}"
				(( filetype -- ))
			;;
			'3')
				iter="${i:1}"
				(( filetype -- ))
			;;
			'4')
				pass="${i:1}"
				(( filetype -- ))
			;;
			*)
				break
			;;
		esac
	done
	
	if [[ loop -gt 1000 ]]; then
		paramChoice='passFile-sed'
	else
		case "$filetype" in
			'0')
				startLine=2
				endLine=6
			;;
			'1')
				startLine=7
				endLine=$(( loop + startLine ))
			;;
			'2')
				startLine=6
				endLine=$(( (loop * 3) + startLine ))
			;;
			'3')
				startLine=5
				endLine=$(( (loop * 4) + startLine ))
			;;
			'4')
				startLine=4
				endLine=$(( (loop * 5) + startLine ))
			;;
		esac
		paramChoice='passFile-ram'
		dataArray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$passFile") )
	fi
	
	unset i cval pchk
fi

# https://www.baeldung.com/linux/copy-directory-structure

createDirTree() {
	find "$@" -type d \
	| while read -r i; do
		mkdir -p "${out}/${i}"
	done
}

if [[ $operation == 'e' ]]; then
	if [[ -z $out ]]; then
		if [[ $useTar == 'y' ]]; then
			printf '%s\n' "Error: tar archive name not defined. Exiting." "Define name with -o (see -h)"
			exit 1
		else
			out='./'
		fi
	fi
	if [[ -n $useTar && $out == *'/'* ]]; then
		mkdir -p "${out%/*}"
	elif [[ -z $useTar ]]; then
		out+='/'
		mkdir -p "$out"
		createDirTree "$@"
	fi
else
	if [[ -z $out ]]; then
		out='./'
	else
		out+='/'
	fi
	mkdir -p "$out"
	createDirTree "$@"
fi

# https://stackoverflow.com/questions/67563098/run-command-after-ctrlc-on-watch-command
# https://stackoverflow.com/questions/22558245/exclude-list-of-files-from-find
# https://unix.stackexchange.com/questions/15308/how-to-use-find-command-to-search-for-multiple-extensions
# https://stackoverflow.com/questions/11456403/stop-shell-wildcard-character-expansion

if [[ $operation == 'e' ]]; then
	set -o noglob
	if [[ -z $b64 ]]; then
		unset base64Flag
	else
		base64Flag='-base64'
	fi
	case "$useTar" in
		'')
			find "$@" -type f ! -name '*-osl' ${recurVal[@]} \
			| while read -r i; do
				i1="$i"
				trap delete-temp-files SIGINT
				encrypt-notar "$i"
			done
		;;
		'y')
			trap delete-temp-files SIGINT
			encrypt-tar "$@"
		;;
	esac
elif [[ $operation == 'd' ]]; then
	find "$@" -type f -name '*-osl' \
	| while read -r i; do
        decrypt-all "$i"
	done
fi