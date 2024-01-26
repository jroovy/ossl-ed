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
  [ -k PRIVKEY,PUBKEY ] Derive password from an ECDH key pair
  [ -k PRIVKEY] Derive a password from your own private key (self encryption)
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
			exit
		fi
		operation='e'
		shift
	;;
	'-d')
		if [[ -n $operation ]]; then
			printf "Error: -e cannot be used with -d. Exiting.\n"
			exit
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
		opstyle='intmp'
		randID=$($sslPath rand -hex 8)
		shift
	;;
	'-p')
		if [[ -n $pass ]]; then
			printf "'-p' cannot be used with '-k'. Exiting.\n"
			exit
		fi
		pass="$2"
		shift 2
	;;
	'-k')
		if [[ -n $pass ]]; then
			printf "'-k' cannot be used with '-p'. Exiting.\n"
			exit
		fi

		# https://unix.stackexchange.com/a/164260
		IFS=','
		eccArgs=($2)
		privkey=${eccArgs[0]}
		pubkey=${eccArgs[1]}

		if [[ -n $pubkey ]]; then
			# https://jameshfisher.com/2017/04/14/openssl-ecc/
			pass=$($sslPath pkeyutl -derive -inkey "$privkey" -peerkey "$pubkey" | $sslPath enc -base64 -A)
		else
			# https://stackoverflow.com/a/54926249
			pass=$(\
				$sslPath ec -in "$privkey" -pubout 2> /dev/null \
				| $sslPath pkeyutl -derive -inkey "$privkey" -peerkey /dev/stdin \
				| $sslPath enc -base64 -A \
			)
		fi
		unset IFS eccArgs privkey pubkey
		shift 2
	;;
	'-f')
		passfile="$2"
		if ! [[ -f "$passfile" ]]; then
			printf "File '$passfile' not found. Aborting.\n"
			exit
		fi
		shift 2
	;;
	'-F')
		if [[ "${2##*.}" == 'txt' ]]; then
			passfile="${centralPassDir}/${2}"
		else
			passfile="${centralPassDir}/${2}.txt"
		fi
		if [[ "$2" == *'/'* ]]; then
			printf '%s\n' "Trying to specify directory to params file." "Use '-f' instead." "Aborting."
			exit
		fi
		if ! [[ -d "$centralPassDir" ]]; then
			mkdir -p "$centralPassDir"
		elif ! [[ -f "$passfile" ]]; then
			printf "Error: '${passfile}' does not exist. Aborting.\n"
			exit
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
		usetar='y'
		shift
	;;
	'-z')
		tar2own='y'
		shift
	;;
	'-c')
		cmptype="$2"
		case "$cmptype" in
			'bz2' | 'bzip2')
				cmpext='bz2'
				tarext='tbz2'
			;;
			# 'bz3' | 'bzip3')
			# 	cmpext='bz3'
			# 	tarext='tbz3'
			# ;;
			'gz' | 'gzip')
				cmpext='gz'
				tarext='tgz'
			;;
			'lz4')
				cmpext='lz4'
				tarext='tlz4'
			;;
			'lzo' | 'lzop')
				cmpext='lzo'
				tarext='tlzo'
			;;
			'xz')
				cmpext='xz'
				tarext='txz'
			;;
			'zst' | 'zstd')
				cmpext='zst'
				tarext='tzst'
			;;
			*)
				printf "Unknown compression algorithm '${cmptype}'. Exiting.\n"
				exit
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

tarcmp="Create & encrypt"
oslenc="Encrypt"

tardec="Decrypt & unpack"
osldec="Decrypt"

threads="$(nproc)"

# Functions

delete-temp-files() {
	set +o noglob
	if [[ $operation == 'e' ]]; then
		if [[ $opstyle == 'intmp' ]]; then
			rm "${tmpDir}/${randID}-"*"${tmpExt}"
		fi
		if [[ -z $usetar ]]; then
			rm "${out}${i1}."*"-osl"
		else
			rm "${out}.t"*"-osl"
		fi
	else
		if [[ $opstyle == 'intmp' ]]; then
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

passfile-assign-vars() {
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

passfile-get-params() {
	case "$pchoice" in
		'passfile-ram')
			# https://askubuntu.com/a/705131
			for i in ${datarray[@]:${startLine}:${endLine}}; do
				passfile-assign-vars
			done
		;;
		'passfile-sed')
			for i in ${datarray[@]}; do
				passfile-assign-vars
			done
		;;
	esac
	gen-ossl-flags
}

passfile-ram() {
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
	passfile-get-params
	unset startLine endLine
}

passfile-sed() {
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
	datarray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$passfile") )
	passfile-get-params
	unset startLine endLine datarray
}

osl-encrypt-in-ram() {
	$pchoice

	n=$(( n + 1 ))
	rcount=$(( rcount + 1 ))

	if [[ rcount -lt loop ]]; then
		$sslPath ${osslArgs[@]} \
		| osl-encrypt-in-ram
	else
		$sslPath ${osslArgs[@]} $b64osl
	fi
}

osl-decrypt-in-ram() {
	$pchoice

	n=$(( n - 1 ))
	rcount=$(( rcount + 1 ))
	
	if [[ rcount -gt 1 ]]; then
		unset b64osl
	fi
	if [[ rcount -lt loop ]]; then
		$sslPath ${osslArgs[@]} $b64osl \
		| osl-decrypt-in-ram
	else
		$sslPath ${osslArgs[@]}
	fi
}

osl-encrypt-in-tmp() {
	for (( rcount = 0; rcount < loop; n ++ )); do
		$pchoice
		if [[ rcount -eq 0 ]]; then
			$sslPath ${osslArgs[@]} \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}"
		elif ! [[ rcount -eq lastone ]]; then
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}" \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}"
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		else
			$sslPath ${osslArgs[@]} $b64osl \
				-in "${tmpDir}/${randID}-${rcount}${tmpExt}"
			rm "${tmpDir}/${randID}-${rcount}${tmpExt}"
		fi
		(( rcount ++ ))
	done
}

osl-decrypt-in-tmp() {
	for (( rcount = 0; rcount < loop; n -- )); do
		$pchoice
		if [[ rcount -eq 0 ]]; then
			$sslPath ${osslArgs[@]} $b64osl \
				-out "${tmpDir}/${randID}-$(( rcount + 1 ))${tmpExt}" 
		elif ! [[ rcount -eq lastone ]]; then
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
	if [[ loop -lt 2 || $opstyle == 'inram' ]]; then
		osl-encrypt-in-ram
	elif [[ $opstyle == 'intmp' ]]; then
		lastone=$(( loop - 1 ))
		osl-encrypt-in-tmp
	fi
}

osl-decrypt() {
	n=$(( loop - 1 ))
	rcount=0
	if [[ loop -lt 2 || $opstyle == 'inram' ]]; then
		osl-decrypt-in-ram
	elif [[ $opstyle == 'intmp' ]]; then
		lastone=$(( loop - 1 ))
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
	case "$cmptype" in
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
	case "$cmptype" in
		'')
			printf "$work $oslenc '$@'"
			if
				osl-encrypt > "${out}${i}.${b64}enc-osl"
			then
				printf "${clear}$success $oslenc '$@'\n"
			else
				printf "${clear}$fail $oslenc '$@'\n"
			fi
		;;
		*)
			printf "$work $oslenc '$@'"
			if
				data-compress | osl-encrypt > "${out}${i}.${b64}${cmpext}-osl"
			then
				printf "${clear}$success $oslenc '$@'\n"
			else
				printf "${clear}$fail $oslenc '$@'\n"
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
	| case "$cmptype" in
		'')
			printf "$work $tarcmp '${out}.tar'"
			if
				osl-encrypt > "${out}.${b64}tar-osl"
			then
				printf "${clear}$success $tarcmp '${out}.tar'\n"
			else
				printf "${clear}$fail $tarcmp '${out}.tar' \n"
			fi
		;;
		*)
			printf "$work $tarcmp '${out}.${tarext}'"
			if
				data-compress | osl-encrypt > "${out}.${b64}${tarext}-osl"
			then
				printf "${clear}$success $tarcmp '${out}.${tarext}'\n"
			else
				printf "${clear}$fail $tarcmp '${out}.${tarext}'\n"
			fi
		;;
	esac
}

decrypt-all() {
	# https://stackoverflow.com/questions/965053/extract-filename-and-extension-in-bash
	i1=${@%.*}
	i2=${@##*.}
	if [[ "$i2" == 'b64-'* ]]; then
		b64osl='-base64'
	else
		unset b64osl
	fi
	trap delete-temp-files SIGINT
	case "$i2" in
		*'tar-osl')
			printf "$work $tardec '$@'"
			if
				osl-decrypt | tar-unpack
			then
				printf "${clear}$success $tardec '$@'\n"
			else
				printf "${clear}$fail $tardec '$@'\n"
			fi
		;;
		*'t'*'z'*'-osl')
			printf "$work $tardec '$@'"
			if
				osl-decrypt | data-decompress | tar-unpack
			then
				printf "${clear}$success $tardec '$@'\n"
			else
				printf "${clear}$fail $tardec '$@'\n"
			fi
		;;
		*'enc-osl')
			printf "$work $osldec '$@'"
			if
				osl-decrypt > "${out}${i1}"
			then
				printf "${clear}$success $osldec '$@'\n"
			else
				printf "${clear}$fail $osldec '$@'\n"
			fi
		;;
		*)
			printf "$work $osldec '$@'"
			if
				osl-decrypt | data-decompress > "${out}${i1}"
			then
				printf "${clear}$success $osldec '$@'\n"
			else
				printf "${clear}$fail $osldec '$@'\n"
			fi
		;;
	esac < "$@"
}

# Check missing variables

if [[ -z $opstyle ]]; then
	opstyle='inram'
fi

if [[ -z $passfile ]]; then
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
	unset pchoice
else
	# https://stackoverflow.com/questions/6022384/bash-tool-to-get-nth-line-from-a-file
	pchk=$(sed '1q;d' "$passfile")

	if ! [[ "$pchk" == '[Cascade Encryption Parameters]' ]]; then
		printf "Error: first line of file must be '[Cascade Encryption Parameters]'. Aborting.\n"
		exit
	fi
	
	filetype=4
	cval=( $(sed -n "2,6p;6q" "$passfile") )
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
		pchoice='passfile-sed'
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
		pchoice='passfile-ram'
		datarray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$passfile") )
	fi
	
	unset i cval pchk
fi

# https://www.baeldung.com/linux/copy-directory-structure

# if [[ -z $usetar ]]; then
# 	if [[ -z $out ]]; then
# 		out='./'
# 	fi
# 	find "$@" -type d \
# 	| while read -r i; do
# 		mkdir -p "${out}/${i}"
# 	done
# elif [[ -z $out ]]; then
# 	if [[ $operation == 'e' ]]; then
# 		printf '%s\n' "Error: tar archive name not defined. Exiting." "Define name with -o (see -h)"
# 		exit 1
# 	else
# 		out='./'
# 	fi
# fi

if [[ $operation == 'e' ]]; then
	if [[ -z $out ]]; then
		if [[ $usetar == 'y' ]]; then
			printf '%s\n' "Error: tar archive name not defined. Exiting." "Define name with -o (see -h)"
			exit 1
		else
			out='./'
		fi
	fi
	mkdir -p "$out"
else
	if [[ -z $out ]]; then
		out='./'
	fi
	mkdir -p "$out"
	find "$@" -type d \
	| while read -r i; do
		mkdir -p "${out}/${i}"
	done
fi

# https://stackoverflow.com/questions/67563098/run-command-after-ctrlc-on-watch-command
# https://stackoverflow.com/questions/22558245/exclude-list-of-files-from-find
# https://unix.stackexchange.com/questions/15308/how-to-use-find-command-to-search-for-multiple-extensions
# https://stackoverflow.com/questions/11456403/stop-shell-wildcard-character-expansion

if [[ $operation == 'e' ]]; then
	set -o noglob
	if [[ -z $b64 ]]; then
		unset b64osl
	else
		b64osl='-base64'
	fi
	case "$usetar" in
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