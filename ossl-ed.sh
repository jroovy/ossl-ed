#!/usr/bin/env bash

scriptName="${0##/*}"
sslPath="$(command -v openssl)"
tmpDir='/tmp'
centralPasswdDir="${HOME}/.local/share/ossl-ed"

helpMessage() {
echo "
$scriptName <options> file(s) folder(s) ...
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
  [ -F PARAM_NAME ] Read parameter file stored in $centralPasswdDir (overrides -f)
                    PARAM_NAME should not include file extension
  [ -a ALGO ] Encryption algorithm to use
  [ -s HASH ] Hash algorithm to use
  [ -i NUM ] Pasword hash iteration
  [ -w NUM ] Salt length of KDF
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

exampleMessage() {
echo "
## Parameter file:

The file should be similar to following format:
[Cascade Encryption Parameters]
0NUM
#1,2,3,4,5
===============================
ALGORITHM
HASH
ITERATIONS
SALT
PASSWORD

ALGORITHM
HASH
ITERATIONS
SALT
PASSWORD

...etc

## Example:

[Cascade Encryption Parameters]
02
#1,2,3,4,5
===============================
aes-256-cbc
sha512
10000
16
Password1

aes-256-cfb
sha512
20000
16
Password2


## Usage Examples:

# Encrypt
$scriptName -ep Passw0rd file1 folder2 file3* ...
$scriptName -ef params.txt file1 folder2 file3* ...
$scriptName -ea aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...

# Compress + Encrypt
$scriptName -ecxz -m3 -p Passw0rd file1 folder2 file3* ...
$scriptName -ecxz -m3 -f params.txt file1 folder2 file3* ...
$scriptName -ea aes-256-cbc -s sha512 -i 1000 -p Passw0rd -cgz -m3 file1 folder2 file3* ...
$scriptName -dp Passw0rd file1 folder2 file3* ...

# Tar + Encrypt
$scriptName -etp Passw0rd file1 folder2 file3* ...
$scriptName -etf params.txt file1 folder2 file3* ...
$scriptName -eta aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...

# Tar + Compress + Encrypt
$scriptName -etcxz -p Passw0rd -o ArchiveName file1 folder2 file3* ...
$scriptName -etcxz -f params.txt -o ArchiveName file1 folder2 file3* ...
$scriptName -eta aes-256-cbc -s sha512 -i 1000 -p Passw0rd -cgz -m3 file1 folder2 file3* ...
$scriptName -dp Passw0rd file1 folder2 file3* ...

# Decrypt (all supported file types)
$scriptName -df params.txt file1 folder2 file3* ...
$scriptName -dp Passw0rd archive.tar-osl
$scriptName -da aes-256-cbc -s sha512 -i 1000 -p Passw0rd file1 folder2 file3* ...
"
}

# DO NOT MODIFY IFS AND OIFS VARIABLES
OIFS="$IFS"

ARGS=$(getopt -n openssl-encrypt -o edr:bgp:k:f:F:a:s:i:w:tzc:m:o:jh -- "$@")
eval set -- "$ARGS"

while true; do
	case "$1" in
		'-e')
			if [[ -n $operationType ]]; then
				echo "Error: -d cannot be used with -e. Exiting."
				exit 1
			fi
			operationType='e'
			shift
		;;
		'-d')
			if [[ -n $operationType ]]; then
				echo "Error: -e cannot be used with -d. Exiting."
				exit 1
			fi
			operationType='d'
			shift
		;;
		'-r')
			if ! [[ ${2:0:1} == '.' ]]; then
				ext=".$2"
			fi
			if (( ${#matchExtensions[@]} == 0 )); then
				matchExtensions+=( '-name' "*$ext" )
			else
				matchExtensions+=( '-o' '-name' "*$ext" )
			fi
			unset ext
			shift 2
		;;
		'-b')
			b64='b64-'
			shift
		;;
		'-g')
			processingMode='tmp'
			randID=$($sslPath rand -hex 8)
			shift
		;;
		'-p')
			if [[ -n $pass ]]; then
				echo "'-p' cannot be used with '-k'. Exiting."
				exit 1
			fi
			pass="$2"
			shift 2
		;;
		'-k')
			if [[ -n $pass ]]; then
				echo "'-k' cannot be used with '-p'. Exiting."
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
			IFS="$OIFS"
			unset eccArgs privKey pubKey
			shift 2
		;;
		'-f')
			paramsFile="$2"
			if ! [[ -f "$paramsFile" ]]; then
				echo "File '$paramsFile' not found. Aborting."
				exit 1
			fi
			shift 2
		;;
		'-F')
			if [[ "${2##*.}" == 'txt' ]]; then
				paramsFile="${centralPasswdDir}/${2}"
			else
				paramsFile="${centralPasswdDir}/${2}.txt"
			fi
			if [[ "$2" == *'/'* ]]; then
				echo "Trying to specify directory to params file." "Use '-f' instead." "Aborting."
				exit
			fi
			if ! [[ -d "$centralPasswdDir" ]]; then
				mkdir -p "$centralPasswdDir"
			elif ! [[ -f "$paramsFile" ]]; then
				echo "Error: '${paramsFile}' does not exist. Aborting."
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
		'-w')
			salt="$2"
			shift 2
		;;
		'-t')
			useTar='y'
			shift
		;;
		'-z')
			extractTarToSeparateFolder='y'
			shift
		;;
		'-c')
			compressionType="$2"
			case "$compressionType" in
				'bz2' | 'bzip2')
					compressedExtension='bz2'
					tarExtension='tbz2'
				;;
				# 'bz3' | 'bzip3')
				# 	compressedExtension='bz3'
				# 	tarExtension='tbz3'
				# ;;
				'gz' | 'gzip')
					compressedExtension='gz'
					tarExtension='tgz'
				;;
				'lz4')
					compressedExtension='lz4'
					tarExtension='tlz4'
				;;
				'lzo' | 'lzop')
					compressedExtension='lzo'
					tarExtension='tlzo'
				;;
				'xz')
					compressedExtension='xz'
					tarExtension='txz'
				;;
				'zst' | 'zstd')
					compressedExtension='zst'
					tarExtension='tzst'
				;;
				*)
					echo "Unknown compression algorithm '${compressionType}'. Exiting."
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
			exampleMessage
			exit
		;;
		'-h')
			helpMessage
			exit
		;;
		--)
			shift
			break
		;;
	esac
done

if [[ -z $@ ]]; then
	helpMessage
	exit
fi

# Static parameters when encrypting/decrypting
staticFlags=( 'enc' "-${operationType}" '-salt' '-pbkdf2' )
tempExtension='.osltmp'

# Progress indicator text

# https://unix.stackexchange.com/questions/26576/how-to-delete-line-with-echo
clear='\r\033[2K'

# Color codes
# https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
reset='\033[0m'
red='\033[0;91m'
green='\033[0;92m'
cyan='\033[0;96m'

work="${cyan}[WORKING]${reset}"
success="${green}[SUCCESS]${reset}"
fail="${red}[FAILED]${reset}"

tarCompressMessage="Create & encrypt"
osslEncryptMessage="Encrypt"

tarUnpackMessage="Decrypt & unpack"
osslDecryptMessage="Decrypt"

# Set number of threads for compress/decompress
if [[ -z $THREADS ]]; then
	threads="$(nproc)"
else
	threads="$THREADS"
fi

# Functions

deleteTempFiles() {
	set +o noglob
	if [[ $operationType == 'e' ]]; then
		if [[ $processingMode == 'tmp' ]]; then
			rm "${tmpDir}/${randID}-"*"${tempExtension}"
		fi
		if [[ -z $useTar ]]; then
			rm "${out}${origFileName}."*"-osl"
		else
			rm "${out}.t"*"-osl"
		fi
	else
		if [[ $processingMode == 'tmp' ]]; then
			rm "${tmpDir}/${randID}-"*"${tempExtension}"
		fi
		if ! [[ "$fileExtension" == 't'*'-osl' ]]; then
			rm "${out}${tempFileName}"
		fi
	fi
	exit
}

setOsslFlags() {
	osslArgs=( ${staticFlags[@]} "-${algo}" "-saltlen" "$salt" "-md" "$hash" "-iter" "$iter" "-k" "$pass" )
}

assignParamsFromFile() {
	case "${orderArray[orderCount]}" in
		'1')
			algo="$i"
		;;
		'2')
			hash="$i"
		;;
		'3')
			iter="$i"
		;;
		'4')
			salt="$i"
		;;
		'5')
			pass="$i"
		;;
	esac
}

getParamsFromPasswdFile() {
	case "$parseMethod" in
		'loadParamsFileToRam')
			# https://askubuntu.com/a/705131
			for i in ${paramsArray[@]:${startLine}:${endLine}}; do
				assignParamsFromFile
				(( orderCount ++ ))
			done
		;;
		'readParamsFileWithSed')
			for i in ${paramsArray[@]}; do
				assignParamsFromFile
				(( orderCount ++ ))
			done
		;;
	esac
	unset orderCount
	setOsslFlags
}

loadParamsFileToRam() {
	case "$paramsFileType" in
		'0')
			startLine=0
			endLine=7
		;;
		'1')
			startLine=$parsingPosition
			endLine=1
		;;
		'2')
			startLine=$(( 2 * parsingPosition ))
			endLine=2
		;;
		'3')
			startLine=$(( 3 * parsingPosition ))
			endLine=3
		;;
		'4')
			startLine=$(( 4 * parsingPosition ))
			endLine=4
		;;
		'5')
			startLine=$(( 5 * parsingPosition ))
			endLine=5
		;;
	esac
	getParamsFromPasswdFile
	unset startLine endLine
}

readParamsFileWithSed() {
	case "$paramsFileType" in
		'0')
			startLine=2
			endLine=8
		;;
		'1')
			startLine=$(( parsingPosition + 9 ))
			endLine=$startLine
		;;
		'2')
			startLine=$(( (3 * parsingPosition) + 8 ))
			endLine=$(( startLine + 1 ))
		;;
		'3')
			startLine=$(( (4 * parsingPosition) + 7 ))
			endLine=$(( startLine + 2 ))
		;;
		'4')
			startLine=$(( (5 * parsingPosition) + 6 ))
			endLine=$(( startLine + 3 ))
		;;
		'5')
			startLine=$(( (6 * parsingPosition) + 5 ))
			endLine=$(( startLine + 4 ))
		;;
	esac
	paramsArray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$paramsFile") )
	getParamsFromPasswdFile
	unset startLine endLine paramsArray
}

encryptDataInRam() {
	$parseMethod

	(( parsingPosition ++ ))
	(( currentIteration ++ ))

	if (( currentIteration < totalIterations )); then
		$sslPath ${osslArgs[@]} \
		| encryptDataInRam
	else
		$sslPath ${osslArgs[@]} $base64Flag
	fi
}

decryptDataInRam() {
	$parseMethod

	(( parsingPosition -- ))
	(( currentIteration ++ ))
	
	if (( currentIteration > 1 )); then
		unset base64Flag
	fi
	if (( currentIteration < totalIterations )); then
		$sslPath ${osslArgs[@]} $base64Flag \
		| decryptDataInRam
	else
		$sslPath ${osslArgs[@]} $base64Flag
	fi
}

encryptDataInTmp() {
	for (( currentIteration = 0; currentIteration < totalIterations; parsingPosition ++ )); do
		$parseMethod
		if (( currentIteration == 0 )); then
			$sslPath ${osslArgs[@]} \
				-out "${tmpDir}/${randID}-$(( currentIteration + 1 ))${tempExtension}"
		elif (( currentIteration != lastOne )); then
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${currentIteration}${tempExtension}" \
				-out "${tmpDir}/${randID}-$(( currentIteration + 1 ))${tempExtension}"
			rm "${tmpDir}/${randID}-${currentIteration}${tempExtension}"
		else
			$sslPath ${osslArgs[@]} $base64Flag \
				-in "${tmpDir}/${randID}-${currentIteration}${tempExtension}"
			rm "${tmpDir}/${randID}-${currentIteration}${tempExtension}"
		fi
		(( currentIteration ++ ))
	done
}

decryptDataInTmp() {
	for (( currentIteration = 0; currentIteration < totalIterations; parsingPosition -- )); do
		$parseMethod
		if (( currentIteration == 0 )); then
			$sslPath ${osslArgs[@]} $base64Flag \
				-out "${tmpDir}/${randID}-$(( currentIteration + 1 ))${tempExtension}" 
		elif (( currentIteration != lastOne )); then
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${currentIteration}${tempExtension}" \
				-out "${tmpDir}/${randID}-$(( currentIteration + 1 ))${tempExtension}"
			rm "${tmpDir}/${randID}-${currentIteration}${tempExtension}"
		else
			$sslPath ${osslArgs[@]} \
				-in "${tmpDir}/${randID}-${currentIteration}${tempExtension}" 
			rm "${tmpDir}/${randID}-${currentIteration}${tempExtension}"
		fi
		(( currentIteration ++ ))
	done
}

osslEncrypt() {
	parsingPosition=0
	currentIteration=0
	if [[ totalIterations -lt 2 || $processingMode == 'ram' ]]; then
		encryptDataInRam
	elif [[ $processingMode == 'tmp' ]]; then
		lastOne=$(( totalIterations - 1 ))
		encryptDataInTmp
	fi
}

osslDecrypt() {
	parsingPosition=$(( totalIterations - 1 ))
	currentIteration=0
	if [[ totalIterations -lt 2 || $processingMode == 'ram' ]]; then
		decryptDataInRam
	elif [[ $processingMode == 'tmp' ]]; then
		lastOne=$(( totalIterations - 1 ))
		decryptDataInTmp
	fi
}

unpackTar() {
	if [[ -z $extractTarToSeparateFolder ]]; then
		tar -xf - -C "$out"
	else
		mkdir -p "${out}/${origFileName}"
		tar -xf - -C "${out}/${origFileName}"
	fi
}

compressData() {
	case "$compressionType" in
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

decompressData() {
	case "$fileExtension" in
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

encryptWithoutTar() {
	case "$compressionType" in
		'')
			echo -ne "$work $osslEncryptMessage '$1'"
			if
				osslEncrypt > "${out}${1}.${b64}enc-osl"
			then
				echo -e "${clear}$success $osslEncryptMessage '$1'"
			else
				echo -e "${clear}$fail $osslEncryptMessage '$1'"
			fi
		;;
		*)
			echo -ne "$work $osslEncryptMessage '$1'"
			if
				compressData | osslEncrypt > "${out}${1}.${b64}${compressedExtension}-osl"
			then
				echo -e "${clear}$success $osslEncryptMessage '$1'"
			else
				echo -e "${clear}$fail $osslEncryptMessage '$1'"
			fi
		;;
	esac < "$1"
}

tarThenEncrypt() {
	if (( ${#matchExtensions[@]} == 0 )); then
		tar -cf - "$@"
	else
		# https://stackoverflow.com/questions/18731603/how-to-tar-certain-file-types-in-all-subdirectories
		find "$@" -type f ${matchExtensions[@]} | tar -cf - -T -
	fi \
	| case "$compressionType" in
		'')
			echo -ne "$work $tarCompressMessage '${out}.tar'"
			if
				osslEncrypt > "${out}.${b64}tar-osl"
			then
				echo -e "${clear}$success $tarCompressMessage '${out}.tar'"
			else
				echo -e "${clear}$fail $tarCompressMessage '${out}.tar'"
			fi
		;;
		*)
			echo -ne "$work $tarCompressMessage '${out}.${tarExtension}'"
			if
				compressData | osslEncrypt > "${out}.${b64}${tarExtension}-osl"
			then
				echo -e "${clear}$success $tarCompressMessage '${out}.${tarExtension}'"
			else
				echo -e "${clear}$fail $tarCompressMessage '${out}.${tarExtension}'"
			fi
		;;
	esac
}

decryptInputFiles() {
	# https://stackoverflow.com/a/965069
	origFileName=${1%.*}
	fileExtension=${1##*.}
	tempFileName=${origFileName}.tmp
	if [[ "$fileExtension" == 'b64-'* ]]; then
		base64Flag='-base64'
	else
		unset base64Flag
	fi
	trap deleteTempFiles SIGINT
	case "$fileExtension" in
		*'tar-osl')
			echo -ne "$work $tarUnpackMessage '$1'"
			if
				osslDecrypt | unpackTar
			then
				echo -e "${clear}$success $tarUnpackMessage '$1'"
			else
				echo -e "${clear}$fail $tarUnpackMessage '$1'"
			fi
		;;
		*'t'*'z'*'-osl')
			echo -ne "$work $tarUnpackMessage '$1'"
			if
				osslDecrypt | decompressData | unpackTar
			then
				echo -e "${clear}$success $tarUnpackMessage '$1'"
			else
				echo -e "${clear}$fail $tarUnpackMessage '$1'"
			fi
		;;
		*'enc-osl')
			echo -ne "$work $osslDecryptMessage '$1'"
			if
				osslDecrypt > "${out}${tempFileName}"
			then
				echo -e "${clear}$success $osslDecryptMessage '$1'"
				mv "${out}${tempFileName}" "${out}${origFileName}"
			else
				echo -e "${clear}$fail $osslDecryptMessage '$1'"
				rm "${out}${tempFileName}"
			fi
		;;
		*)
			echo -ne "$work $osslDecryptMessage '$1'"
			if
				osslDecrypt | decompressData > "${out}${tempFileName}"
			then
				echo -e "${clear}$success $osslDecryptMessage '$1'"
				mv "${out}${tempFileName}" "${out}${origFileName}"
			else
				echo -e "${clear}$fail $osslDecryptMessage '$1'"
				rm "${out}${tempFileName}"
			fi
		;;
	esac < "$1"
}

# Check missing variables

if [[ -z $processingMode ]]; then
	processingMode='ram'
fi

if [[ -z $paramsFile ]]; then
	if [[ -z $pass ]]; then
		echo -n 'Using blank password, are you sure? (y/n) '
		read a
		if ! [[ "$a" == [yY] ]]; then
			echo 'Exiting.'
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
	if [[ -z $salt ]]; then
		salt='16'
	fi
	totalIterations=1
	setOsslFlags
	unset parseMethod
else
	# https://stackoverflow.com/questions/6022384/bash-tool-to-get-nth-line-from-a-file
	paramsFileHeader=$(sed '1q;d' "$paramsFile")

	if ! [[ "$paramsFileHeader" == '[Cascade Encryption Parameters]' ]]; then
		echo "Error: first line of file must be '[Cascade Encryption Parameters]'. Aborting."
		exit
	fi
	
	paramsFileType=5
	cascadeValue=( $(sed -n "2,8p;8q" "$paramsFile") )
	for i in ${cascadeValue[@]}; do
		case "${i:0:1}" in
			'0')
				totalIterations="${i:1}"
			;;
			'1')
				algo="${i:1}"
				(( paramsFileType -- ))
			;;
			'2')
				hash="${i:1}"
				(( paramsFileType -- ))
			;;
			'3')
				iter="${i:1}"
				(( paramsFileType -- ))
			;;
			'4')
				salt="${i:1}"
				(( paramsFileType -- ))
			;;
			'5')
				pass="${i:1}"
				(( paramsFileType -- ))
			;;
			'#')
				IFS=','
				orderArray=(${i:1})
				IFS="$OIFS"
			;;
			*)
				break
			;;
		esac
	done
	
	if (( totalIterations > 1000 )); then
		parseMethod='readParamsFileWithSed'
	else
		case "$paramsFileType" in
			'0')
				startLine=2
				endLine=8
			;;
			'1')
				startLine=9
				endLine=$(( totalIterations + startLine ))
			;;
			'2')
				startLine=8
				endLine=$(( (totalIterations * 3) + startLine ))
			;;
			'3')
				startLine=7
				endLine=$(( (totalIterations * 4) + startLine ))
			;;
			'4')
				startLine=6
				endLine=$(( (totalIterations * 5) + startLine ))
			;;
			'5')
				startLine=5
				endLine=$(( (totalIterations * 6) + startLine ))
			;;
		esac
		parseMethod='loadParamsFileToRam'
		paramsArray=( $(sed -n "${startLine},${endLine}p;${endLine}q" "$paramsFile") )
	fi
	
	unset i cascadeValue paramsFileHeader
fi

# https://www.baeldung.com/linux/copy-directory-structure

createDirTree() {
	find "$@" -type d \
	| while read -r i; do
		mkdir -p "${out}/${i}"
	done
}

if [[ $operationType == 'e' ]]; then
	if [[ -z $out ]]; then
		if [[ $useTar == 'y' ]]; then
			echo -e "Error: tar archive name not defined. Exiting.\nDefine name with -o (see -h)"
			exit 1
		else
			out='./'
		fi
	fi
	if [[ -n $useTar && $out == *'/'* ]]; then
		mkdir -p "${out%/*}"
	elif [[ -z $useTar ]]; then
		out+='/'
		createDirTree "$@"
	fi
else
	if [[ -z $out ]]; then
		out='./'
		createDirTree "$@"
	else
		out+='/'
		createDirTree "$@"
		mkdir -p "$out"
	fi
fi

# https://stackoverflow.com/questions/67563098/run-command-after-ctrlc-on-watch-command
# https://stackoverflow.com/questions/22558245/exclude-list-of-files-from-find
# https://unix.stackexchange.com/questions/15308/how-to-use-find-command-to-search-for-multiple-extensions
# https://stackoverflow.com/questions/11456403/stop-shell-wildcard-character-expansion

if [[ $operationType == 'e' ]]; then
	set -o noglob
	if [[ -z $b64 ]]; then
		unset base64Flag
	else
		base64Flag='-base64'
	fi
	case "$useTar" in
		'y')
			trap deleteTempFiles SIGINT
			tarThenEncrypt "$@"
		;;
		*)
			find "$@" -type f ! -name '*-osl' ${matchExtensions[@]} \
			| while read -r i; do
				origFileName="$i"
				trap deleteTempFiles SIGINT
				encryptWithoutTar "$i"
			done
		;;
	esac
elif [[ $operationType == 'd' ]]; then
	find "$@" -type f -name '*-osl' \
	| while read -r i; do
		decryptInputFiles "$i"
	done
fi
