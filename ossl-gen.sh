#!/usr/bin/env bash

sslPath='openssl'
centralPassDir="${HOME}/.config/ossl-ed"

help_msg() {
yellow='\033[0;93m'
reset='\033[0m'
printf "\nUsage:
$0 <options>

# Options marked in ${yellow}yellow${reset} are required
Options:
  ${yellow}[ -a ALGO ]${reset} Encryption algorithm
  ${yellow}[ -s HASH ]${reset} Password hash
  ${yellow}[ -i LO-HI ]${reset} Number range of password iterations
       Append 's' before LO-HI for static iteration,
       and replace LO-HI with a single NUMBER
  ${yellow}[ -c ROUNDS ]${reset} Number of encryption rounds
  ${yellow}[ -p LENGTH ]${reset} Length of generated passwords
       Append 's' before LENGTH for static password
  [ -k PRIVKEY,PUBKEY ] Use ECDH shared secret as password
  [ -t asip ] Choose which parameters are static
       a: algorithm, s: hash
       i: iterations, p: password
  [ -d aN|sN ] Randomize encryption algo or hash (overrides -a and -s)
    -da = random algo
    -ds = random hash
        a: 1 = AES, 2 = CAMELLIA, 3 = ARIA,
           4 = CHACHA20
        s: 1 = SHA512, 2 = BLAKE2B-512, 3 = SHA3-512,
           4 = WHIRLPOOL
  [ -o FILE ] Location to save output
  [ -n NAME ] Save output file to $centralPassDir (overrides -o)
              NAME should not include extension
  [ -f ] Generate faster, but less secure passwords
  [ -r ] Use /dev/random instead of /dev/urandom
  [ -h ] Show this help
  
Example:
$0 -a aes-256-cbc -s sha512 -i 1000-2000 -c 2 -p 64
$0 -da123 -ds123 -i s5000 -c 2 -p s64
\n"
}

if [[ -z $@ ]]; then
	help_msg
	exit
fi

mode=4
dynVals=( 'a' 'h' 'i' 'p' )

ARGS=$(getopt -n openssl-multigen -o a:s:i:c:p:k:d:o:n:frh -- "$@")
eval set -- "$ARGS"

while :
do case "$1" in
	'-a')
		algo="$2"
		# https://stackoverflow.com/questions/16860877/remove-an-element-from-a-bash-array
		(( mode -- ))
		dynVals=( "${dynVals[@]/a}" )
		statVals+=('a')
		algoLength=1
		shift 2
	;;
	'-s')
		hash="$2"
		(( mode -- ))
		dynVals=( "${dynVals[@]/h}" )
		statVals+=('h')
		hashLength=1
		shift 2
	;;
	'-i')
		if [[ "${2:0:1}" == 's' ]]; then
			(( mode -- ))
			dynVals=( "${dynVals[@]/i}" )
			statVals+=('i')
			is="${2:1}"
			iterval="${is}-${is}"
			unset is
		else
			dynIter=1
			iterval="$2"
		fi
		shift 2
	;;
	'-c')
		rounds="$2"
		shift 2
	;;
	'-p')
		if [[ "${2:0:1}" == 's' ]]; then
			(( mode -- ))
			dynVals=( "${dynVals[@]/p}" )
			statVals+=('p')
			length="${2:1}"
		else
			dynPass=1
			length="$2"
		fi
		if [[ length -gt 512 ]]; then
			printf '%s\n' "Warning: OpenSSL can only accept password lengths up to 512"
			length=512
		fi
		shift 2
	;;
	'-k')
		secret=$($sslPath pkeyutl -derive -inkey "${2%,*}" -peerkey "${2##*,}" | $sslPath enc -base64 -A)
		length=${#secret}
		dynVals=( "${dynVals[@]/p}" )
		statVals+=('p')
		(( mode -- ))
		shift 2
	;;
	'-d')
		# https://www.tutorialkart.com/bash-shell-scripting/bash-iterate-over-characters-in-string/#gsc.tab=0
		if [[ "${2:0:1}" == 'a' ]]; then
			for (( i = 1; i < ${#2}; i ++ )); do
				case "${2:${i}:1}" in
					'1')
						algo+=( aes-256-{cbc,cfb,ofb,ctr} )
					;;
					'2')
						algo+=( camellia-256-{cbc,cfb,ofb,ctr} )
					;;
					'3')
						algo+=( aria-256-{cbc,cfb,ofb,ctr} )
					;;
					'4')
						algo+=( chacha20 )
					;;
					*)
						printf "Unknown option '${2:${i}:1}'\n"
						exit
					;;
				esac
				algoLength=${#algo[@]}
			done
		elif [[ "${2:0:1}" == 's' ]]; then
			for (( i = 1; i < ${#2}; i ++ )); do
				case "${2:${i}:1}" in
					'1')
						hash+=( sha512 )
					;;
					'2')
						hash+=( blake2b512 )
					;;
					'3')
						hash+=( sha3-512 )
					;;
					'4')
						hash+=( whirlpool )
					;;
					*)
						printf "Unknown option '${2:${i}:1}'\n"
						exit
					;;
				esac
				hashLength=${#hash[@]}
			done
		fi
		shift 2
	;;
	'-o')
		output="$2"
		shift 2
	;;
	'-n')
		output="${centralPassDir}/${2}.txt"
		if ! [[ -d "$centralPassDir" ]]; then
			mkdir -p "$centralPassDir"
		elif [[ -f "$output" ]]; then
			printf "'$output' already exists, replace? (y/n) "
			read a
			if ! [[ $a == [Yy] ]]; then
				printf 'Exiting.\n'
				exit
			fi
			unset a
		fi
		shift 2
	;;
	'-f')
		genmode='fast'
		shift
	;;
	'-r')
		randomtype='/dev/random'
		shift
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

if [[ -z $algo ]]; then
	echo "Algorithm not defined. Exiting."
	exit
fi
if [[ -z $hash ]]; then
	echo "Hash not defined. Exiting."
	exit
fi
if [[ -z $iterval ]]; then
	echo "Password iterations not defined. Exiting."
	exit
fi
if [[ -z $rounds ]]; then
	echo "Password count not defined. Exiting."
	exit
fi
if [[ -z $length ]]; then
	echo "Password length not defined. Exiting."
	exit
fi
if [[ -z $genmode ]]; then
	genmode='secure'
fi
if [[ mode -gt 1 ]]; then
	printNewline=( 'printf' '\n' )
else
	printOne=( 'printf' '\n' )
fi
if [[ -z $randomtype ]]; then
	randomtype='/dev/urandom'
fi

gen-static() {
printf '%s\n' "[Cascade Encryption Parameters]" "0${rounds}"
for i in ${statVals[@]}; do
	case "$i" in
		'a')
			printf '%s\n' "1${algo[ $((RANDOM % algoLength)) ]}"
		;;
		'h')
			printf '%s\n' "2${hash[ $((RANDOM % hashLength)) ]}"
		;;
		'i')
			printf '%s\n' "3$(shuf -n 1 -i $iterval)"
		;;
		'p')
			if [[ -z $secret ]]; then
				printf '%s\n' "4$(cat $randomtype | tr -dc '[:graph:]' | head -c $length)"
			else
				printf '%s\n' "4$secret"
			fi
		;;
	esac
done
unset statVals
printf '%s' "==============================="
}

generate-file() {

gen-static

if [[ $genmode == 'secure' ]]; then
	for (( i = 0; i < rounds; i ++ )); do
		if [[ dynPass -eq 1 ]]; then
			pass=$(cat $randomtype | tr -dc '[:graph:]' | head -c $length)
		fi
		if [[ dynIter -eq 1 ]]; then
			iter=$(shuf -n 1 -i $iterval)
		fi
		for j in ${dynVals[@]}; do
			case "$j" in
				'a')
					printf '\n%s' "1${algo[ $((RANDOM % algoLength)) ]}"
				;;
				'h')
					printf '\n%s' "2${hash[ $((RANDOM % hashLength)) ]}"
				;;
				'i')
					printf '\n%s' "3${iter}"
				;;
				'p')
					printf '\n%s' "4${pass}"
				;;
			esac
		done
		${printNewline[@]}
	done
elif [[ $genmode == 'fast' ]]; then
		if [[ rounds -gt 10000 ]]; then
		prod=$(( rounds / 10000 ))
		remainder=$(( rounds % 10000 ))
		if [[ remainder -gt 0 ]]; then
			runs=$(( prod + 1 ))
		else
			runs="$prod"
		fi
		subruns=10000
	else
		runs=1
		prod=0
		remainder="$rounds"
	fi

	for (( runcount = 0; runcount < runs; runcount ++ )); do
		if [[ runcount -eq prod ]]; then
			subruns="$remainder"
		fi
		
		if [[ dynIter -eq 1 ]]; then
			iter=( $(shuf -r -n $subruns -i $iterval) )
		fi

		if [[ dynPass -eq 1 ]]; then
			pass=( $(cat $randomtype | tr -dc '[:graph:]' | head -c $(( length * subruns )) | fold -w $length) )
		fi

		for (( i = 0; i < subruns; i ++ )); do
			for j in ${dynVals[@]}; do
				case "$j" in
					'a')
						printf '\n%s' "1${algo[ $((RANDOM % algoLength)) ]}"
					;;
					'h')
						printf '\n%s' "2${hash[ $((RANDOM % hashLength)) ]}"
					;;
					'i')
						printf '\n%s' "3${iter[ $i ]}"
					;;
					'p')
						printf '\n%s' "4${pass[ $i ]}"
					;;
				esac
			done
			${printNewline[@]}
		done
	done
fi
${printOne[@]}

}

if [[ -z $output ]]; then
	generate-file
else
	generate-file > "$output"
fi