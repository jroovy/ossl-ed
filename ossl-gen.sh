#!/usr/bin/env bash

sslPath='openssl'
centralPassDir="${HOME}/.config/ossl-ed"

help_msg() {
# yellow='\033[0;93m'
# reset='\033[0m'
printf "\nUsage:
$0 <options>

Options:
  [ -a ALGO ] Encryption algorithm
  [ -s HASH ] Password hash
  [ -i LO-HI ] Number range of password iterations
       Replace LO-HI with a single number for static iteration
  [ -c ROUNDS ] Number of encryption rounds
  [ -p LENGTH ] Length of generated passwords
       Append 's' before LENGTH for static password
  [ -e LO-HI ] Number range of salt length
       Replace LO-HI with a single number for static iteration
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

dynamicVals=( 'a' 'h' 'i' 's' 'p' )
mode=${#dynamicVals[@]}

ARGS=$(getopt -n openssl-multigen -o a:e:s:i:c:p:k:d:o:n:frh -- "$@")
eval set -- "$ARGS"

while :
do case "$1" in
	'-a')
		algo="$2"
		# https://stackoverflow.com/questions/16860877/remove-an-element-from-a-bash-array
		dynamicVals=( "${dynamicVals[@]/a}" )
		staticVals+=('a')
		algoLength=1
		(( mode -- ))
		shift 2
	;;
	'-e')
		if [[ "$2" == *'-'* ]]; then
			dynamicSalt=1
			saltVal="$2"
		else
			dynamicVals=( "${dynamicVals[@]/s}" )
			staticVals+=('s')
			is="$2"
			saltVal="${is}-${is}"
			unset is
			(( mode -- ))
		fi
		shift 2
	;;
	'-s')
		hash="$2"
		dynamicVals=( "${dynamicVals[@]/h}" )
		staticVals+=('h')
		hashLength=1
		(( mode -- ))
		shift 2
	;;
	'-i')
		if [[ "$2" == *'-'* ]]; then
			dynamicIteration=1
			iterVal="$2"
		else
			dynamicVals=( "${dynamicVals[@]/i}" )
			staticVals+=('i')
			is="$2"
			iterVal="${is}-${is}"
			unset is
			(( mode -- ))
		fi
		shift 2
	;;
	'-c')
		rounds="$2"
		shift 2
	;;
	'-p')
		if [[ "${2:0:1}" == 's' ]]; then
			length="${2:1}"
			dynamicVals=( "${dynamicVals[@]/p}" )
			staticVals+=('p')
			(( mode -- ))
		else
			dynamicPass=1
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
		dynamicVals=( "${dynamicVals[@]/p}" )
		staticVals+=('p')
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
	algo='aes-256-cfb'
	dynamicVals=( "${dynamicVals[@]/a}" )
	staticVals+=('a')
	algoLength=1
	(( mode -- ))
fi
if [[ -z $hash ]]; then
	hash="sha512"
	dynamicVals=( "${dynamicVals[@]/h}" )
	staticVals+=('h')
	hashLength=1
	(( mode -- ))
fi
if [[ -z $iterVal ]]; then
	dynamicVals=( "${dynamicVals[@]/i}" )
	staticVals+=('i')
	iterVal="10000-10000"
	unset is
	(( mode -- ))
fi
if [[ -z $rounds ]]; then
	rounds=1
fi
if [[ -z $saltVal ]]; then
	dynamicVals=( "${dynamicVals[@]/s}" )
	staticVals+=('s')
	saltVal='16-16'
	(( mode -- ))
fi
if [[ -z $length ]]; then
	length=40
	dynamicPass=1
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
for i in ${staticVals[@]}; do
	case "$i" in
		'a')
			printf '%s\n' "1${algo[ $((RANDOM % algoLength)) ]}"
		;;
		'h')
			printf '%s\n' "2${hash[ $((RANDOM % hashLength)) ]}"
		;;
		'i')
			printf '%s\n' "3$(shuf -n 1 -i $iterVal)"
		;;
		's')
			printf '%s\n' "4$(shuf -n 1 -i $saltVal)"
		;;
		'p')
			if [[ -z $secret ]]; then
				printf '%s\n' "5$(cat $randomtype | tr -dc '[:graph:]' | head -c $length)"
			else
				printf '%s\n' "5${secret}"
			fi
		;;
	esac
done
unset staticVals
printf '%s' "==============================="
}

generate-file() {

gen-static

if [[ $genmode == 'secure' ]]; then
	for (( i = 0; i < rounds; i ++ )); do
		if (( dynamicPass == 1 )); then
			pass=$(cat $randomtype | tr -dc '[:graph:]' | head -c $length)
		fi
		if (( dynamicIteration == 1 )); then
			iter=$(shuf -n 1 -i $iterVal)
		fi
		if (( dynamicSalt == 1 )); then
			salt=$(shuf -n 1 -i $saltVal)
		fi
		for j in ${dynamicVals[@]}; do
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
				's')
					printf '\n%s' "4${salt}"
				;;
				'p')
					printf '\n%s' "5${pass}"
				;;
			esac
		done
		${printNewline[@]}
	done
elif [[ $genmode == 'fast' ]]; then
	if (( rounds > 10000 )); then
		prod=$(( rounds / 10000 ))
		remainder=$(( rounds % 10000 ))
		if (( remainder > 0 )); then
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
		if (( runcount == prod )); then
			subruns="$remainder"
		fi
		if (( dynamicIteration == 1 )); then
			iter=( $(shuf -r -n $subruns -i $iterVal) )
		fi
		if (( dynamicSalt == 1 )); then
			salt=( $(shuf -r -n $subruns -i $saltVal) )
		fi
		if (( dynamicPass == 1 )); then
			pass=( $(cat $randomtype | tr -dc '[:graph:]' | head -c $(( length * subruns )) | fold -w $length) )
		fi
		for (( i = 0; i < subruns; i ++ )); do
			for j in ${dynamicVals[@]}; do
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
					's')
						printf '\n%s' "4${salt[ $i ]}"
					;;
					'p')
						printf '\n%s' "5${pass[ $i ]}"
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