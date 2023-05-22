#!/bin/bash

# Use Bash Strict Mode
set -euo pipefail
#IFS=$'\n\t'

eval set -- "$(getopt -o "k:u:p:" -l "key:url:passphrase:" -- "$@")"
while :; do
    case "$1" in
        (-k|--key)
            KEY="$2"
            shift 2;;
        (-u|--url)
            url="$2"
            shift 2;;
        (-p|--passphrase)
            PASS="$2"
            shift 2;;
        (--)
            shift
            break;;
    esac
done

#echo "$url $secret $KEY $PASS"

while read -r field value; do
    case "$field" in
        (id:)
            id="$value"
            ;;
        (event:)
            event="$value"
            ;;
        (data:)
            case "$event" in
                (ping)
                    id="${value:1-1}"
                    echo "{\"ping\":\"$id\"}"
                    ;;
                (webhook)
                    echo "${value:1:-1}"
                    ;;
                (encrypted)
                    data="${value//:/ }"
                    data="${data:1:-1}"
                    read -r encrypted_key iv encrypted_text < <(echo "$data")
                    echo "$encrypted_key" | openssl base64 -d > encrypted_key
                    openssl pkeyutl -decrypt -in encrypted_key -out decrypted_key -inkey "$KEY" -passin "pass:$PASS" -pkeyopt rsa_padding_mode:oaep
                    rm -f encrypted_key
                    ENCRYPTION_KEY=$(cat decrypted_key)
                    rm -f decrypted_key
                    ENCRYPTION_KEY=$(echo -n "$ENCRYPTION_KEY" | xxd -ps -c 200)
                    echo "$encrypted_text" | xxd -r -p | openssl enc -aes-256-ctr -d -K "$ENCRYPTION_KEY" -iv "$iv"
                    echo
                    ;;
            esac
            ;;
    esac
done < <(wget -q "$url" -O -)
