#!/bin/bash

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <input_file> <output_file> <cbc|gcm>" >&2
    exit 1
fi

input_file="$1"
output_file="$2"
mode="$3"

if [ ! -f "$input_file" ]; then
    echo "Error: input file does not exist: $input_file" >&2
    exit 1
fi

if [ -e "$output_file" ]; then
    echo "Error: output file already exists: $output_file" >&2
    exit 1
fi

case "$mode" in
    cbc)
        password_file="$(mktemp)"
        trap 'rm -f "$password_file"' EXIT

        chmod 600 "$password_file"

        read -r -s -p "Encryption password: " password
        echo
        read -r -s -p "Confirm password: " confirmation
        echo

        if [ "$password" != "$confirmation" ]; then
            echo "Error: passwords do not match." >&2
            exit 1
        fi

        printf '%s' "$password" > "$password_file"
        unset password confirmation

        openssl enc \
            -aes-256-cbc \
            -salt \
            -pbkdf2 \
            -iter 200000 \
            -md sha256 \
            -in "$input_file" \
            -out "$output_file" \
            -pass file:"$password_file"

        echo "Encrypted successfully with AES-256-CBC."
        ;;

    gcm)
        key_directory="${HOME}/.meddefense-crypto"
        private_key="${key_directory}/gcm-private-key.pem"
        certificate="${key_directory}/gcm-certificate.pem"

        mkdir -p "$key_directory"
        chmod 700 "$key_directory"

        if [ ! -f "$private_key" ] || [ ! -f "$certificate" ]; then
            echo "Creating the local GCM laboratory key pair..."

            openssl req \
                -x509 \
                -newkey rsa:3072 \
                -sha256 \
                -nodes \
                -keyout "$private_key" \
                -out "$certificate" \
                -days 365 \
                -subj "/C=LU/O=MedDefense Health Systems/OU=Crypto Lab/CN=MedDefense AES-GCM Lab"

            chmod 600 "$private_key"
            chmod 644 "$certificate"
        fi

        openssl cms \
            -encrypt \
            -aes-256-gcm \
            -binary \
            -in "$input_file" \
            -out "$output_file" \
            -outform DER \
            "$certificate"

        echo "Encrypted successfully with AES-256-GCM."
        echo "Private key: $private_key"
        echo "Certificate: $certificate"
        ;;

    *)
        echo "Error: mode must be either 'cbc' or 'gcm'." >&2
        exit 1
        ;;
esac

echo "Input:  $input_file"
echo "Output: $output_file"
