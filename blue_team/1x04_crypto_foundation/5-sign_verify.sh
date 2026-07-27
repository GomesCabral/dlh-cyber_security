#!/bin/bash

if [ "$#" -lt 1 ]; then
    echo "Usage:"
    echo "  $0 sign <file> <private_key>"
    echo "  $0 verify <file> <signature_file> <public_key>"
    exit 1
fi

mode="$1"

case "$mode" in
    sign)
        if [ "$#" -ne 3 ]; then
            echo "Usage: $0 sign <file> <private_key>" >&2
            exit 1
        fi

        file_path="$2"
        private_key="$3"
        signature_file="${file_path}.sig"

        if [ ! -f "$file_path" ]; then
            echo "Error: file does not exist: $file_path" >&2
            exit 1
        fi

        if [ ! -f "$private_key" ]; then
            echo "Error: private key does not exist: $private_key" >&2
            exit 1
        fi

        if openssl dgst             -sha256             -sign "$private_key"             -out "$signature_file"             "$file_path"; then
            echo "SIGNATURE CREATED: $signature_file"
            exit 0
        else
            echo "Error: signing failed." >&2
            exit 1
        fi
        ;;

    verify)
        if [ "$#" -ne 4 ]; then
            echo "Usage: $0 verify <file> <signature_file> <public_key>" >&2
            exit 1
        fi

        file_path="$2"
        signature_file="$3"
        public_key="$4"

        if [ ! -f "$file_path" ]; then
            echo "Error: file does not exist: $file_path" >&2
            exit 1
        fi

        if [ ! -f "$signature_file" ]; then
            echo "Error: signature file does not exist: $signature_file" >&2
            exit 1
        fi

        if [ ! -f "$public_key" ]; then
            echo "Error: public key does not exist: $public_key" >&2
            exit 1
        fi

        if openssl dgst             -sha256             -verify "$public_key"             -signature "$signature_file"             "$file_path"; then
            echo "SIGNATURE VALID"
            exit 0
        else
            echo "SIGNATURE INVALID"
            exit 1
        fi
        ;;

    *)
        echo "Error: mode must be 'sign' or 'verify'." >&2
        exit 1
        ;;
esac
