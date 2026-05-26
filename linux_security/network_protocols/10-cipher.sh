#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
  echo "Usage: sudo ./10-cipher.sh <target-ip-or-domain>"
  exit 1
fi

nmap --script ssl-enum-ciphers -p 443 "$TARGET"
