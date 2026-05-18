#!/bin/bash
echo "$(john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 "$1" 2>/dev/null)$(john --show --format=raw-md5 "$1" | cut -d ":" -f2 | head -n -2)" > 4-password.txt
