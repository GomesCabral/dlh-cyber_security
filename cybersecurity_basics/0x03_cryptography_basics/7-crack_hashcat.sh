#!/bin/bash
hashcat -m 0 -a 0 "$1" /usr/share/wordlists/rockyou.txt --show | cut -d ":" -f2 > 7-password.txt
