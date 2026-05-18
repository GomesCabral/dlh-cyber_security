#!/bin/bash
john --show --format=raw-md5 "$1" | cut -d ":" -f2 | head -n -2 > 4-password.txt
