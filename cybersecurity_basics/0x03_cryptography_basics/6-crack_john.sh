#!/bin/bash
john --show --format=raw-sha256 "$1" | cut -d ":" -f2 | head -n -2 > 6-password.txt
