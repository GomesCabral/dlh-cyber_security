#!/bin/bash
john --show --format=nt "$1" | cut -d ":" -f2 | head -n -2 > 5-password.txt
