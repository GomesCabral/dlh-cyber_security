#!/bin/bash
echo "$1" | sed 's/^{xor}//' | base64 -d | python3 -c 'import sys
data = sys.stdin.buffer.read()
decoded = bytes([byte ^ 95 for byte in data])
sys.stdout.buffer.write(decoded)
print()'
