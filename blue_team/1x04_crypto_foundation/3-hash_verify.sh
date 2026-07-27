#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file_path> <expected_sha256_hash>" >&2
    exit 1
fi

file_path="$1"
expected_hash="$2"

if [ ! -f "$file_path" ]; then
    echo "Error: file does not exist: $file_path" >&2
    exit 1
fi

if ! [[ "$expected_hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo "Error: expected hash must contain exactly 64 hexadecimal characters." >&2
    exit 1
fi

actual_hash="$(sha256sum "$file_path" | awk '{print $1}')"

expected_hash="${expected_hash,,}"
actual_hash="${actual_hash,,}"

if [ "$actual_hash" = "$expected_hash" ]; then
    echo "INTEGRITY OK"
    exit 0
else
    echo "INTEGRITY FAILED - expected $expected_hash got $actual_hash"
    exit 1
fi
