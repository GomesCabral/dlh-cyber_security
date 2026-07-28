#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./12-luks_manager.sh create <image_file> <size_mb>
  ./12-luks_manager.sh open <image_file> <mapping_name> <mount_point>
  ./12-luks_manager.sh close <mapping_name> <mount_point>

Examples:
  ./12-luks_manager.sh create encrypted_volume.img 500
  ./12-luks_manager.sh open encrypted_volume.img secure_vol /mnt/secure_vol
  ./12-luks_manager.sh close secure_vol /mnt/secure_vol
EOF
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command not found: $1" >&2
        exit 1
    fi
}

require_tools() {
    require_command sudo
    require_command cryptsetup
    require_command dd
    require_command mkfs.ext4
    require_command mount
    require_command umount
    require_command mountpoint
}

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

mode="$1"

case "$mode" in
    create)
        if [ "$#" -ne 3 ]; then
            usage
            exit 1
        fi

        image_file="$2"
        size_mb="$3"
        temporary_mapping="luks_create_$$"

        require_tools

        if ! [[ "$size_mb" =~ ^[1-9][0-9]*$ ]]; then
            echo "Error: size_mb must be a positive integer." >&2
            exit 1
        fi

        if [ -e "$image_file" ]; then
            echo "Error: output file already exists: $image_file" >&2
            exit 1
        fi

        cleanup() {
            if [ -e "/dev/mapper/$temporary_mapping" ]; then
                sudo cryptsetup luksClose "$temporary_mapping" || true
            fi
        }

        trap cleanup EXIT

        echo "[1/5] Creating ${size_mb} MB virtual disk: $image_file"

        dd if=/dev/zero \
            of="$image_file" \
            bs=1M \
            count="$size_mb" \
            status=progress

        echo "[2/5] Formatting the image with LUKS2."

        sudo cryptsetup luksFormat \
            --type luks2 \
            "$image_file"

        echo "[3/5] Opening the encrypted volume temporarily."

        sudo cryptsetup luksOpen \
            "$image_file" \
            "$temporary_mapping"

        echo "[4/5] Creating an ext4 filesystem."

        sudo mkfs.ext4 \
            "/dev/mapper/$temporary_mapping"

        echo "[5/5] Closing the temporary LUKS mapping."

        sudo cryptsetup luksClose \
            "$temporary_mapping"

        trap - EXIT

        echo "CREATE OK"
        echo "Encrypted image: $image_file"
        echo "Size: ${size_mb} MB"
        ;;

    open)
        if [ "$#" -ne 4 ]; then
            usage
            exit 1
        fi

        image_file="$2"
        mapping_name="$3"
        mount_point="$4"

        require_tools

        if [ ! -f "$image_file" ]; then
            echo "Error: image file does not exist: $image_file" >&2
            exit 1
        fi

        if [ -e "/dev/mapper/$mapping_name" ]; then
            echo "Error: mapping already exists: /dev/mapper/$mapping_name" >&2
            exit 1
        fi

        echo "[1/3] Opening the LUKS volume."

        sudo cryptsetup luksOpen \
            "$image_file" \
            "$mapping_name"

        echo "[2/3] Creating the mount point."

        sudo mkdir -p \
            "$mount_point"

        echo "[3/3] Mounting the encrypted filesystem."

        if ! sudo mount \
            "/dev/mapper/$mapping_name" \
            "$mount_point"; then

            echo "Error: mount failed. Closing the LUKS mapping." >&2

            sudo cryptsetup luksClose \
                "$mapping_name" || true

            exit 1
        fi

        echo "OPEN OK"
        echo "Mapped device: /dev/mapper/$mapping_name"
        echo "Mount point: $mount_point"
        ;;

    close)
        if [ "$#" -ne 3 ]; then
            usage
            exit 1
        fi

        mapping_name="$2"
        mount_point="$3"

        require_tools

        if mountpoint -q "$mount_point"; then
            echo "[1/2] Unmounting: $mount_point"

            sudo umount \
                "$mount_point"
        else
            echo "[1/2] Mount point is not mounted: $mount_point"
        fi

        if [ -e "/dev/mapper/$mapping_name" ]; then
            echo "[2/2] Closing LUKS mapping: $mapping_name"

            sudo cryptsetup luksClose \
                "$mapping_name"
        else
            echo "[2/2] Mapping does not exist: /dev/mapper/$mapping_name"
        fi

        echo "CLOSE OK"
        ;;

    *)
        echo "Error: mode must be create, open, or close." >&2
        usage
        exit 1
        ;;
esac
