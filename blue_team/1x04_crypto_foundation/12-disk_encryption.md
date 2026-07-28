# 12. The Disk Encryption Lab

## Goal

This laboratory demonstrates how to protect data at rest using Linux Unified Key Setup (LUKS). A virtual encrypted disk was created, formatted, mounted, tested, unmounted, and reopened to verify that data remained confidential while the encrypted volume was closed.

This directly addresses one of the highest-priority findings from the MedDefense cryptographic audit:

- **Finding:** NAS-01 stores backups in plaintext.
- **Risk:** Anyone stealing the NAS disks or obtaining offline access can read every backup.
- **Mitigation:** Encrypt backup storage using LUKS with strong key management.

---

# Part 1 – LUKS Setup

## Step 1 – Verify cryptsetup

Command:

```bash
cryptsetup --version
```

Output:

```text
cryptsetup 2.x.x
```

---

## Step 2 – Create a 500 MB virtual disk

Command:

```bash
dd if=/dev/zero \
of=encrypted_volume.img \
bs=1M \
count=500 \
status=progress
```

Output:

```text
500+0 records in
500+0 records out
524288000 bytes copied
```

Verify:

```bash
ls -lh encrypted_volume.img
```

Output:

```text
-rw-rw-r-- 1 gomes gomes 500M encrypted_volume.img
```

### Explanation

This file behaves exactly like a physical disk.

It currently contains only zeroes and is not encrypted.

---

## Step 3 – Format the volume using LUKS2

Command:

```bash
sudo cryptsetup luksFormat \
--type luks2 \
encrypted_volume.img
```

During execution:

```text
WARNING!
========
This will overwrite data.

Type YES:
```

Type:

```text
YES
```

Then enter a strong passphrase.

---

## Step 4 – Verify the LUKS header

Command:

```bash
sudo cryptsetup luksDump encrypted_volume.img
```

Relevant output:

```text
Version:        2
Cipher:         aes-xts-plain64
Keyslots:       1
PBKDF:          Argon2id
UUID:           xxxxxxxxxxxxxxxxx
```

### Explanation

The LUKS header stores:

- encryption algorithm
- key derivation function
- UUID
- keyslots
- metadata

It **does not contain plaintext data**.

---

## Step 5 – Open the encrypted volume

Command:

```bash
sudo cryptsetup luksOpen \
encrypted_volume.img \
secure_vol
```

Verify:

```bash
sudo cryptsetup status secure_vol
```

Output:

```text
/dev/mapper/secure_vol is active.
```

A decrypted block device now exists:

```text
/dev/mapper/secure_vol
```

---

## Step 6 – Create the filesystem

Command:

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

Output:

```text
Creating filesystem with ...
Filesystem UUID ...
```

### Explanation

LUKS encrypts blocks only.

A filesystem is still required before files can be stored.

---

## Step 7 – Mount the encrypted filesystem

Create mount point:

```bash
sudo mkdir -p /mnt/secure_vol
```

Mount:

```bash
sudo mount \
/dev/mapper/secure_vol \
/mnt/secure_vol
```

Verify:

```bash
findmnt /mnt/secure_vol
```

Output:

```text
/dev/mapper/secure_vol
```

---

## Step 8 – Write confidential data

Command:

```bash
echo "MedDefense confidential backup test - Patient MRN MED-50421" \
| sudo tee /mnt/secure_vol/backup_test.txt
```

Create another file:

```bash
sudo cp /etc/hosts \
/mnt/secure_vol/hosts-backup.txt
```

List files:

```bash
sudo ls -lh /mnt/secure_vol
```

Output:

```text
backup_test.txt
hosts-backup.txt
```

Read file:

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

---

## Step 9 – Calculate integrity hash

Command:

```bash
sudo sha256sum \
/mnt/secure_vol/backup_test.txt
```

Example:

```text
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

This hash will be compared after reopening the encrypted volume.

---

## Step 10 – Unmount and close

Flush writes:

```bash
sync
```

Unmount:

```bash
sudo umount /mnt/secure_vol
```

Close:

```bash
sudo cryptsetup luksClose secure_vol
```

Verify:

```bash
sudo cryptsetup status secure_vol
```

Output:

```text
inactive
```

The decrypted device has disappeared.

---

# Part 2 – Verification

## Attempt to read the encrypted image

Command:

```bash
strings encrypted_volume.img | head -50
```

No patient information appeared.

Search for the patient record:

```bash
strings encrypted_volume.img \
| grep "MED-50421"
```

Output:

```text
(no output)
```

Return code:

```bash
echo $?
```

Output:

```text
1
```

### What this proves

Although the plaintext existed while the filesystem was mounted, once the volume was closed the underlying image contained only encrypted blocks.

An attacker stealing the backup disk cannot recover patient records without the correct encryption key.

---

## Reopen the encrypted volume

Command:

```bash
sudo cryptsetup luksOpen \
encrypted_volume.img \
secure_vol
```

Mount:

```bash
sudo mount \
/dev/mapper/secure_vol \
/mnt/secure_vol
```

Read file:

```bash
sudo cat \
/mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

Verify integrity:

```bash
sudo sha256sum \
/mnt/secure_vol/backup_test.txt
```

The SHA-256 hash matched the original value.

### Conclusion

The encrypted volume successfully protected confidentiality while preserving integrity after reopening.

---

# Part 3 – LUKS Automation Script

Script:

```text
12-luks_manager.sh
```

Supported modes:

### Create

```bash
./12-luks_manager.sh create encrypted_volume.img 500
```

Creates:

- image file
- LUKS2 volume
- ext4 filesystem

---

### Open

```bash
./12-luks_manager.sh open \
encrypted_volume.img \
secure_vol \
/mnt/secure_vol
```

Opens and mounts the encrypted filesystem.

---

### Close

```bash
./12-luks_manager.sh close \
secure_vol \
/mnt/secure_vol
```

Unmounts and securely closes the encrypted volume.

---

# Part 4 – MedDefense Backup Encryption Design

## Recommended Encryption Level

**Volume-level encryption (LUKS)** should be implemented on NAS-01.

Reasons:

- protects every backup automatically
- transparent to backup software
- no application changes required
- encrypts databases, images, logs and configuration files simultaneously

---

## Performance Impact

AES acceleration is supported by modern CPUs.

Based on previous AES laboratory measurements, encryption overhead is expected to be approximately:

- **3–8%** during backup operations

This small performance cost is acceptable considering the protection gained.

---

## Key Storage

The encryption key **must not** be stored on NAS-01.

Instead it should be protected using:

- dedicated Hardware Security Module (HSM), or
- enterprise key management server, or
- offline encrypted backup accessible only by security administrators.

If ransomware compromises NAS-01, storing the key on the same device would allow attackers to decrypt the backups.

---

## Key Loss

If every copy of the LUKS key is lost:

- the encrypted backups become permanently unrecoverable;
- no recovery mechanism exists.

Therefore:

- multiple encrypted backups of the LUKS header should be maintained;
- key escrow procedures must be documented;
- disaster recovery testing should be performed regularly.

---

## Offsite Backup Integration

The cloud replica must **also remain encrypted**.

Recommended architecture:

```text
Production Servers
        │
        ▼
Encrypted Backup (LUKS)
        │
        ▼
Encrypted Replication
        │
        ▼
Cloud Storage
```

The cloud provider should never possess the encryption keys.

MedDefense should retain exclusive control of key management.

---

# MedDefense Connection

This laboratory directly mitigates one of the highest risks identified during Project 1x02.

Current situation:

- NAS-01 stores backups in plaintext.
- Any attacker obtaining the disks can read patient records.
- Ransomware compromising NAS-01 can access unencrypted backup files.

Recommended solution:

- Implement LUKS2 volume encryption using AES-XTS.
- Store encryption keys outside NAS-01.
- Maintain encrypted offsite replicas.
- Backup the LUKS header securely.
- Regularly test backup restoration procedures.

This design significantly improves confidentiality of backup data while remaining operationally practical for MedDefense.
