# 12. The Disk Encryption Lab

## Goal

This laboratory demonstrates how to protect data at rest using Linux Unified Key Setup (LUKS). A 500 MB virtual disk is created, encrypted, formatted, mounted, tested, closed, inspected in raw form, reopened, and verified.

This directly addresses the MedDefense finding that NAS-01 stores backup data in plaintext.

- **Finding:** NAS-01 backups are stored without encryption.
- **Risk:** Anyone who steals the disks or obtains offline access can read patient and business data.
- **Mitigation:** Encrypt backup storage with LUKS and manage recovery keys outside NAS-01.

---

# Part 1 - LUKS Setup

## Step 1 - Verify cryptsetup

Command:

```bash
cryptsetup --version
```

Output:

```text
[PASTE YOUR REAL OUTPUT HERE]
```

If `cryptsetup` is not installed:

```bash
sudo apt update
sudo apt install -y cryptsetup
```

---

## Step 2 - Create the 500 MB Virtual Disk

Required command:

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

Command used during the laboratory:

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500 status=progress
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Verify the file:

```bash
ls -lh encrypted_volume.img
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

The `dd` command creates a **500 MB file** that behaves like a virtual hard disk. Initially, it contains only zeroes and is **not encrypted**.

---

## Step 3 - Format the Image with LUKS

Required command:

```bash
sudo cryptsetup luksFormat encrypted_volume.img
```

Command used:

```bash
sudo cryptsetup luksFormat --type luks2 encrypted_volume.img
```

When prompted:

```text
Type YES:
```

Type:

```text
YES
```

Then enter a strong passphrase.

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

This command writes a **LUKS2 header** onto the virtual disk. The encrypted filesystem does not yet exist—the disk is only prepared to hold encrypted data.

---

## Step 4 - Inspect the LUKS Header

Command:

```bash
sudo cryptsetup luksDump encrypted_volume.img
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The output should include information such as:

- LUKS Version
- Cipher
- Cipher Mode
- UUID
- PBKDF
- Keyslots

### Explanation

The header contains metadata about the encrypted volume but **does not contain the encrypted files themselves**.

---

## Step 5 - Open the Encrypted Volume

Required command:

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Verify:

```bash
sudo cryptsetup status secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The decrypted mapping is now available at:

```text
/dev/mapper/secure_vol
```

### Explanation

`luksOpen` decrypts the volume using the passphrase and creates a temporary device mapper entry that applications can use normally.

---

## Step 6 - Create the Filesystem

Required command:

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

LUKS encrypts blocks only.

A filesystem must be created before storing files.

---

## Step 7 - Mount the Filesystem

Create the mount point:

```bash
sudo mkdir -p /mnt/secure_vol
```

Mount:

```bash
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Verify:

```bash
findmnt /mnt/secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

After mounting, the encrypted volume behaves like any normal Linux filesystem.

---

## Step 8 - Write Test Data

Create a confidential file:

```bash
echo "MedDefense confidential backup test - Patient MRN MED-50421" | sudo tee /mnt/secure_vol/backup_test.txt
```

Copy another file:

```bash
sudo cp /etc/hosts /mnt/secure_vol/hosts-backup.txt
```

List the contents:

```bash
sudo ls -lh /mnt/secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Read the confidential file:

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

Calculate its SHA-256 hash:

```bash
sudo sha256sum /mnt/secure_vol/backup_test.txt
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

### Explanation

The hash will later be compared after reopening the encrypted volume to prove that the stored data has not changed.

---

## Step 9 - Unmount and Close

Flush pending writes:

```bash
sync
```

Unmount:

```bash
sudo umount /mnt/secure_vol
```

Close the encrypted mapping:

```bash
sudo cryptsetup luksClose secure_vol
```

Verify:

```bash
sudo cryptsetup status secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The encrypted mapping should now be inactive.

---

# Part 2 - Verification

## Step 1 - Inspect the Raw Encrypted Image

Attempt to read the encrypted image directly:

```bash
strings encrypted_volume.img | head -50
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Search for the confidential patient record:

```bash
strings encrypted_volume.img | grep "MED-50421"
```

Output:

```text
No output
```

Check the exit status:

```bash
echo $?
```

Output:

```text
1
```

### Explanation

The command `strings` extracts printable text from binary files.

Because the LUKS volume is closed, the image contains only encrypted blocks. The confidential patient information cannot be recovered from the raw image.

This demonstrates **encryption at rest**. Even if an attacker steals the disk or copies the backup image, the stored data remains unreadable without the encryption key.

---

## Step 2 - Reopen the Encrypted Volume

Open the encrypted volume:

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

Mount it:

```bash
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

Verify the mount:

```bash
findmnt /mnt/secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

---

## Step 3 - Verify the Stored Data

Read the confidential file:

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

Output:

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

Calculate the SHA-256 hash again:

```bash
sudo sha256sum /mnt/secure_vol/backup_test.txt
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

Compare the new SHA-256 value with the one calculated before closing the encrypted volume.

The hashes should be identical.

### Explanation

The matching SHA-256 values prove that:

- confidentiality was preserved while the volume was closed;
- no data corruption occurred;
- the encrypted filesystem successfully restored the original plaintext after decryption.

---

## Step 4 - Complete the Close Cycle

Flush pending writes:

```bash
sync
```

Unmount:

```bash
sudo umount /mnt/secure_vol
```

Close the encrypted mapping:

```bash
sudo cryptsetup luksClose secure_vol
```

Verify:

```bash
sudo cryptsetup status secure_vol
```

Output:

```text
[PASTE YOUR OUTPUT HERE]
```

The encrypted volume is now completely closed.

---

## Verification Summary

This laboratory demonstrates an important security property:

- While the LUKS volume is **open**, authorised users can read and modify files normally.
- While the LUKS volume is **closed**, the underlying disk contains only encrypted data.

Anyone stealing the physical disk or backup image obtains only ciphertext.

---

# Part 3 - LUKS Automation Script

The automation script for this task is:

```text
12-luks_manager.sh
```

## Create Mode

```bash
./12-luks_manager.sh create encrypted_volume.img 500
```

Operations performed:

1. Create the image using:

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

2. Initialise encryption:

```bash
cryptsetup luksFormat
```

3. Open the encrypted volume:

```bash
cryptsetup luksOpen
```

4. Create the ext4 filesystem:

```bash
mkfs.ext4
```

5. Close the encrypted volume:

```bash
cryptsetup luksClose
```

---

## Open Mode

```bash
./12-luks_manager.sh open encrypted_volume.img secure_vol /mnt/secure_vol
```

Operations:

- cryptsetup luksOpen
- mount

---

## Close Mode

```bash
./12-luks_manager.sh close secure_vol /mnt/secure_vol
```

Operations:

- umount
- cryptsetup luksClose

---

## Script Validation

Make the script executable:

```bash
chmod +x 12-luks_manager.sh
```

Validate the syntax:

```bash
bash -n 12-luks_manager.sh
```

No output indicates that Bash detected no syntax errors.

---

# Part 4 - MedDefense Backup Encryption Design

## Recommended Encryption Strategy

The current MedDefense environment stores all backup data on **NAS-01** without encryption. This represents a critical security risk because anyone who gains physical access to the storage device or copies the disks can read all backup data in plaintext.

To mitigate this risk, MedDefense should implement a layered encryption strategy consisting of:

- LUKS2 volume encryption for NAS-01.
- AES-256-GCM encryption for backup archives before they are copied to cloud storage.
- Secure external key management.
- Immutable off-site backups.

This provides confidentiality even if the backup media is stolen.

---

## Appropriate Encryption Level

### Recommended

**Volume-Level Encryption (LUKS2)**

LUKS encrypts every block written to the storage device and is transparent to the backup software after the administrator unlocks the volume.

Advantages:

- Protects all files automatically.
- No application changes required.
- Excellent Linux support.
- Standard enterprise solution.

---

### Additional Layer

For backups replicated to another location, MedDefense should also encrypt each backup archive individually using **AES-256-GCM** before replication.

This provides end-to-end protection even if another storage provider is compromised.

---

## Performance Impact

Based on the AES performance tests completed in Task 1, symmetric encryption introduces only a small performance overhead.

Typical enterprise overhead is approximately:

- 2%–10% with modern CPUs supporting AES-NI.

For MedDefense this overhead is acceptable because:

- Backup operations occur during maintenance windows.
- Confidentiality of patient records is significantly more important than a small reduction in throughput.

The real performance should be measured using:

```bash
cryptsetup benchmark
```

and compared against the backup throughput measured in Task 1.

---

## Encryption Key Storage

The encryption key **must never be stored on NAS-01**.

If ransomware compromises NAS-01 and both the encrypted data and the encryption key are stored together, encryption provides almost no protection.

Recommended key storage:

- Hardware Security Module (HSM)
- Enterprise Key Management System (KMS)
- Offline encrypted recovery key stored in a secure safe

Access to recovery keys should require:

- Multi-factor authentication
- Role-based access control
- Audit logging
- Dual approval for key export

---

## What Happens if the Key is Lost?

If every copy of the LUKS passphrase and recovery key is lost:

- The encrypted backups become permanently unrecoverable.
- Patient records cannot be restored.
- Financial records are lost.
- DICOM medical images cannot be recovered.
- Disaster recovery fails completely.

For this reason, recovery keys must themselves be backed up securely.

---

## LUKS Header Backup

The LUKS header should be backed up immediately after creating the encrypted volume.

Command:

```bash
sudo cryptsetup luksHeaderBackup encrypted_volume.img --header-backup-file encrypted_volume-header.backup
```

The header backup should be:

- encrypted;
- stored offline;
- protected with strict access controls;
- tested periodically.

---

## Off-Site Backup Replication

The off-site backup copy should also remain encrypted.

Recommended workflow:

```text
Production Servers
        |
        v
Backup Software
        |
        v
AES-256-GCM Encrypted Backup
        |
        +-----------------------+
        |                       |
        v                       v
LUKS Encrypted NAS        Cloud Backup Storage
```

Even if the cloud provider encrypts stored data, MedDefense should encrypt the backup before uploading it.

This ensures only MedDefense controls the encryption keys.

---

## Key Ownership

Recommended ownership:

```text
Encryption Keys

↓

MedDefense IT Security Team

↓

Enterprise Key Management System (KMS)

↓

Encrypted Backup Storage
```

The cloud provider should never be the only party able to decrypt patient data.

---

## Key Separation

Different encryption keys should be used for different purposes.

Example:

| Purpose | Key |
|---------|-----|
| NAS-01 LUKS Volume | Key A |
| Backup Archive Encryption | Key B |
| Cloud Replication | Key C |
| Disaster Recovery Testing | Key D |

Key separation limits the impact of a compromised key and simplifies key rotation.

---

## Protection Against Ransomware

Encryption at rest does **not** protect files while the encrypted volume is unlocked.

If ransomware infects NAS-01 while the filesystem is mounted, it can still:

- delete backups;
- encrypt backup files;
- corrupt recovery data.

For this reason, MedDefense should also implement:

- immutable snapshots;
- offline backups;
- network segmentation;
- MFA for administrators;
- Wazuh monitoring;
- regular recovery testing;
- least privilege.

Encryption protects confidentiality.

Immutability protects availability.

Both are required.

---

# MedDefense Backup Encryption Summary

| Requirement | Recommendation |
|--------------|---------------|
| Disk Encryption | LUKS2 |
| Encryption Algorithm | AES-XTS |
| Backup File Encryption | AES-256-GCM |
| Encryption Key Storage | External KMS / HSM |
| Store Keys on NAS | No |
| Cloud Backup Encryption | Yes |
| Key Ownership | MedDefense |
| Immutable Backups | Required |
| Header Backup | Required |
| Recovery Testing | Required |
| Monitoring | Wazuh |
| MFA | Required |
| Least Privilege | Required |

---

# Conclusion

This laboratory demonstrated how Linux Unified Key Setup (LUKS) provides encryption at rest.

The complete workflow performed was:

```text
dd
↓
cryptsetup luksFormat
↓
cryptsetup luksOpen
↓
mkfs.ext4
↓
mount
↓
write confidential data
↓
umount
↓
cryptsetup luksClose
↓
verify encrypted raw image
↓
cryptsetup luksOpen
↓
mount
↓
verify file integrity
↓
umount
↓
cryptsetup luksClose
```

When the encrypted volume was closed, confidential patient information was not visible in the raw disk image.

After reopening the encrypted volume using the correct passphrase, all data remained intact, demonstrating both confidentiality and integrity.

For MedDefense, LUKS should be implemented on NAS-01 together with external key management, encrypted off-site backups, immutable storage, and regular recovery testing to provide a secure backup solution aligned with healthcare security requirements.
