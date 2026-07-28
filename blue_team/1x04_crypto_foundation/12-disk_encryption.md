# 12. The Disk Encryption Lab

## Goal

This laboratory demonstrates how to protect data at rest using Linux Unified Key Setup (LUKS). A 500 MB virtual disk was created, encrypted with LUKS2, formatted with an ext4 filesystem, mounted, populated with test data, unmounted, closed, and reopened to verify data integrity.

This exercise addresses the MedDefense finding that **NAS-01 stores backups in plaintext**.

**Finding:** NAS-01 stores backup data without encryption.

**Risk:** If the NAS disks are stolen or an attacker gains offline access, all patient records, billing information, medical images, and system backups can be read.

**Mitigation:** Encrypt backup storage using LUKS and store the encryption keys **NOT on the NAS**.

---

# Part 1 - LUKS Setup

## Step 1 - Verify cryptsetup

### Command

```bash
cryptsetup --version
```

### Output

```text
cryptsetup 2.8.6 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL
```

This confirms that the required LUKS encryption utilities are installed.

---

## Step 2 - Create a 500 MB Virtual Disk

### Required command

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
```

### Command used

```bash
dd if=/dev/zero of=encrypted_volume.img bs=1M count=500 status=progress
```

### Output

```text
204472320 bytes (204 MB, 195 MiB) copied, 1 s, 203 MB/s
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, 2.96641 s, 177 MB/s
```

### Verify the image

```bash
ls -lh encrypted_volume.img
```

### Output

```text
-rw-rw-r--. 1 gomes gomes 500M Jul 28 11:11 encrypted_volume.img
```

### Explanation

The file `encrypted_volume.img` acts as a virtual hard disk that can safely be used to practise LUKS without modifying a physical storage device.

---

## Step 3 - Format the Image with LUKS2

### Required command

```bash
sudo cryptsetup luksFormat encrypted_volume.img
```

### Command used

```bash
sudo cryptsetup luksFormat --type luks2 encrypted_volume.img
```

During execution, cryptsetup requested confirmation:

```text
WARNING!
========
This will overwrite data on encrypted_volume.img irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
```

A strong passphrase was then entered.

### Explanation

This command writes the LUKS2 header, generates a random master encryption key, and protects that key using the supplied passphrase.

The passphrase is **not** used to encrypt the data directly.

---

## Step 4 - Inspect the LUKS Header

### Command

```bash
sudo cryptsetup luksDump encrypted_volume.img
```

### Output (excerpt)

```text
Version:        2
UUID:           8ff06c4c-e1d2-4427-bb66-b86166485e66

Data segments:
  cipher: aes-xts-plain64

Keyslots:
  Key:        512 bits
  Cipher:     aes-xts-plain64
  PBKDF:      argon2id

Digests:
  Hash:       sha256
```

### Explanation

The LUKS header contains metadata only.

It stores:

- UUID
- encryption algorithm
- key derivation function
- keyslots
- integrity information

It **does not** contain any plaintext user data.

---

## Step 5 - Open the Encrypted Volume

### Required command

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
```

### Verify the mapping

```bash
sudo cryptsetup status secure_vol
```

### Output

```text
/dev/mapper/secure_vol is active.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 [bits]
  key location: keyring
  device:  /dev/loop0
  loop:    /home/gomes/dlh-cyber_security/blue_team/1x04_crypto_foundation/encrypted_volume.img
  sector size: 4096 [bytes]
  mode: read/write
```

### Explanation

`luksOpen` decrypts the master key using the passphrase and creates the temporary decrypted block device:

```text
/dev/mapper/secure_vol
```

Applications access this mapper device as if it were a normal disk.

---

## Step 6 - Create the Filesystem

### Command

```bash
sudo mkfs.ext4 /dev/mapper/secure_vol
```

### Output

```text
Creating filesystem with 123904 4k blocks and 123904 inodes
Filesystem UUID: 2dd2a589-ba7b-46e9-be39-d7730a186ac9
Superblock backups stored on blocks:
32768, 98304

Writing superblocks and filesystem accounting information: done
```

### Explanation

LUKS encrypts raw disk blocks only.

An ext4 filesystem must still be created before files can be stored.

---

## Step 7 - Mount the Filesystem

### Create the mount point

```bash
sudo mkdir -p /mnt/secure_vol
```

### Mount

```bash
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

### Verify

```bash
findmnt /mnt/secure_vol
```

### Output

```text
TARGET              SOURCE                   FSTYPE OPTIONS
/mnt/secure_vol     /dev/mapper/secure_vol   ext4   rw,relatime,seclabel
```

### Explanation

Once mounted, the encrypted volume behaves exactly like a normal Linux filesystem.

---

## Step 8 - Write Test Data

### Create the confidential file

```bash
echo "MedDefense confidential backup test - Patient MRN MED-50421" | sudo tee /mnt/secure_vol/backup_test.txt
```

### Output

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

### Copy another file

```bash
sudo cp /etc/hosts /mnt/secure_vol/hosts-backup.txt
```

### Verify

```bash
sudo ls -lh /mnt/secure_vol
```

### Output

```text
total 24K
-rw-r--r--. 1 root root   60 Jul 28 11:23 backup_test.txt
-rw-r--r--. 1 root root  649 Jul 28 11:23 hosts-backup.txt
drwx------  2 root root 16K Jul 28 11:22 lost+found
```

### Read the file

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

### Output

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

---

## Step 9 - Calculate the SHA-256 Hash

### Command

```bash
sudo sha256sum /mnt/secure_vol/backup_test.txt
```

### Output

```text
28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419  /mnt/secure_vol/backup_test.txt
```

This hash will later be compared after reopening the encrypted volume.

---

## Step 10 - Unmount and Close

### Commands

```bash
sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
```

### Verify

```bash
sudo cryptsetup status secure_vol
```

### Output

```text
/dev/mapper/secure_vol is inactive.
```

The decrypted device has been removed from the system and the encrypted volume is now protected.

---

# Part 2 - Verification

## Attempt to Read the Raw Encrypted File

After closing the encrypted volume, the raw image was inspected using the `strings` utility.

### Command

```bash
strings encrypted_volume.img | head -20
```

### Output

```text
LUKS
sha256
8ff06c4c-e1d2-4427-bb66-b86166485e66
{"keyslots":{"0":{"type":"luks2","key_size":64...
```

The output only contains the LUKS header and metadata.

No patient information or plaintext files are visible.

---

## Search for the Confidential Data

### Command

```bash
strings encrypted_volume.img | grep -F "MED-50421"
echo $?
```

### Output

```text
1
```

### Explanation

The confidential string stored inside the encrypted filesystem cannot be found in the raw disk image.

An exit code of **1** means that `grep` did not find the searched text.

This demonstrates **encryption at rest**. Even if an attacker steals the disk or obtains offline access to the encrypted image, they cannot recover the stored files without first unlocking the LUKS volume.

---

## Reopen the Encrypted Volume

### Commands

```bash
sudo cryptsetup luksOpen encrypted_volume.img secure_vol

sudo mount /dev/mapper/secure_vol /mnt/secure_vol
```

The passphrase was entered successfully.

---

## Verify the Stored Data

### Command

```bash
sudo cat /mnt/secure_vol/backup_test.txt
```

### Output

```text
MedDefense confidential backup test - Patient MRN MED-50421
```

The confidential file remained intact after reopening the encrypted volume.

---

## Verify File Integrity

### Command

```bash
sudo sha256sum /mnt/secure_vol/backup_test.txt
```

### Output

```text
28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419  /mnt/secure_vol/backup_test.txt
```

This SHA-256 hash is identical to the hash calculated before closing the encrypted volume.

This proves that:

- the encrypted filesystem preserved the data correctly;
- no corruption occurred while the volume was closed;
- encryption protects confidentiality without affecting integrity.

---

## Close the Volume Again

### Commands

```bash
sync

sudo umount /mnt/secure_vol

sudo cryptsetup luksClose secure_vol
```

### Verification

```bash
sudo cryptsetup status secure_vol
```

### Output

```text
/dev/mapper/secure_vol is inactive.
```

Once the encrypted volume is closed, the decrypted device mapper disappears and the mounted filesystem is no longer accessible.

This behaviour confirms that access to the data depends entirely on successful authentication with the correct encryption key.

---

# Part 3 - MedDefense Backup Encryption Design

## Recommended Encryption Strategy for NAS-01

Three different encryption approaches were evaluated.

### Full-disk encryption

Full-disk encryption protects the entire storage device, including the operating system and swap partitions.

This is useful for laptops and workstations but is not the best solution for a dedicated backup server because administrators may need to manage multiple encrypted backup volumes independently.

---

### Volume-level encryption

**Volume-level encryption is the recommended solution for NAS-01.**

The backup volume should be protected using **LUKS2** with:

- AES-XTS-512 encryption;
- Argon2id key derivation;
- strong administrator passphrases;
- multiple authorised recovery keys.

This approach encrypts every backup stored on NAS-01 while allowing the operating system to remain separate from the encrypted backup volume.

---

### File-level encryption

Sensitive backups replicated to external locations should also use **file-level (backup-object) encryption** before transmission.

This provides an additional layer of protection if encrypted backup files are copied outside the primary storage system.

---

## Performance Impact

Modern processors include AES hardware acceleration (AES-NI).

Because of this, LUKS encryption typically introduces only a small performance overhead, generally between **2% and 5%** during backup operations.

Compared with the benefits of protecting regulated healthcare data, this overhead is considered acceptable for MedDefense.

---

## Encryption Key Storage

The encryption key must be stored **NOT on the NAS**.

Keeping both the encrypted backups and the only decryption key on NAS-01 would allow an attacker who compromises the NAS to obtain everything required to decrypt the data.

Recommended key storage locations include:

- Enterprise Key Management System (KMS);
- Hardware Security Module (HSM);
- encrypted offline recovery media stored in a secure safe;
- protected password vault with strict administrative controls.

Access to recovery keys should require:

- multi-factor authentication;
- role-based access control;
- least privilege;
- audit logging;
- separation of duties.

---

## What Happens if the Key is Lost?

If the **key is lost**, the encrypted backups become permanently inaccessible.

If the encryption **key is lost**, MedDefense cannot recover patient records, billing databases, DICOM images, Active Directory backups, or disaster recovery data stored inside the encrypted volume.

There is no hidden recovery password or administrative bypass built into LUKS.

To reduce this risk, MedDefense should:

- maintain multiple authorised recovery keys;
- back up the LUKS header;
- store recovery keys **NOT on the NAS**;
- periodically test recovery procedures.

---

## Cloud Backup Replication

The cloud replica must also remain encrypted.

Backup data should never be uploaded to cloud storage in plaintext.

The preferred design is:

1. Encrypt the backup locally.
2. Replicate the encrypted backup to the cloud.
3. Keep ownership of the encryption keys within MedDefense.

The cloud provider must never possess the only copy of the encryption key.

Instead, MedDefense should use:

- a MedDefense-controlled Key Management System (KMS); or
- a customer-managed cloud KMS key (CMK).

This ensures that cloud administrators cannot decrypt regulated healthcare data without MedDefense's authorisation.

---

# Conclusion

This laboratory demonstrated the practical implementation of encryption at rest using LUKS2.

The encrypted volume successfully protected confidential information while closed, prevented plaintext recovery from the raw disk image, and preserved data integrity after reopening.

The same principles should be applied to MedDefense's NAS-01 backup infrastructure to protect regulated healthcare information against theft, offline attacks, and unauthorised access.


