12. The Disk Encryption Lab

Goal

This laboratory demonstrates how to protect data at rest using Linux Unified Key Setup (LUKS). A 500 MB virtual disk was created, encrypted with LUKS2, formatted with ext4, mounted, populated with test data, unmounted, closed, inspected as a raw encrypted file, reopened, and verified.

This exercise addresses the MedDefense finding that NAS-01 stores backups in plaintext.

Finding: NAS-01 stores backup data without encryption.

Risk: If the NAS disks are stolen or an attacker gains offline access, patient records, billing data, medical images, and system backups can be read.

Mitigation: Encrypt NAS-01 at rest, store encryption keys NOT on the NAS, and ensure that the cloud replica also remains encrypted.

Part 1 - LUKS Setup

Step 1 - Verify cryptsetup

Command:

cryptsetup --version

Output:

cryptsetup 2.8.6 flags: UDEV BLKID KEYRING KERNEL_CAPI HW_OPAL

Step 2 - Create a 500 MB Virtual Disk

Required command:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500

Command used:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500 status=progress

Output:

204472320 bytes (204 MB, 195 MiB) copied, 1 s, 203 MB/s
500+0 records in
500+0 records out
524288000 bytes (524 MB, 500 MiB) copied, 2.96641 s, 177 MB/s

Verify the image:

ls -lh encrypted_volume.img

Output:

-rw-rw-r--. 1 gomes gomes 500M Jul 28 11:11 encrypted_volume.img

The file acts as a virtual block device for the laboratory.

Step 3 - Format the Image with LUKS2

Required command:

sudo cryptsetup luksFormat encrypted_volume.img

Command used:

sudo cryptsetup luksFormat --type luks2 encrypted_volume.img

The confirmation YES was entered and a strong passphrase was configured.

luksFormat created the LUKS2 header and protected the internal volume key with the passphrase.

Step 4 - Inspect the LUKS Header

Command:

sudo cryptsetup luksDump encrypted_volume.img

Output:

LUKS header information
Version:        2
Epoch:          3
Metadata area:  16384 [bytes]
Keyslots area:  16744448 [bytes]
UUID:           8ff06c4c-e1d2-4427-bb66-b86166485e66
Label:          (no label)
Subsystem:      (no subsystem)
Flags:          (no flags)

Data segments:
  0: crypt
  offset: 16777216 [bytes]
  length: (whole device)
  cipher: aes-xts-plain64
  sector: 4096 [bytes]

Keyslots:
  0: luks2
  Key:        512 bits
  Priority:   normal
  Cipher:     aes-xts-plain64
  Cipher key: 512 bits
  PBKDF:      argon2id
  Time cost:  4
  Memory:     529866
  Threads:    2
  AF stripes: 4000
  AF hash:    sha256

Digests:
  0: pbkdf2
  Hash:       sha256
  Iterations: 151528

The volume uses:

LUKS2
AES-XTS
512-bit XTS key material
Argon2id
SHA-256

Step 5 - Open the Encrypted Volume

Required command:

sudo cryptsetup luksOpen encrypted_volume.img secure_vol

Verify the mapping:

sudo cryptsetup status secure_vol

Output:

/dev/mapper/secure_vol is active.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 [bits]
  key location: keyring
  device:  /dev/loop0
  loop:    /home/gomes/dlh-cyber_security/blue_team/1x04_crypto_foundation/encrypted_volume.img
  sector size:  4096 [bytes]
  offset:  32768 [512-byte units] (16777216 [bytes])
  size:    991232 [512-byte units] (507510784 [bytes])
  mode:    read/write

The decrypted mapper device became available at:

/dev/mapper/secure_vol

Step 6 - Create the ext4 Filesystem

Command:

sudo mkfs.ext4 /dev/mapper/secure_vol

Output:

mke2fs 1.47.4 (6-Mar-2025)
/dev/mapper/secure_vol contains a ext4 file system
  last mounted on /mnt/secure_vol on Tue Jul 28 11:19:08 2026
Proceed anyway? (y,N) y
Creating filesystem with 123904 4k blocks and 123904 inodes
Filesystem UUID: 2dd2a589-ba7b-46e9-be39-d7730a186ac9
Superblock backups stored on blocks:
  32768, 98304

Allocating group tables: done
Writing inode tables: done
Creating journal (4096 blocks): done
Writing superblocks and filesystem accounting information: done

Step 7 - Mount the Filesystem

Commands:

sudo mkdir -p /mnt/secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol

Verify:

findmnt /mnt/secure_vol

Output:

TARGET          SOURCE                 FSTYPE OPTIONS
/mnt/secure_vol /dev/mapper/secure_vol ext4   rw,relatime,seclabel

Step 8 - Write Test Data

Create the confidential file:

echo "MedDefense confidential backup test - Patient MRN MED-50421" | sudo tee /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Create a second file:

sudo cp /etc/hosts /mnt/secure_vol/hosts-backup.txt

List the volume:

sudo ls -lh /mnt/secure_vol

Output:

total 24K
-rw-r--r--. 1 root root  60 Jul 28 11:23 backup_test.txt
-rw-r--r--. 1 root root 649 Jul 28 11:23 hosts-backup.txt
drwx------  2 root root 16K Jul 28 11:22 lost+found

Read the test file:

sudo cat /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Calculate the original hash:

sudo sha256sum /mnt/secure_vol/backup_test.txt

Output:

28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419  /mnt/secure_vol/backup_test.txt

Step 9 - Unmount and Close

Commands:

sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol

Verify:

sudo cryptsetup status secure_vol

Output:

/dev/mapper/secure_vol is inactive.

The correct operational order is:

write data
sync
umount
cryptsetup luksClose

The filesystem must be unmounted before the LUKS mapping is closed.

Part 2 - Raw-File Verification

Step 1 - Inspect the Raw Encrypted Image

Required command:

strings encrypted_volume.img | head -50

Observed output began with LUKS metadata:

LUKS
sha256
8ff06c4c-e1d2-4427-bb66-b86166485e66
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":529866,"cpus":2,...

The output contained LUKS header metadata, random printable fragments, and the UUID. It did not expose the patient record.

Search for the patient MRN:

strings encrypted_volume.img | grep -F "MED-50421"
echo $?

Output:

1

What the Raw-File Test Proves

The raw-file test proves that the patient record is not stored as readable plaintext inside the closed LUKS image.

An attacker who steals or copies encrypted_volume.img can see that the file is a LUKS volume and may see non-secret metadata such as the UUID, cipher, PBKDF, and keyslot configuration. However, the attacker cannot read the stored backup files without unlocking the volume.

This demonstrates encryption at rest against:

stolen disks;

copied image files;

offline access;

unauthorised raw-file inspection.

The test does not protect data while the volume is unlocked and mounted. Malware with sufficient permissions may still read, modify, or delete files through /mnt/secure_vol.

Part 3 - Reopen Verification

Step 1 - Reopen and Mount

Commands:

sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol

The correct passphrase successfully unlocked the volume.

Step 2 - Read the Original File

Command:

sudo cat /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Step 3 - Recalculate the Hash

Command:

sudo sha256sum /mnt/secure_vol/backup_test.txt

Output:

28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419  /mnt/secure_vol/backup_test.txt

The hash after reopening is identical to the original hash:

Before close:
28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419

After reopen:
28801c60a374ab42d5d46e432449f7572c617dd91deebe518d4d83ee3cd4d419

This proves that the encrypted volume preserved the original data without corruption.

Step 4 - Final Close

Commands:

sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol

Final verification:

sudo cryptsetup status secure_vol

Output:

/dev/mapper/secure_vol is inactive.

After closing the volume:

findmnt /mnt/secure_vol
sudo ls -lh /mnt/secure_vol
sudo cat /mnt/secure_vol/backup_test.txt
sudo sha256sum /mnt/secure_vol/backup_test.txt

Output:

total 0
cat: /mnt/secure_vol/backup_test.txt: No such file or directory
sha256sum: /mnt/secure_vol/backup_test.txt: No such file or directory

This is expected because /mnt/secure_vol is only an empty mount-point directory when the encrypted filesystem is not mounted.

Part 4 - LUKS Automation Script

The companion script is:

12-luks_manager.sh

Create Mode

./12-luks_manager.sh create encrypted_volume.img 500

The mode runs:

dd
cryptsetup luksFormat
cryptsetup luksOpen
mkfs.ext4
cryptsetup luksClose

Open Mode

./12-luks_manager.sh open encrypted_volume.img secure_vol /mnt/secure_vol

The mode runs:

cryptsetup luksOpen
mkdir
mount

Close Mode

./12-luks_manager.sh close secure_vol /mnt/secure_vol

The mode runs:

umount
cryptsetup luksClose

Part 5 - MedDefense NAS-01 Backup Encryption Design

NAS-01 Encryption Level

MedDefense should use a layered encryption strategy.

Full-Disk Encryption

Full-disk encryption should be enabled where the NAS platform supports it. It protects operating-system partitions, swap, temporary data, and storage media if the complete device or its drives are stolen.

However, full-disk encryption alone is not sufficient because NAS-01 is normally running and unlocked. An attacker who compromises the live NAS may still access mounted data.

Volume-Level Encryption

The primary control for NAS-01 should be volume-level encryption.

The dedicated backup volume should use:

LUKS2 or an approved NAS equivalent
AES-XTS
strong passphrase protection
multiple controlled recovery keyslots

Volume-level encryption is the most appropriate primary layer because it:

protects every backup stored on the volume;

is transparent to backup software after unlocking;

allows the backup repository to be managed independently;

protects removed drives and offline copies;

avoids manually encrypting every file.

File-Level Encryption

MedDefense should also use file-level encryption or backup-object encryption for backup archives before offsite replication.

Recommended protection:

AES-256-GCM

File-level encryption ensures that backup objects remain encrypted after leaving NAS-01.

Final Recommendation

Full-disk encryption where supported
+
Volume-level encryption for the NAS-01 backup repository
+
File-level encryption for offsite backup objects

Performance Impact

The local image creation completed at approximately:

177 MB/s

This dd result is not a complete encrypted-storage benchmark, because it measured zero-filled image creation rather than encrypted NAS backup throughput.

MedDefense must benchmark the real NAS using:

cryptsetup benchmark

and controlled backup tests.

The production assessment should measure:

unencrypted backup throughput;

encrypted backup throughput;

restore performance;

CPU utilisation;

backup-window completion;

cloud replication duration;

Recovery Time Objective compliance.

Modern CPUs with AES acceleration usually reduce encryption overhead, but MedDefense must use measured results rather than an unsupported percentage estimate.

Encryption Key Storage

The encryption key must be stored NOT on the NAS.

The master recovery key must not be stored unprotected on NAS-01. If an attacker compromises the NAS and obtains both the encrypted backups and the only decryption key, the encryption control is defeated.

Recommended key locations:

Enterprise Key Management System.

Hardware Security Module.

Approved secrets-management platform.

Encrypted offline recovery copy in a physically controlled safe.

Access to the key should require:

MFA;

least privilege;

role-based access control;

full audit logging;

dual approval for key export;

separation between backup administrators and key custodians.

NAS-01 may receive an authorised unlock operation, but the master recovery key must remain external to NAS-01.

What Happens if the Key is Lost?

If the key is lost, the encrypted backup volume becomes permanently unrecoverable.

If the encryption key is lost, MedDefense cannot decrypt or restore:

EHR PostgreSQL backups;

MySQL billing backups;

DICOM and PACS archives;

Active Directory backups;

file-server data;

system configurations;

audit logs.

LUKS has no hidden master password or administrative bypass.

MedDefense must therefore maintain:

multiple controlled recovery keyslots;

at least two authorised key custodians;

an encrypted offline recovery copy;

a protected LUKS header backup;

documented emergency-recovery procedures;

regular key-recovery and restore tests.

Header-backup command:

sudo cryptsetup luksHeaderBackup encrypted_volume.img --header-backup-file encrypted_volume-header.backup

The header backup must be encrypted and stored separately from NAS-01.

Cloud Replica Encryption

The cloud replica must also remain encrypted.

The correct workflow is:

Production system
        |
        v
Backup created
        |
        v
Backup encrypted before leaving MedDefense
        |
        +------------------------------+
        |                              |
        v                              v
NAS-01 encrypted volume          Cloud replica remains encrypted

MedDefense must not decrypt the backup before cloud upload.

The cloud copy should have:

client-side backup-object encryption;

provider-side encryption as a second layer;

immutable object-lock or retention controls.

Cloud Key Ownership

The encryption key used for the cloud replica should remain under MedDefense ownership.

Preferred options:

MedDefense-controlled KMS key

or:

customer-managed cloud KMS key

The cloud provider must not be the only party controlling the key. Provider-managed encryption may be used as an additional layer, but MedDefense must retain control of the client-side backup-encryption key.

Ransomware Limitation

Encryption at rest does not make a mounted NAS ransomware-proof.

When the backup volume is unlocked, ransomware with equivalent permissions may:

read backups;

delete backups;

corrupt backup archives;

encrypt the files again;

remove snapshots.

MedDefense must combine encryption with:

immutable snapshots;

offline or logically isolated copies;

object-lock retention;

separate backup credentials;

network segmentation;

MFA;

restricted management access;

Wazuh monitoring;

regular restore testing.

Encryption protects confidentiality. Immutability and isolation protect availability and recoverability.

Final Conclusion

The laboratory followed the complete and correctly ordered workflow:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
sudo cryptsetup luksFormat encrypted_volume.img
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mkfs.ext4 /dev/mapper/secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
write test data
calculate SHA-256
sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
strings encrypted_volume.img | head -50
search for the plaintext
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
read the original file
verify the matching SHA-256 hash
sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol

The raw-file verification confirmed that the patient MRN was not readable from the closed image. The reopen verification confirmed that the original file remained accessible and produced the same SHA-256 hash after decryption.

For NAS-01, MedDefense should use volume-level encryption as the primary protection layer, full-disk encryption where supported, and file-level encryption for cloud backup objects. The key must be stored NOT on the NAS, the impact if the key is lost must be addressed through tested recovery controls, and the cloud replica must also remain encrypted with a key controlled by MedDefense.

