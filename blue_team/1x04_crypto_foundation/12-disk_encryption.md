12. The Disk Encryption Lab

Goal

This laboratory demonstrates how to protect data at rest with Linux Unified Key Setup (LUKS). A 500 MB virtual disk is created, formatted with LUKS2, opened, formatted with ext4, mounted, populated with test data, unmounted, closed, inspected as a raw encrypted file, reopened, and verified.

The exercise connects directly to the MedDefense finding that NAS-01 stores backup data in plaintext.

Finding: NAS-01 stores all backups without encryption.

Risk: Anyone who steals the NAS disks or gains offline access can read patient records, billing data, DICOM images, and system backups.

Required control: Encrypt NAS-01 at rest, store the encryption keys outside the NAS, and ensure that offsite replicas also remain encrypted.

Part 1 - LUKS Setup

Step 1 - Verify the Required Tool

Command:

cryptsetup --version

Output:

[PASTE YOUR REAL OUTPUT HERE]

If cryptsetup is not installed:

sudo apt update
sudo apt install -y cryptsetup

Step 2 - Create a 500 MB Virtual Disk

Required command:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500

Optional version with progress information:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500 status=progress

Output:

[PASTE YOUR REAL OUTPUT HERE]

Verify the image:

ls -lh encrypted_volume.img

Output:

[PASTE YOUR REAL OUTPUT HERE]

Explanation

The file encrypted_volume.img acts as a virtual block device. It allows LUKS operations to be practised safely without modifying a physical disk or partition.

Step 3 - Format the Image with LUKS2

Required command:

sudo cryptsetup luksFormat encrypted_volume.img

Explicit LUKS2 command used in this laboratory:

sudo cryptsetup luksFormat --type luks2 encrypted_volume.img

When prompted, type:

YES

Then enter and confirm a strong passphrase.

Output:

[PASTE YOUR REAL OUTPUT HERE]

Explanation

luksFormat creates the LUKS header, generates the internal volume-encryption key, and protects that key using the supplied passphrase. The passphrase itself must never be stored in Git, in the report, or beside the encrypted volume.

Step 4 - Inspect the LUKS Header

Command:

sudo cryptsetup luksDump encrypted_volume.img

Output:

[PASTE YOUR REAL OUTPUT HERE]

Relevant fields include:

LUKS version;

cipher;

cipher mode;

key size;

PBKDF;

UUID;

keyslots.

Explanation

The LUKS header contains metadata and protected keyslot material. It does not contain the plaintext files stored inside the encrypted data area.

Step 5 - Open the Encrypted Volume

Required command:

sudo cryptsetup luksOpen encrypted_volume.img secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Verify the mapping:

sudo cryptsetup status secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

The decrypted block-device mapping should now exist at:

/dev/mapper/secure_vol

Explanation

luksOpen unlocks the internal volume key and creates a device-mapper target. Applications access /dev/mapper/secure_vol as a normal block device while encryption and decryption occur transparently underneath.

Step 6 - Create an ext4 Filesystem

Required command:

sudo mkfs.ext4 /dev/mapper/secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Explanation

LUKS provides encrypted blocks, but it does not create a filesystem. The mkfs.ext4 command creates the filesystem needed to store normal files and directories.

Step 7 - Create the Mount Point and Mount the Volume

Create the mount point:

sudo mkdir -p /mnt/secure_vol

Required mount command:

sudo mount /dev/mapper/secure_vol /mnt/secure_vol

Verify the mount:

findmnt /mnt/secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Explanation

After mounting, /mnt/secure_vol behaves like a normal directory. Files written there are stored inside the encrypted LUKS volume.

Step 8 - Write Test Data

Create the MedDefense test file:

echo "MedDefense confidential backup test - Patient MRN MED-50421" | sudo tee /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Create another test file:

sudo cp /etc/hosts /mnt/secure_vol/hosts-backup.txt

List the contents:

sudo ls -lh /mnt/secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Read the confidential file:

sudo cat /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Calculate the original SHA-256 hash:

sudo sha256sum /mnt/secure_vol/backup_test.txt

Output:

[PASTE YOUR REAL OUTPUT HERE]

Step 9 - Unmount and Close the LUKS Volume

Flush pending writes:

sync

Required unmount command:

sudo umount /mnt/secure_vol

Required close command:

sudo cryptsetup luksClose secure_vol

Verify that the mapping is closed:

sudo cryptsetup status secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Expected state:

/dev/mapper/secure_vol is inactive.

Operational Order

The correct order is:

write data
sync
umount
cryptsetup luksClose

The filesystem must be unmounted before the LUKS mapping is closed. Closing the mapping first could cause filesystem errors or data loss.

Part 2 - Verification

Step 1 - Inspect the Raw Encrypted Image

Required command:

strings encrypted_volume.img | head -50

Output:

[PASTE YOUR REAL OUTPUT HERE]

Search for the exact confidential sentence:

strings encrypted_volume.img | grep -F "MedDefense confidential backup test"

Output:

[PASTE YOUR REAL OUTPUT HERE]

Check the exit code immediately:

echo $?

Expected result when no plaintext is found:

1

Search for the patient MRN:

strings encrypted_volume.img | grep -F "MED-50421"

Expected result:

No output

What the Raw-File Test Proves

The test proves that the confidential data is not stored as readable plaintext in the closed LUKS image. Someone who steals or copies encrypted_volume.img sees encrypted blocks rather than the original files.

The test demonstrates confidentiality at rest against:

stolen physical disks;

copied image files;

offline forensic access;

unauthorised access to unmounted storage.

The test does not prove that the volume is safe while it is unlocked. When /dev/mapper/secure_vol is open and mounted, authorised processes and malware with equivalent permissions can read or modify the plaintext files.

Some printable LUKS header metadata may appear in strings output. This does not mean that the stored backup contents are exposed. LUKS protects the encrypted data area, not the existence or basic metadata of the encrypted volume.

Step 2 - Reopen the Volume

Required command:

sudo cryptsetup luksOpen encrypted_volume.img secure_vol

Mount the filesystem again:

sudo mount /dev/mapper/secure_vol /mnt/secure_vol

Verify:

findmnt /mnt/secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Step 3 - Read and Verify the Stored Data

Read the test file:

sudo cat /mnt/secure_vol/backup_test.txt

Output:

MedDefense confidential backup test - Patient MRN MED-50421

Calculate the SHA-256 hash again:

sudo sha256sum /mnt/secure_vol/backup_test.txt

Output:

[PASTE YOUR REAL OUTPUT HERE]

The second hash must match the original hash captured before the first close operation.

Verification Result

A matching hash proves that the data remained intact through the following cycle:

write
unmount
close
raw-image inspection
reopen
mount
read
hash comparison

Step 4 - Final Unmount and Close

sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol

Verify:

sudo cryptsetup status secure_vol

Output:

[PASTE YOUR REAL OUTPUT HERE]

Part 3 - LUKS Automation Script

The companion script is:

12-luks_manager.sh

Create Mode

./12-luks_manager.sh create encrypted_volume.img 500

The create mode performs:

dd image creation;

cryptsetup luksFormat;

cryptsetup luksOpen;

mkfs.ext4;

cryptsetup luksClose.

Open Mode

./12-luks_manager.sh open encrypted_volume.img secure_vol /mnt/secure_vol

The open mode performs:

cryptsetup luksOpen;

mount-point creation;

filesystem mounting.

Close Mode

./12-luks_manager.sh close secure_vol /mnt/secure_vol

The close mode performs:

umount;

cryptsetup luksClose.

Prepare the script:

chmod +x 12-luks_manager.sh

Validate the syntax:

bash -n 12-luks_manager.sh

No output means that Bash detected no syntax error.

Part 4 - MedDefense NAS-01 Backup Encryption Design

4.1 Encryption Level for NAS-01

MedDefense should use a layered encryption design rather than relying on a single encryption level.

Full-Disk Encryption

Full-disk encryption protects the entire physical NAS disk, including operating-system partitions, temporary files, swap space, and backup storage areas.

It is useful against:

theft of the complete NAS;

removal of physical drives;

offline analysis of powered-off storage.

However, full-disk encryption alone is not sufficient for NAS-01 because the disks are normally unlocked while the NAS is running. An attacker who compromises the live NAS through the network may still access mounted plaintext data.

Volume-Level Encryption

The primary recommended control for NAS-01 is volume-level encryption.

The dedicated backup volume should be encrypted with:

LUKS2 with AES-XTS

or the equivalent enterprise encryption feature supported by the production NAS platform.

Volume-level encryption is appropriate because:

it protects all files stored on the backup volume;

it is transparent to the backup software after unlocking;

it is simpler to administer than encrypting every individual file;

it separates the backup data volume from other NAS functions;

it supports controlled mounting, recovery, and key rotation procedures.

File-Level or Backup-Object Encryption

MedDefense should also use file-level encryption or backup-object encryption for each backup set before replication.

Recommended encryption for portable backup objects:

AES-256-GCM

This additional layer is required because volume-level encryption protects the physical NAS storage, but it does not automatically protect backup objects copied to another system or cloud provider.

Final Encryption-Layer Decision

The recommended design is:

Full-disk encryption where supported
+
Volume-level encryption for the NAS-01 backup volume
+
File-level or backup-object encryption before offsite replication

The most important production layer for NAS-01 is volume-level encryption, because it protects the complete backup repository while remaining operationally manageable. File-level encryption adds end-to-end protection for replicated copies.

4.2 Performance Impact

Encryption introduces CPU and I/O overhead, but the impact must be measured on the real NAS hardware rather than assumed.

Use the Task 1 performance results:

Unencrypted throughput: [INSERT T1 RESULT]
Encrypted throughput: [INSERT T1 RESULT]
Measured overhead: [INSERT CALCULATION]

Calculation:

Overhead percentage =
((unencrypted throughput - encrypted throughput)
 / unencrypted throughput) × 100

MedDefense should also run:

cryptsetup benchmark

and perform controlled backup and restore tests.

The production test must measure:

backup throughput;

restore throughput;

CPU utilisation;

backup-window completion;

offsite replication duration;

impact on the Recovery Time Objective.

Modern CPUs with AES hardware acceleration may keep the overhead modest, but the final design must be based on measured NAS-01 results.

4.3 Encryption-Key Storage

The encryption key must be stored NOT on the NAS. More precisely, the master recovery key must not be stored unprotected on NAS-01.

If the NAS contains both:

the encrypted backups

and:

the only decryption key

then a ransomware operator or administrator who compromises NAS-01 may obtain both items and defeat the encryption.

The preferred key-storage hierarchy is:

enterprise Key Management System;

Hardware Security Module;

approved secrets-management platform;

encrypted offline emergency recovery copy in a physically controlled safe.

Key access should require:

multi-factor authentication;

least privilege;

role-based access control;

full audit logging;

dual approval for key export;

separation between backup administrators and key custodians.

NAS-01 may receive an authorised unlock operation during boot or recovery, but the master recovery key must remain external to the NAS.

4.4 Impact of a Lost Key

If all valid passphrases, keyslots, recovery keys, and protected header backups are lost, the encrypted backups become permanently unrecoverable.

There is no master password, administrative bypass, or legitimate cryptographic back door.

Loss of the key could prevent MedDefense from restoring:

PostgreSQL EHR records;

MySQL billing data;

PACS and DICOM images;

Active Directory backups;

file-server data;

audit logs;

system configurations.

This would turn a confidentiality control into a major availability incident.

MedDefense must therefore maintain:

multiple controlled recovery methods;

at least two authorised key custodians;

a protected LUKS header backup;

offline recovery material;

documented emergency procedures;

regular restore and key-recovery exercises.

Example LUKS header-backup command:

sudo cryptsetup luksHeaderBackup encrypted_volume.img --header-backup-file encrypted_volume-header.backup

The header backup must be encrypted and stored separately from NAS-01.

4.5 Offsite and Cloud Replica Encryption

The offsite backup replica must also remain encrypted.

The correct replication model is:

Production system
        |
        v
Backup application creates backup
        |
        v
Backup object encrypted before leaving MedDefense
        |
        +-----------------------------+
        |                             |
        v                             v
NAS-01 encrypted volume         Cloud or offsite replica
                                remains encrypted

MedDefense should not decrypt the backup before cloud upload.

The cloud replica should be protected by:

client-side backup-object encryption controlled by MedDefense;

provider-side encryption as a second layer;

immutable object-lock or retention controls.

Key Ownership

MedDefense should control the key used to encrypt the backup object.

Preferred options:

MedDefense-controlled KMS key

or:

customer-managed cloud KMS key

The cloud provider must not be the only party controlling the key. Provider-managed encryption alone does not fully protect against:

cloud-account compromise;

provider administrator misuse;

accidental access-policy changes;

cross-tenant configuration errors;

unauthorised snapshot exposure.

The cloud provider may manage an additional storage-encryption key, but MedDefense must retain control of the client-side backup-encryption key.

4.6 Key Separation

MedDefense should not use one universal key for every encryption purpose.

Recommended separation:

Purpose

Key

NAS-01 full-disk encryption

Key A

NAS-01 backup-volume encryption

Key B

Backup-object encryption

Key C

Cloud key wrapping

Key D

Test and development restores

Key E

Key separation reduces the blast radius of a single key compromise and makes rotation, revocation, and auditing easier.

4.7 Ransomware Limitation

Encryption at rest does not make an unlocked NAS ransomware-proof.

When the volume is mounted, authorised applications can read and write plaintext. Malware with equivalent permissions may:

delete backups;

corrupt backup files;

encrypt the mounted backups again;

remove snapshots;

disable recovery services.

MedDefense must combine encryption with:

immutable snapshots;

offline or logically isolated backup copies;

object-lock retention;

separate backup credentials;

network segmentation;

MFA for administrators;

restricted NAS management access;

Wazuh monitoring;

regular restore testing.

Encryption protects confidentiality. Immutability, isolation, and access control protect availability and recoverability.

MedDefense Backup Encryption Summary

Requirement

Recommendation

Full-disk encryption

Enable where supported to protect the complete NAS device

Primary NAS-01 encryption layer

Volume-level encryption

Volume technology

LUKS2 or approved NAS equivalent

Block-device cipher mode

AES-XTS

File-level or backup-object encryption

AES-256-GCM

Key stored on NAS-01

Not as the sole or unprotected recovery key

Primary key location

External KMS or HSM

Lost-key impact

Backups become permanently unrecoverable

Header backup

Required, encrypted, and stored separately

Cloud replica encryption

Mandatory

Cloud key ownership

MedDefense-controlled or customer-managed key

Provider-side encryption

Additional layer only

Immutable backups

Required

Restore testing

Regular and documented

Administrative access

MFA and least privilege

Monitoring

Wazuh and audit logs

Final Conclusion

This laboratory follows the complete operational sequence:

dd if=/dev/zero of=encrypted_volume.img bs=1M count=500
sudo cryptsetup luksFormat encrypted_volume.img
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mkfs.ext4 /dev/mapper/secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
write test data
sync
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol
strings encrypted_volume.img | head -50
sudo cryptsetup luksOpen encrypted_volume.img secure_vol
sudo mount /dev/mapper/secure_vol /mnt/secure_vol
verify the data
sudo umount /mnt/secure_vol
sudo cryptsetup luksClose secure_vol

The raw-file test demonstrates that closed LUKS storage protects the confidentiality of data at rest. The reopen-and-read test demonstrates that authorised users with the correct passphrase can recover the original data without corruption.

For NAS-01, MedDefense should use volume-level encryption as the primary control, full-disk encryption where supported, and file-level backup-object encryption for offsite replication. The keys must be stored outside NAS-01, key-loss recovery must be planned and tested, and every cloud replica must remain encrypted with a key controlled by MedDefense.

