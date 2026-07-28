14. Hardware Security and Key Management

Goal

This document compares TPM, HSM, Secure Enclave, and software KMS technologies and defines a practical key management strategy for MedDefense.

The objective is to solve the central encryption problem: protecting the encryption keys separately from the data they protect.

Part 1 - Technology Comparison

Technology

What It Is

What It Protects

Typical Cost

Typical Deployment

TPM

A hardware security chip built into or attached to a computer motherboard that provides a hardware root of trust and securely stores device-specific secrets.

Disk-encryption keys, measured boot values, device identity keys, Windows Hello credentials, and BitLocker protectors.

Usually included in modern business computers; little or no additional hardware cost.

Employee laptops, desktops, servers, and endpoints requiring secure boot and device-bound key protection.

HSM

A dedicated tamper-resistant hardware appliance or cloud service that generates, stores, and uses cryptographic keys without exposing private key material to normal system memory.

Enterprise encryption keys, database master keys, certificate-authority keys, code-signing keys, payment keys, and high-value TLS private keys.

Managed HSM-backed key services may cost approximately $1–$2 per key per month. Dedicated cloud HSM instances cost much more and may exceed $1 per hour per HSM, before redundancy.

Centralised enterprise PKI, regulated databases, certificate authorities, payment systems, and high-value cryptographic operations.

Secure Enclave

An isolated security subsystem built into a processor or system-on-chip and separated from the main operating system and application processor.

Biometric templates, device-bound encryption keys, authentication secrets, and sensitive cryptographic operations.

Included in supported devices; no separate purchase cost.

Apple devices, selected mobile devices, modern processors, and endpoint authentication systems.

KMS (Software)

A centralised software or cloud service that creates, stores, rotates, authorises, logs, and distributes encryption keys through controlled APIs.

Database keys, backup keys, application secrets, cloud-storage keys, and envelope-encryption master keys.

Commonly approximately $1 per customer-managed key per month, plus API usage and logging costs.

Cloud workloads, database encryption, backup encryption, application encryption, and centralised enterprise key management.

TPM - Best Choice

A TPM is the best choice when a key must be bound to one physical device, such as protecting a BitLocker key on an employee laptop.

A TPM is not designed to act as a central enterprise key vault for many servers and applications.

HSM - Best Choice

An HSM is the best choice when high-value keys must never be exportable in plaintext and cryptographic operations must occur inside tamper-resistant hardware.

HSMs are appropriate for certificate-authority keys, database key-encryption keys, and other keys whose compromise would expose large amounts of regulated data.

Secure Enclave - Best Choice

A Secure Enclave is the best choice for protecting device-local credentials, biometrics, and encryption keys on supported endpoints.

It is not a centralised key management platform for MedDefense servers.

KMS - Best Choice

A software or cloud KMS is the best choice when MedDefense needs centralised key lifecycle management, access control, logging, rotation, and integration with databases, backups, and cloud systems.

A KMS may itself be backed by HSMs while still providing a simpler and lower-cost management interface.

Part 2 - MedDefense Key Management Design

Key Management Principles

MedDefense must follow these principles:

Encryption keys must be stored separately from the encrypted data.

Master keys must not be stored in plaintext configuration files.

Keys must be accessed through authenticated and authorised APIs.

Key access must follow least privilege.

Key usage must be logged.

Keys must have documented owners.

Keys must be rotated according to risk.

Compromised keys must be revoked and replaced immediately.

Recovery keys must be protected separately from production systems.

A lost key must not make all recovery impossible.

Key Inventory

MedDefense System

Key Type

Recommended Storage

Patient database on ehr-db-01

Database key-encryption key and data-encryption keys

Central KMS backed by an HSM

NAS-01 backup storage

LUKS recovery key and backup-object encryption key

KMS/HSM plus encrypted offline escrow copy

Patient portal TLS

ECC P-256 private key

Web-server protected key store; HSM-backed storage preferred for production

VPN tunnels

IKE/IPsec pre-shared secrets or certificate private keys

FortiGate secure storage or HSM-backed certificate store

Employee laptops

BitLocker or equivalent disk-encryption keys

Device TPM, with recovery key escrow in central directory/KMS

Internal CA, if deployed

Root and intermediate CA private keys

Offline HSM for root CA and HSM-backed storage for intermediate CA

2.1 Patient Database Keys

Storage Location

The PostgreSQL database key-encryption key must be stored in a central KMS backed by an HSM.

The database server may receive a short-lived data-encryption key, but the master key must not be stored in:

a plaintext configuration file;

application source code;

an environment file committed to Git;

the PostgreSQL data directory;

a backup stored on NAS-01.

Envelope encryption should be used:

HSM-backed KMS master key
        |
        v
Encrypts data-encryption key
        |
        v
Data-encryption key encrypts database records

Authorised Roles

Access should be limited to:

Security Engineer: key policy and technical management;

Database Administrator: authorised use of the key through the database service, but no plaintext key export;

IT Director: approval of emergency recovery operations;

Security Officer or Compliance Officer: audit review;

Application service account: decrypt operations only for authorised application workflows.

Rotation

Master key-encryption key: annually.

Data-encryption keys: every 90 days or after a defined volume of encryption operations.

Immediate rotation after suspected compromise, staff departure involving key access, or major application compromise.

Rotation should use key versioning so that old data can be decrypted while it is gradually re-encrypted under the new key.

Compromise Procedure

Disable the compromised key version.

Block affected service accounts.

Create a new key version.

Re-encrypt affected data-encryption keys.

Re-encrypt sensitive records where required.

review KMS and database audit logs;

investigate the source of compromise;

notify governance and compliance roles;

assess breach-notification obligations;

permanently revoke the old key after migration and validation.

Lost-Key Recovery

The master key must have controlled recovery through the KMS/HSM backup process.

A recovery operation must require:

two authorised approvers;

MFA;

documented incident or disaster-recovery ticket;

complete audit logging.

If every valid master key and backup is lost, the encrypted patient records become unrecoverable.

2.2 NAS-01 Backup Keys

Storage Location

The LUKS recovery key and backup-object encryption key must be stored NOT on NAS-01.

They should be stored in:

the central KMS/HSM;

an encrypted offline recovery medium;

a physically controlled safe as a secondary escrow location.

NAS-01 may receive an authorised unlock operation, but it must not contain the only usable recovery key.

Authorised Roles

Access should be limited to:

Backup Administrator: routine backup operations through approved automation;

Security Engineer: key lifecycle administration;

IT Director: emergency recovery approval;

second authorised key custodian: dual-control approval.

Rotation

Backup-object encryption key: annually.

NAS volume recovery passphrase: annually or after privileged staff changes.

Immediate rotation after suspected NAS compromise.

Older backup sets may retain their original key version until expiry, but every required key version must remain protected until the corresponding backups reach the end of retention.

Compromise Procedure

Isolate NAS-01.

Disable the compromised key or key version.

create a replacement key;

unlock and validate known-good backups in a controlled environment;

re-encrypt active backup sets where practical;

rotate NAS credentials and recovery passphrases;

inspect replication and access logs;

verify that offsite immutable copies were not modified;

revoke the old key after migration.

Lost-Key Recovery

Recovery must use the protected escrow copy and the LUKS header backup.

If the key is lost and no valid recovery copy exists, the encrypted backups are permanently unrecoverable.

2.3 Patient Portal TLS Key

Storage Location

The portal ECC P-256 private key should be stored:

with restrictive permissions on the web server for the current deployment; or

in an HSM-backed TLS key store for the preferred production design.

The private key must never be:

committed to Git;

sent by email;

included in the CSR;

stored in an unencrypted backup;

copied to administrator workstations without approval.

Authorised Roles

PKI or Security Engineer: certificate and private-key lifecycle;

Web Administrator: certificate installation through an approved process;

IT Director: emergency replacement approval;

Compliance Officer: audit access only.

Rotation

The TLS private key should be replaced during every certificate renewal or at least annually.

For automated short-lived certificates, a new private key should be generated during the automated renewal workflow where operationally supported.

Compromise Procedure

Remove the exposed key from all repositories and systems.

Revoke the associated certificate.

Generate a new private key.

Generate a new CSR.

obtain a replacement certificate;

install and verify the new certificate;

remove the old certificate and key;

inspect logs for impersonation or unauthorised use;

rotate any related application secrets.

Lost-Key Recovery

A lost TLS private key should normally be replaced rather than recovered.

Generate a new key and certificate because retaining recoverable copies of every TLS private key increases exposure.

2.4 VPN Tunnel Keys

Storage Location

VPN certificate private keys should be stored in the FortiGate secure key store or an HSM-backed certificate store.

If pre-shared keys are used temporarily, they must be stored in an approved secrets manager and never in plaintext documentation.

Authorised Roles

Network Security Engineer: VPN configuration and key rotation;

Security Engineer: certificate and key policy;

IT Director: emergency approval;

SOC Analyst: log review, but no key access.

Rotation

Pre-shared keys: every 90 days.

VPN certificates: annually or according to certificate validity.

Immediate replacement after firewall compromise or administrator credential compromise.

Compromise Procedure

Disable the affected tunnel.

revoke the compromised certificate or pre-shared key;

generate a replacement;

update both tunnel endpoints;

validate connectivity and encryption;

inspect VPN logs;

investigate possible interception or unauthorised access.

Lost-Key Recovery

A lost VPN key should be replaced.

A controlled backup may be retained for disaster recovery, but it must be encrypted and access-controlled.

Key Rotation Schedule

Key

Normal Rotation

Emergency Rotation Trigger

Database master key

Annually

Suspected compromise or unauthorised access

Database data-encryption keys

Every 90 days

Database or application compromise

NAS recovery key

Annually

NAS compromise or privileged staff departure

Backup-object key

Annually

Backup or cloud-account compromise

Portal TLS private key

Every certificate renewal or annually

Private-key exposure

VPN pre-shared key

Every 90 days

Firewall or administrator compromise

VPN certificate key

Annually

Certificate or firewall compromise

Laptop recovery keys

On device reprovisioning or security event

Device or account compromise

Access-Control Matrix

Role

Database Keys

Backup Keys

TLS Keys

VPN Keys

Audit Logs

IT Director

Emergency approval

Emergency approval

Emergency approval

Emergency approval

Read

Security Engineer

Manage

Manage

Manage

Policy/manage

Read

Database Administrator

Use only

No

No

No

Limited

Backup Administrator

No

Use only

No

No

Limited

Web Administrator

No

No

Install/use only

No

Limited

Network Security Engineer

No

No

No

Manage

Read

SOC Analyst

No

No

No

No

Read

Compliance Officer

No

No

No

No

Read

No individual should be able to export a master key and decrypt regulated data without oversight.

Key Logging and Monitoring

The KMS/HSM must log:

key creation;

key use;

decrypt operations;

policy changes;

failed access attempts;

key rotation;

key disablement;

key deletion scheduling;

recovery operations;

administrative access.

Wazuh or the selected SIEM should alert on:

unusual decrypt volume;

decrypt requests outside normal hours;

unauthorised service accounts;

failed key-access attempts;

emergency key export;

key-policy modification;

disabled logging;

use of an old or revoked key version.

Part 3 - The HSM Decision

Relevant Risk

The relevant MedDefense risk is compromise of the patient-database encryption key.

If the key is stored in a plaintext configuration file on ehr-db-01, an attacker who compromises the server may obtain both:

the encrypted patient data

and:

the decryption key

This would expose approximately 50,000 patient records and invalidate the primary benefit of database encryption.

The Risk Register should therefore include a risk similar to:

Risk

Threat

Vulnerability

Impact

Database encryption-key compromise

External attacker, ransomware operator, or malicious insider

Key stored on the same server or accessible to the application without hardware protection

Large-scale disclosure of regulated patient data

Cost Options

Option 1 - HSM-Backed Managed KMS

The project assumption states that managed HSM-backed key services may cost approximately:

$1–$2 per key per month

Assuming four managed production keys:

Database master key
Backup master key
Portal key
VPN or internal PKI key

Estimated annual key-storage cost:

4 keys × $2 × 12 months = $96 per year

API requests, logging, and integration may add a small additional cost.

Option 2 - Dedicated Cloud HSM

A dedicated single-tenant cloud HSM is priced by the hour and can exceed:

$1 per HSM per hour

At an illustrative rate of $1.45 per hour:

$1.45 × 24 × 365 = $12,702 per HSM per year

A resilient two-HSM deployment would be approximately:

$25,404 per year

before data transfer, engineering, monitoring, and support costs.

This is a different service class from a low-cost HSM-backed managed KMS.

ALE Comparison

Using the MedDefense quantified risk level from the prior risk assessment:

Relevant annualised loss exposure: $120,000

Managed KMS Cost Comparison

Annual managed key cost: approximately $96
ALE: $120,000

Expected cost as a percentage of ALE:

$96 / $120,000 × 100 = 0.08%

Dedicated HSM Cost Comparison

Using a resilient two-HSM estimate:

Annual dedicated HSM cost: approximately $25,404
ALE: $120,000

Expected cost as a percentage of ALE:

$25,404 / $120,000 × 100 = 21.17%

Decision

MedDefense should invest in HSM-backed key management, but it should begin with a managed KMS whose root keys are protected by provider HSMs.

This option is justified because:

the annual cost is very small compared with the $120,000 ALE;

keys are separated from the encrypted database;

master key material is not stored in plaintext on ehr-db-01;

access is centrally controlled and logged;

rotation and revocation can be automated;

the design supports database, backup, portal, and VPN keys;

it avoids the operational complexity of managing dedicated HSM appliances.

MedDefense should not initially deploy a dedicated two-node CloudHSM cluster unless:

a regulator requires dedicated single-tenant HSMs;

MedDefense deploys its own certificate authority;

key volume or cryptographic transaction volume increases significantly;

managed KMS controls no longer meet the risk or compliance requirement.

Cost-Benefit Conclusion

The investment is justified.

Using the project estimate of $1–$2 per key per month, the managed HSM-backed KMS cost is negligible compared with the annualised risk of database-key compromise.

The recommended decision is:

Approve managed HSM-backed KMS now.
Do not purchase dedicated HSM appliances at the current scale.
Review the dedicated-HSM requirement annually.

Final Conclusion

TPMs, HSMs, Secure Enclaves, and software KMS platforms solve different key-protection problems.

TPMs protect device-bound keys.

Secure Enclaves protect keys and credentials on supported endpoints.

HSMs protect high-value enterprise keys in tamper-resistant hardware.

KMS platforms provide centralised lifecycle management, access control, logging, and rotation.

For MedDefense, the recommended architecture is a central HSM-backed KMS for database, backup, TLS, and VPN key management; TPM protection for employee laptop encryption keys; and controlled offline escrow for recovery keys.

The database master key must never be stored on the same server as the encrypted patient database. A managed HSM-backed KMS provides the best balance of security, cost, auditability, and operational simplicity for MedDefense's current size and risk profile.

