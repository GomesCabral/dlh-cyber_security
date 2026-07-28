# 22. Implementation Playbook

## Goal

This implementation playbook provides the operational procedure for deploying the highest-priority cryptographic improvements identified during the MedDefense security assessment. Each change includes prerequisites, implementation steps, validation, rollback procedures, maintenance windows, and communication requirements.

---

# Action #1 – Disable Legacy TLS Versions

**Priority:** Immediate

**System Affected:** `portal.meddefense.local`

## Objective

Remove support for TLS 1.0 and TLS 1.1 and allow only TLS 1.2 and TLS 1.3.

## Prerequisites

- Full backup of web server configuration.
- Maintenance window approved.
- Current TLS certificate available.
- Rollback configuration saved.

## Steps

1. Backup the current configuration.

```bash
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
```

2. Edit the TLS configuration.

Example:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

3. Reload the configuration.

```bash
sudo nginx -t
sudo systemctl reload nginx
```

4. Perform an SSL Labs scan.

## Validation

- SSL Labs reports only TLS 1.2 and TLS 1.3.
- HTTPS website loads normally.
- Login succeeds.
- No application errors appear.

## Rollback

Restore backup.

```bash
sudo cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
sudo systemctl reload nginx
```

Maximum acceptable downtime:

**10 minutes**

## Maintenance Window

Overnight

## Communication

Before:

- Infrastructure Team
- SOC
- Help Desk

After:

- Security Manager
- Application Owner

---

# Action #2 – Encrypt NAS-01 Backups with LUKS

**Priority:** Immediate

**System Affected:** `NAS-01`

## Objective

Encrypt all backup storage using LUKS2.

## Prerequisites

- Complete backup verification.
- Recovery procedure tested.
- Encryption passphrase generated.
- Recovery key stored securely.

## Steps

1. Create encrypted volume.

```bash
sudo cryptsetup luksFormat /dev/sdb
```

2. Open the encrypted volume.

```bash
sudo cryptsetup luksOpen /dev/sdb backup_volume
```

3. Create filesystem.

```bash
sudo mkfs.ext4 /dev/mapper/backup_volume
```

4. Mount filesystem.

```bash
sudo mount /dev/mapper/backup_volume /backup
```

5. Restore backup files.

## Validation

- Backup jobs complete successfully.
- Backup files are readable after mounting.
- `strings` on the raw device does not reveal plaintext.

## Rollback

Restore backups to previous storage.

Unmount.

```bash
sudo umount /backup
sudo cryptsetup luksClose backup_volume
```

Maximum acceptable downtime:

**30 minutes**

## Maintenance Window

Weekend overnight.

## Communication

- Backup Administrator
- Infrastructure Team
- Security Team

---

# Action #3 – Encrypt PostgreSQL Patient Database

**Priority:** Immediate

**System Affected:** `ehr-db-01`

## Objective

Protect ePHI stored in PostgreSQL using AES-256 encryption.

## Prerequisites

- Database backup.
- Maintenance window approved.
- Application testing environment available.

## Steps

1. Backup database.

```bash
pg_dump ehr > ehr_backup.sql
```

2. Enable encrypted storage.

3. Configure database encryption.

4. Restart PostgreSQL.

```bash
sudo systemctl restart postgresql
```

5. Verify application connectivity.

## Validation

- Database starts correctly.
- Application connects.
- Queries return expected results.
- No corruption detected.

## Rollback

Restore database backup.

```bash
psql ehr < ehr_backup.sql
```

Maximum acceptable downtime:

**30 minutes**

## Maintenance Window

Weekend overnight.

## Communication

- Database Administrator
- Clinical Systems Team
- Security Team

---

# Action #4 – Implement Centralized Key Management

**Priority:** Phase 1

**System Affected:**

- ehr-db-01
- NAS-01
- portal.meddefense.local
- VPN Gateway

## Objective

Move encryption keys into a centralized HSM/KMS.

## Prerequisites

- HSM or KMS deployed.
- Administrator training completed.
- Recovery procedures documented.

## Steps

1. Deploy HSM/KMS.

2. Import encryption keys.

3. Update applications to retrieve keys securely.

4. Test encryption and decryption.

5. Remove locally stored keys.

## Validation

- Applications retrieve keys successfully.
- Encryption works normally.
- Local plaintext keys no longer exist.

## Rollback

Restore previous key storage.

Restart affected services.

Maximum acceptable downtime:

**15 minutes**

## Maintenance Window

Weekend.

## Communication

- PKI Administrator
- Security Team
- Infrastructure Manager

---

# Action #5 – Deploy Certificate Monitoring and Renewal

**Priority:** Phase 1

**System Affected**

- portal.meddefense.local
- VPN
- EHR
- Email
- Internal Services

## Objective

Prevent certificate expiration through automated monitoring.

## Prerequisites

- Certificate inventory completed.
- Monitoring platform configured.
- Email notification system operational.

## Steps

1. Register every certificate.

2. Configure expiration monitoring.

3. Configure alerts:

- 90 days
- 60 days
- 30 days
- 7 days

4. Test notifications.

5. Verify renewal process.

## Validation

- Alerts generated successfully.
- Certificate inventory updated.
- Test renewal completed.

## Rollback

Disable monitoring rules.

Restore previous monitoring configuration.

Maximum acceptable downtime:

**No downtime expected**

## Maintenance Window

Business hours acceptable.

## Communication

Before:

- Infrastructure Team
- Security Team

After:

- IT Manager
- SOC Team

---

# Deployment Order

| Order | Action | Priority |
|--------|---------|----------|
| 1 | Disable TLS 1.0 / TLS 1.1 | Immediate |
| 2 | Encrypt NAS-01 using LUKS | Immediate |
| 3 | Encrypt PostgreSQL (ehr-db-01) | Immediate |
| 4 | Deploy HSM/KMS for Key Management | Phase 1 |
| 5 | Implement Certificate Monitoring | Phase 1 |

---

# Post-Implementation Verification Checklist

- TLS 1.0 and TLS 1.1 disabled.
- SSL Labs grade A or higher.
- Backups encrypted with LUKS.
- Database encryption operational.
- Encryption keys stored in HSM/KMS.
- Certificates monitored automatically.
- Alert thresholds configured.
- Backup recovery tested.
- Incident documentation updated.
- Security documentation reviewed.

---

# Success Criteria

The implementation is considered successful when:

- All patient data is encrypted at rest and in transit.
- Legacy cryptographic protocols have been removed.
- Encryption keys are centrally managed.
- Certificate expiration is continuously monitored.
- No production service experiences unplanned downtime.
- HIPAA cryptographic requirements are significantly improved.
- MedDefense's overall cryptographic posture is strengthened and aligned with current security best practices.
