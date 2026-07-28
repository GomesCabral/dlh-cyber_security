# 13. The Encryption Levels

## Goal

Compare the six encryption levels defined in Security+ and recommend the appropriate encryption level for each MedDefense data store.

---

# Part 1 - Encryption Level Comparison

| Encryption Level | Scope | Performance Impact | Key Management | Best Use Case |
|------------------|-------|--------------------|----------------|---------------|
| **Full-disk** | Entire physical or virtual disk | Low | Simple (single disk key) | Protect laptops, desktops and servers against physical theft. |
| **Partition** | One logical partition | Low | Simple | Protect a specific partition while leaving other partitions unchanged. |
| **Volume** | One logical volume (can span multiple disks) | Low to Medium | Moderate | Protect storage volumes such as NAS backup repositories or SAN volumes. |
| **File** | Individual files | Medium | Moderate | Protect sensitive documents before sharing or storing externally. |
| **Database** | Entire database or tablespace | Medium | Moderate to High | Protect complete databases while allowing normal database operations. |
| **Record** | Individual fields or records | High | High | Protect highly sensitive information such as SSNs or credit card numbers from database administrators or application users. |

---

## Best Choice for Each Encryption Level

### Full-disk Encryption

Best used when the entire operating system and all stored files must be protected against physical theft.

### Partition Encryption

Best used when only one partition requires protection while other partitions remain unencrypted.

### Volume Encryption

Best used when protecting shared storage volumes, backup repositories or NAS storage.

### File Encryption

Best used when protecting individual confidential files that may be copied, emailed or stored outside the organisation.

### Database Encryption

Best used when an entire database must be encrypted while remaining fully functional for database services.

### Record Encryption

Best used when only highly sensitive database fields require additional protection from privileged users.

---

# Part 2 - MedDefense Encryption Level Map

| MedDefense Data Store | Recommended Encryption Level | Justification |
|------------------------|------------------------------|---------------|
| **Patient records in PostgreSQL (ehr-db-01)** | **Record-level encryption** | Protect sensitive patient fields such as diagnoses, SSNs and medical identifiers even if the database is accessed by privileged users. |
| **Backup data on NAS-01** | **Volume-level encryption** | Encrypt the entire backup repository while allowing backup software to operate normally after the volume is unlocked. |
| **Financial records in MySQL (billing-srv-01)** | **Database encryption** | Protect the complete financial database while maintaining normal SQL operations and backup processes. |
| **Medical images on PACS (pacs-srv-01)** | **Volume-level encryption** | Protect all DICOM image storage with minimal performance impact and simple administration. |
| **Email data in O365** | **File-level encryption** | Protect sensitive email attachments and exported mailbox files containing confidential information. |
| **Employee laptops** | **Full-disk encryption** | Protect the entire device against data disclosure if the laptop is lost or stolen. |
| **BD Alaris pump firmware/configuration** | **File-level encryption** | Protect firmware and configuration files against unauthorised disclosure or modification before deployment. |

---

# Conclusion

Different encryption levels protect different parts of the system. MedDefense should apply the encryption level that best matches the sensitivity, operational requirements and access patterns of each data store rather than using the same encryption method everywhere.
