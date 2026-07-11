# Incident Classification

| Incident | Primary CIA Pillar | Justification | Secondary CIA Pillar | Secondary Justification |
|----------|--------------------|---------------|----------------------|-------------------------|
| A | Availability | The ransomware encrypted the billing server, preventing the finance team from processing insurance claims for four days. | Integrity | The ransomware modified (encrypted) the server's data. |
| B | Confidentiality | Broken access control allowed patients to view other patients' laboratory results without authorization. | None | No evidence indicates that the data was modified or the service became unavailable. |
| C | Integrity | A faulty database update script overwrote medication dosage values with incorrect information. | None | The issue affected data accuracy but did not expose data or interrupt system availability. |
| D | Integrity | The public website was defaced and its content was modified without authorization. | Availability | The website could not provide its intended content until it was restored. |
| E | Availability | The EHR system was unavailable for nine hours during the failed database migration. | None | The incident affected system availability only. |
| F | Confidentiality | An unauthorized personal laptop had access to the internal network and potentially sensitive HR resources. | Integrity | The laptop could potentially modify or compromise internal files and systems. |

