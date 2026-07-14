# Threat Actor Taxonomy

## Report A

**Actor Type:** Nation-State

**Internal/External:** External – The attackers entered through a zero-day vulnerability in the VPN appliance.

**Resources:** High – The operation used custom malware, a stolen code-signing certificate and an unpublished vulnerability.

**Sophistication:** High – The attackers remained undetected for 14 months and used encrypted DNS communications.

**Primary Motivation:** Espionage – The objective was to steal valuable pharmaceutical research and clinical trial data.

**Confidence Level:** High – The long-term operation, custom tooling and zero-day exploitation strongly match nation-state behavior.

## Report B

**Actor Type:** Organized Crime

**Internal/External:** External – Initial access was obtained through a malicious email campaign.

**Resources:** Medium – The attackers used commercially available malware and a ransomware operation capable of handling payment and extortion.

**Sophistication:** Medium – The attack combined phishing, malware installation, data theft and ransomware deployment.

**Primary Motivation:** Financial Gain – The attackers demanded payment and threatened to publish stolen patient records.

**Confidence Level:** High – The behavior is consistent with financially motivated ransomware and double extortion.

## Report C

**Actor Type:** Hacktivist

**Internal/External:** External – The public website was compromised through an internet-facing content management system.

**Resources:** Low – The attackers used a known SQL injection technique and did not demonstrate advanced capabilities.

**Sophistication:** Low – The activity was limited to website defacement and did not extend into internal systems.

**Primary Motivation:** Philosophical or Political Beliefs – The message protested the hospital’s decision to close a community clinic.

**Confidence Level:** Medium – The political message and activist branding support a hacktivist classification, although opportunistic vandalism using an activist identity is also possible.

## Report D

**Actor Type:** Insider Threat

**Internal/External:** Internal – The attacker was a former administrator who prepared the attack while still employed and retained unauthorized access after termination.

**Resources:** Medium – The attacker relied on existing privileged access rather than expensive external tools.

**Sophistication:** Medium – The administrator created a hidden VPN account and disabled backups before deleting production data.

**Primary Motivation:** Revenge – The destructive activity occurred immediately after disciplinary termination.

**Confidence Level:** High – The home IP address, account creation and timing directly connect the former administrator to the incident.

## Report E

**Actor Type:** Unskilled Attacker

**Internal/External:** External – Automated exploitation targeted an exposed remote management vulnerability.

**Resources:** Low – The attackers used public exploits and freely available cryptocurrency-mining software.

**Sophistication:** Low – The attack was automated and showed no lateral movement, data theft or advanced persistence.

**Primary Motivation:** Financial Gain – The objective was to generate cryptocurrency using victim computing resources.

**Confidence Level:** High – The large number of unrelated victims and public tooling indicate opportunistic mass exploitation.

## Report F

**Actor Type:** Unskilled Attacker

**Internal/External:** External – The attacker found an internet-exposed Raspberry Pi and logged in using its default credentials.

**Resources:** Low – The attack required only basic scanning and knowledge of common default passwords.

**Sophistication:** Low – The attacker exploited an exposed device with unchanged default credentials and then pivoted to the nurse call system.

**Primary Motivation:** Chaos – No evidence of financial gain, espionage or data theft is provided; the resulting activity disrupted a clinical support system.

**Confidence Level:** Medium – The external attacker appears opportunistic, but the report does not provide enough evidence to confirm the attacker’s final objective.

**Shadow IT Context:** The employee-created Raspberry Pi was Shadow IT and created the entry point, but Shadow IT describes the unmanaged asset and employee behavior, not the external adversary who exploited it.

## Report G

**Actor Type:** Organized Crime or Insider Threat

**Internal/External:** Could be either – An external attacker may have used stolen physician credentials, or an internal user may have deliberately abused the account.

**Resources:** Medium – The actor maintained access for six weeks and selected records associated with high-value insurance plans.

**Sophistication:** Medium – The activity used legitimate credentials, occurred during off-hours and avoided immediate detection.

**Primary Motivation:** Financial Gain – The selected records could support insurance fraud, identity theft or later sale, although no transaction has yet been confirmed.

**Confidence Level:** Low – The available evidence confirms credential abuse but does not identify whether the responsible actor was internal or external.

**Ambiguity Explanation:** An external criminal using stolen credentials and a malicious insider using another employee’s account would produce similar access patterns. VPN logs, geolocation data, endpoint forensics, authentication history, device identifiers, account-reset records and interviews with personnel who could access the credentials would help distinguish between the two possibilities.

## Report H

**Actor Type:** Organized Crime

**Internal/External:** External – The attacker accessed the API from a Tor exit node.

**Resources:** Medium – The attacker found and exploited an authentication weakness and carried out a cryptocurrency extortion attempt.

**Sophistication:** Medium – The attacker successfully extracted genuine patient records but did not demonstrate custom malware or advanced persistence.

**Primary Motivation:** Blackmail – The attacker threatened to publish the vulnerability and stolen records unless payment was made.

**Confidence Level:** High – The explicit payment demand and threat of disclosure clearly indicate cyber extortion.
