# Threat Actor Taxonomy

## Report A

- **Actor Type:** Nation-State
- **Internal/External:** External – The attackers exploited a VPN zero-day vulnerability.
- **Resources:** High – Used custom malware, a stolen code-signing certificate and a zero-day exploit.
- **Sophistication:** High – Long-term covert operation using advanced techniques.
- **Primary Motivation:** Espionage – The objective was to steal valuable pharmaceutical research.
- **Confidence Level:** High – The attack strongly matches known nation-state behavior.

---

## Report B

- **Actor Type:** Organized Crime
- **Internal/External:** External – Initial access was gained through phishing emails.
- **Resources:** Medium – Used commercially available malware and ransomware.
- **Sophistication:** Medium – Combined phishing, data exfiltration and ransomware.
- **Primary Motivation:** Financial Gain – The attackers demanded a ransom and threatened to leak stolen data.
- **Confidence Level:** High – The attack follows a typical ransomware campaign.

---

## Report C

- **Actor Type:** Hacktivist
- **Internal/External:** External – The website was compromised from outside the organization.
- **Resources:** Low – Used a known SQL injection vulnerability.
- **Sophistication:** Low – The attack was limited to website defacement.
- **Primary Motivation:** Political or Philosophical Beliefs – The attackers protested the hospital's decision.
- **Confidence Level:** High – The public message clearly indicates hacktivist activity.

---

## Report D

- **Actor Type:** Insider Threat
- **Internal/External:** Internal – The attacker was a former employee with privileged access.
- **Resources:** Medium – Already had administrative privileges and created a hidden VPN account.
- **Sophistication:** Medium – Planned the attack by disabling backups before deletion.
- **Primary Motivation:** Revenge – The attack occurred shortly after termination.
- **Confidence Level:** High – Evidence directly identifies the former administrator.

---

## Report E

- **Actor Type:** Unskilled Attacker
- **Internal/External:** External – The attack was performed through automated internet scanning.
- **Resources:** Low – Used public mining software and known vulnerabilities.
- **Sophistication:** Low – No persistence or lateral movement was observed.
- **Primary Motivation:** Financial Gain – The objective was cryptocurrency mining.
- **Confidence Level:** High – The activity matches large-scale automated exploitation.

---

## Report F

- **Actor Type:** Shadow IT
- **Internal/External:** Internal – The Raspberry Pi was connected by an employee without authorization.
- **Resources:** Low – Personal hardware with default credentials.
- **Sophistication:** Low – The device was poorly secured.
- **Primary Motivation:** Ethical Motivation – The employee intended to monitor network performance, not cause harm.
- **Confidence Level:** High – The report clearly states there was no malicious intent.

---

## Report G

- **Actor Type:** Organized Crime (possible) or Insider Threat
- **Internal/External:** Could be either – The physician's account was used, but the real user was not responsible.
- **Resources:** Medium – Legitimate credentials were abused over several weeks.
- **Sophistication:** Medium – The attacker maintained access while avoiding immediate detection.
- **Primary Motivation:** Data Exfiltration – Patient records were selectively downloaded.
- **Confidence Level:** Medium – The evidence does not identify whether the credentials were stolen externally or misused internally.

**Ambiguity Explanation:**  
The attack could involve an external attacker using stolen credentials or an insider abusing another employee's account. Additional evidence such as authentication logs, malware analysis, endpoint forensics or VPN records would help determine the responsible actor.

---

## Report H

- **Actor Type:** Organized Crime
- **Internal/External:** External – The attacker accessed the API through a Tor exit node.
- **Resources:** Medium – Exploited a known application weakness and attempted extortion.
- **Sophistication:** Medium – Successfully extracted sensitive data but did not use advanced techniques.
- **Primary Motivation:** Financial Gain – The attacker demanded cryptocurrency to avoid public disclosure.
- **Confidence Level:** High – The behavior matches financially motivated cyber extortion.
