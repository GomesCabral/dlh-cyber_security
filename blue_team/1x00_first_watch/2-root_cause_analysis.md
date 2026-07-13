# Root Cause Analysis: billing-srv-01

## Executive Finding

The recurring performance degradation on `billing-srv-01` is not primarily a hardware-capacity problem. The diagnostic evidence shows that the server is actively compromised and running an unauthorized cryptocurrency-mining process.

The process named `kworker` consumes 94.2% of the available CPU and maintains outbound connections to Monero mining pools. The resulting CPU saturation explains the billing application's poor performance, but the performance degradation is only the visible symptom. The underlying problem is unauthorized access to and modification of the server.

## Process Identification

The suspicious process is shown in the diagnostic output as:

```text
PID: 8834
User: www-data
CPU usage: 94.2%
Command: ./kworker -o stratum+tcp://pool.monero.org:4443 --threads 4 --donate-level 0
Executable path: /var/www/html/.cache/kworker
```

This process is not a legitimate Linux kernel worker.

Legitimate Linux `kworker` processes are kernel threads. They normally appear in process listings with names such as `[kworker/0:1]`, run as kernel-level or root processes, and are not stored as executable files inside a web application's directory.

The process on `billing-srv-01` instead:

* runs as the Apache service account, `www-data`;
* is stored under `/var/www/html/.cache/`;
* consumes nearly all available CPU;
* connects to external cryptocurrency-mining infrastructure;
* uses a configuration file containing mining pool addresses and a cryptocurrency wallet identifier.

The process name was selected to resemble a legitimate system process and reduce the likelihood of detection.

## Meaning of the Stratum Connection

The command contains the following connection:

```text
stratum+tcp://pool.monero.org:4443
```

Stratum is a protocol commonly used by cryptocurrency-mining software to communicate with mining pools. A mining pool distributes computational work to participating systems and receives completed mining results.

The configuration file also contains additional external mining endpoints:

```text
91.121.87.10:8080
104.238.140.32:3333
```

It further specifies:

* a Monero wallet address;
* four mining threads;
* background execution;
* a CPU priority setting;
* multiple mining pools for resilience.

These details confirm that the purpose of the process is to mine Monero cryptocurrency using MedDefense's computing resources. This activity is commonly referred to as cryptojacking.

## CIA Triad Analysis

### Primary Violation: Confidentiality

Confidentiality was compromised because an unauthorized party obtained access to the server and executed code under the `www-data` account.

The available evidence does not prove that billing, patient, or insurance data was exfiltrated. However, the attacker gained unauthorized access to resources available to the Apache account and may have been able to:

* read web-application files;
* inspect configuration files;
* identify database credentials;
* access application data;
* collect authentication material;
* attempt movement to other systems.

The confirmed violation is unauthorized access. Whether protected or sensitive data was viewed or extracted requires further investigation.

### Secondary Violation: Integrity

Integrity was compromised because the attacker modified the server's trusted state.

The compromise introduced unauthorized files and processes, including:

```text
/var/www/html/.cache/kworker
/var/www/html/.cache/config.json
```

The attacker or malicious process:

* created a hidden directory;
* installed an unauthorized executable;
* created a mining configuration;
* launched unapproved code;
* changed the server from its intended operating state.

Because the server was modified without authorization, its integrity can no longer be trusted.

### Resulting Impact: Availability

Availability was affected after the confidentiality and integrity violations occurred.

The cryptocurrency miner consumes approximately 94% of the server's CPU capacity. This leaves insufficient resources for the legitimate billing application and causes recurring performance degradation for Finance users.

The sequence of impact is:

1. Unauthorized access to the server.
2. Unauthorized modification of the server.
3. Execution of the cryptocurrency miner.
4. CPU resource exhaustion.
5. Degraded billing-service availability.

Availability is therefore the visible operational symptom, not the root security problem.

## Why the Hardware Upgrade Does Not Resolve the Problem

Migrating `billing-srv-01` to a more powerful virtual machine does not eliminate the compromise.

Additional CPU and memory may temporarily improve the application's performance, but the malicious process, attacker access, and underlying vulnerability may remain present. A miner configured to use multiple threads may simply consume the additional processing capacity.

A hardware upgrade fails because it does not:

* remove the unauthorized executable;
* terminate attacker access;
* identify the initial access vector;
* patch the vulnerable service or application;
* rotate potentially compromised credentials;
* validate the integrity of the operating system;
* determine whether data was accessed;
* search for persistence mechanisms;
* identify compromise on other systems.

The new server may also be compromised if MedDefense reuses the same vulnerable application, system image, configuration, credentials, or exposed services.

The appropriate response is to treat `billing-srv-01` as an actively compromised system. MedDefense should contain the server, preserve evidence, investigate the entry point, remove or rebuild the system from a trusted source, patch the relevant vulnerability, rotate affected credentials, and validate the environment before returning the service to production.

## Connection to the January Ransomware Incident

`billing-srv-01` was affected by ransomware in January and was subsequently rebuilt. The discovery of a cryptocurrency miner on the rebuilt server suggests that the underlying security weakness may not have been corrected.

The two incidents involve different payloads:

* ransomware encrypted the server in January;
* the current malware mines cryptocurrency.

Different payloads do not necessarily mean different entry points. Both incidents may have resulted from the same unresolved vulnerability, insecure configuration, or compromised credential.

The process location and ownership support the possibility that the attacker entered through Apache or the billing web application:

* the executable is located under `/var/www/html/`;
* the process runs as `www-data`;
* the server uses Apache 2.4.29;
* Marcus documented concern about known remote-code-execution vulnerabilities affecting that version.

However, the diagnostics alone do not prove the precise initial access method. Other possibilities include:

* a vulnerability in the billing application;
* insecure file-upload functionality;
* compromised administrative credentials;
* exposed SSH access;
* weak service permissions;
* reuse of a compromised system image;
* unremoved persistence from the previous incident.

The central investigative question is:

> What initial access vector allowed both the January ransomware incident and the current cryptocurrency-mining compromise, and why was that vector still available after the server was rebuilt?

Supporting questions include:

* Was Apache patched during the rebuild?
* Was the billing application reviewed for vulnerabilities?
* Were passwords, SSH keys, API keys, and database credentials rotated?
* Was the server rebuilt from a trusted and fully updated image?
* Were all persistence mechanisms removed?
* Were firewall rules and exposed services reviewed?
* Were logs preserved and analyzed after the ransomware incident?
* Were the same indicators of compromise searched for elsewhere in the environment?

## Conclusion

The sysadmin correctly identified CPU saturation but incorrectly attributed it to insufficient hardware.

The diagnostic evidence confirms an active cryptocurrency-mining compromise. Unauthorized access affected confidentiality, unauthorized installation and execution affected integrity, and the resulting CPU exhaustion degraded availability.

The recurrence of compromise after the January rebuild suggests that MedDefense restored the server without eliminating the underlying access path. Increasing hardware capacity would treat the symptom while leaving the security problem unresolved.
