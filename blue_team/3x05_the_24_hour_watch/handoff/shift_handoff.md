# MedDefense SOC Shift Handoff

## Shift Identifier

- Shift ID: SHIFT-20260915-1624
- Analyst host: ip-10-42-218-134.ec2.internal
- Started: 2026-09-15T16:24:37Z
- Ended: 2026-09-16T15:07:13Z
- Duration: 22.71 hours

## Situation

MedDefense operated under heightened monitoring following the HC-RED7 healthcare-sector advisory.
The shift briefing contained 12 threat indicators for mechanical comparison against observed activity.
The investigated incident period runs from 2026-04-08T00:04:19Z through 2026-04-08T23:58:40Z.
The processed evidence and Wazuh export describe partially different host sets, so unsupported attribution was avoided.

## Incidents

INC-20260916-A: TP with unresolved ambiguity; primary ATT&CK technique T1110.001. Full report: `reports/incident_A.md`.

INC-20260916-B: TP with unresolved ambiguity; primary ATT&CK technique T1110.001. Full report: `reports/incident_B.md`.

INC-20260916-C: TP with unresolved ambiguity; primary ATT&CK technique T1110.001. Full report: `reports/incident_C.md`.

## Campaign Assessment

The mechanical assessment found campaign_linked=true, cluster_id=unknown, and confidence=medium. The Wazuh export reports HC-RED7, but the processed evidence contains no direct feed match. See `campaign/campaign_assessment.json`.

## Open Items for Next Shift

- INC-20260916-A: Correlation is broad because shared users joined multiple hosts. Domain-controller authentication and VPN logs are required to confirm whether one actor controlled all sessions.
- INC-20260916-B: The incident hosts do not exist in the supplied asset inventory and do not match the rad-srv-02 scenario. SSH server, IAM and network logs are required to confirm whether the attempts came from one authorized administrator or a compromised account.
- INC-20260916-C: The supplied asset and Wazuh context describes different hostnames. SSH, IAM and network logs are required to establish actor identity and intent.
- Reconcile the evidence-pack hostnames with the Wazuh export using the original collection manifest and index metadata.
- Validate affected accounts using identity-provider, VPN and domain-controller authentication logs.
- Confirm containment execution using firewall, IAM and endpoint change records.

## Artifact Index

| Relative path | SHA256 |
|---|---|
| `runtime/shift_start.json` | `d2785bede68b4d98dce98b92020cdc82d2e7f870fab30d009d6d5b5eba0859a4` |
| `runtime/pipeline_run.json` | `a7909deba6e995dab174d29441eafd05eeaa31442213f4d8bfe65353e5266c95` |
| `runtime/baseline_run.json` | `b7e3e315b6679565e7223181326e09a1b9d740e2324426b0ce1d84f7670d8558` |
| `runtime/catalog_run.json` | `dbe19743e58d4120efa698c24d0d4fefa6c5249cabbb8df8d909048a00bd6a9c` |
| `enriched/enriched_events.jsonl` | `fb0a3bc5ac3d779f2029fa96474e2955f61153e75311a6577ff7575d6fd8daac` |
| `enriched/timeline.jsonl` | `5c7c414edfc4c3e4fd930d25180b8674d08858b93fe14489815b13fb52a6c41d` |
| `enriched/source_stats.json` | `5cfe49155a67eea5761f3df6a44e1481821294da860a7fbf1717b4d804e8b5bd` |
| `enriched/baseline.json` | `7893a6880224699756c5ee56461dbdf02b742b5673a151f6ad58d37fa2658f9f` |
| `alerts/alert_queue.json` | `bc3ecd8f72f3dda236f443eb27053feccf585ce5da6dcdb42986ac23e0bf50ad` |
| `alerts/shift_briefing.json` | `29d37f6b60b499d5aad3ffc074b6714bd22093a5b362c784059cea244fe063eb` |
| `alerts/triage_log.jsonl` | `92bbeedfd9da574deb7dd268ab4fd50d9f1f0a040b31e0a0a047cbae8277d023` |
| `alerts/incidents.json` | `b9a2c506b208e87d48cb17fd65b750117a7e647b590a5644fba79c9bd67c95dd` |
| `investigations/incident_A.json` | `1822931a183f59127eeb1f010fe1d9ca5fdd8336f093ee89dc34c45c6fce2e04` |
| `investigations/incident_B.json` | `902281254685b5faabc893521b8d7116b31d9ca4f5f4bcf2f8c92c1c829180a8` |
| `investigations/incident_C_cli.json` | `0f69999a4a93a0c80c71966c313a2ac56be9711d4f89dc455518642f979986cf` |
| `campaign/campaign_assessment.json` | `fa8ebb2698f55f0d9d44a5dc85859d926020e827241943f2abc37676770a0e1d` |
| `reports/incident_A.md` | `509e03a0d44fdf9803656acf77b249f6ec257e8757ae29dc520f9ae34da447e3` |
| `reports/incident_B.md` | `22570f21ed42d30c92934db88b8b701affdefd83859f5c3b1a807a125229ff96` |
| `reports/incident_C.md` | `8536b8587ef598447dc310d24f4026017a1b203d83dc4c64be8fb652e7fb3db5` |
| `response/containment.json` | `4a1ac4ba3efedcde0879a5f3ff32f179bc76558557bfd6a157cd33d4ec926181` |
| `response/ioc_package.json` | `79fd71e9aef381313f19f3b5fbebe9139a23171476553b5a790ae3cb2826fbb0` |
