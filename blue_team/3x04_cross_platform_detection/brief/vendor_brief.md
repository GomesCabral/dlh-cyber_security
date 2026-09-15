# MedDefense SIEM Interface Evaluation Brief

## Purpose

Evaluate the CLI and Wazuh evidence interfaces using MedDefense incident data and measured analyst workflows. Recommend a primary analyst surface while retaining a bounded secondary capability for resilience and deeper evidence handling.

## Evaluation Methodology

The evaluation used four representative cases: a known SSH brute-force anchor, a credential-theft chain, an off-hours privileged PHI logon, and medical-IoT egress. Each case was investigated through the CLI and Wazuh export interface, producing eight schema-locked findings from identical source evidence. Scripts measured time to first answer and ordered actions; findings recorded fields, event references, confidence, and ATT&CK mappings. T13 aggregated the measurements without human weighting, while T12 attributed scenario-level trade-offs to bounded operational causes. Export mode measured the Wazuh evidence model and prepared workflow, not live-dashboard latency or availability.

## Findings Summary

The CLI processed four findings in 144 seconds total, averaging 36 seconds with a 47-second median. It required 28 actions, touched 62 fields, and preserved no populated event references in the current findings. The Wazuh export interface processed four findings in 11 seconds total, averaging 2.75 seconds with a 3-second median. It required 29 actions, touched 27 fields, and preserved 69 document references. Both interfaces produced three high-confidence and one medium-confidence finding. Wazuh export was faster for the anchor and scenarios A and B; scenario C tied at three seconds, with export requiring seven actions versus eight for CLI.

## Strengths and Weaknesses per Interface

**CLI.** The CLI provides expressive, reproducible filtering against raw or enriched evidence and supports explicit joins to local context. It used fewer actions for the anchor, five versus seven, and for scenario B, seven versus eight. However, the T12 anchor entry attributed the 44-second export advantage to `filter_bar_efficiency`, and the scenario A entry attributed another 44-second advantage to `timeline_visualization`. The current CLI findings also lack populated event references, weakening handoff traceability even though more fields were inspected.

**Wazuh export.** The prepared evidence surface reduced time substantially: scenario A completed in 3 seconds versus 47 and used seven actions versus eight; scenario B completed in 2 seconds versus 47 despite one additional action. The scenario C entry recorded `reproducibility`: both interfaces took 3 seconds, while export used one fewer action and retained six event references. Weaknesses remain: the anchor required two more actions, scenario B required an asset-inventory fallback because classification was absent from `agent.labels`, and export performance does not measure live search, ingestion delay, or dashboard outages.

## Recommendation

Select the Wazuh analyst evidence interface as MedDefense's primary investigation surface, subject to live-pilot validation of search latency, availability, and field completeness. Use the CLI as the secondary interface during dashboard or index disruption, for raw-evidence validation, complex context joins, bulk processing, and reproducible investigations requiring control below the indexed schema.

## Operational Risks of Being Wrong

- **Overstated Wazuh speed:** at 120 comparable investigations per week, the observed 33.25-second average difference represents about 1.1 analyst hours weekly; live latency could eliminate that saving.
- **Dashboard dependency:** one two-hour weekly outage affecting two analysts costs approximately 4 analyst hours unless the CLI path remains tested.
- **Weak evidence traceability:** reconstructing references for ten weekly escalations at 15 minutes each costs approximately 2.5 analyst hours when findings omit stable event IDs.
- **Incomplete indexed context:** five weekly asset or IOC fallbacks at 10 minutes each cost approximately 0.8 analyst hours and can delay risk prioritization.
- **Unmaintained dual workflows:** a one-hour weekly validation exercise for two analysts costs 2 analyst hours, but avoiding it increases recovery time during an interface failure.

## Security+ 4.7 Considerations

Automation and an efficient indexed surface support scaling, but field-mapping complexity, licensing and operating cost, and live-platform performance must be measured before expansion. Retaining tested CLI procedures limits vendor dependency and technical debt, although maintaining two workflows adds controlled training and validation cost.

## Next Steps

1. **Detection engineering:** run a live Wazuh pilot, validate the three translated XML rules, populate missing asset labels, and repeat timing measurements with uncached searches.
2. **Compliance:** retain the manifest, findings, hashes, methodology, exceptions, and approval record in the annual audit evidence folder.
3. **SOC manager:** define availability and latency acceptance criteria, assign owners for both interfaces, and schedule quarterly failover exercises.
