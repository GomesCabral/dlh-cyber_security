# CLI vs. Wazuh Export Trade-off Analysis

Generated from paired structured findings. Time and action deltas are calculated as `wazuh_export - cli`; negative values favor the export workflow.

| Scenario | CLI time (s) | Export time (s) | Time delta | Faster interface | CLI actions | Export actions | Action delta | Cause |
|---|---:|---:|---:|---|---:|---:|---:|---|
| anchor | 47 | 3 | -44 | wazuh_export | 5 | 7 | 2 | filter_bar_efficiency |
| scenario_a | 47 | 3 | -44 | wazuh_export | 8 | 7 | -1 | timeline_visualization |
| scenario_b | 47 | 2 | -45 | wazuh_export | 7 | 8 | 1 | filter_bar_efficiency |
| scenario_c | 3 | 3 | 0 | tie | 8 | 7 | -1 | reproducibility |

## Evidence-based attribution

- **anchor — filter_bar_efficiency:** The prepared dashboard filter exposed the known SSH cluster without rescanning the large NDJSON handoff.
- **scenario_a — timeline_visualization:** The exported, host-scoped event set made the ordered credential-theft chain quick to reconstruct.
- **scenario_b — filter_bar_efficiency:** The prepared event filter surfaced the privileged logon chain quickly despite the inventory fallback.
- **scenario_c — reproducibility:** Both interfaces reached the first answer in the same measured time; action counts remain a secondary comparison.

## Summary

- Scenarios analyzed: 4
- Export advantages: 3
- CLI advantages: 0
- Ties: 1
