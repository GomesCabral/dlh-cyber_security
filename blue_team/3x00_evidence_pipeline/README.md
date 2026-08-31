# MedDefense SOC Evidence Pipeline

A local pipeline for transforming raw security exports into structured, analyst-ready evidence during the MedDefense Health Systems SIEM migration window.

## Environment

- Ubuntu 22.04 LTS
- Bash 5
- Python 3
- `jq`, `sha256sum`, and `shellcheck`
- Primary evidence pack: `~/evidence_pack_primary/`
- Secondary evidence pack: `~/evidence_pack_secondary/`

The scripts do not depend on a SIEM, API, or network service. Input and output paths can be supplied through arguments or environment variables.

## Task 0 — Evidence Pack Inventory

### Objective

Inventory every file found under the `windows/`, `linux/`, and `network/` directories in the primary evidence pack. The inventory is written to `source_inventory.json`, allowing later pipeline stages to use an exact record of the received sources instead of walking the filesystem again.

### Deliverables

- `0-source_inventory.sh`: creates the inventory and prints a human-readable summary.
- `source_inventory.json`: structured manifest of the discovered sources.

### Supported sources

| Source | Format | `source_type` | Count field |
| --- | --- | --- | --- |
| Windows | NDJSON | `windows_json` | `record_count` |
| Linux | Text/syslog/auditd | `linux_text` | `line_count` |
| Firewall | CSV | `network_csv` | `record_count`, excluding the header |
| Suricata and PCAP summary | NDJSON | `network_json` | `record_count` |

Files under `context/` and `student_telemetry/` are outside the scope of Task 0.

### Manifest fields

Each object in the `files` array contains:

- `path`: path relative to the evidence pack root;
- `source_type`: source category and format;
- `size_bytes`: exact file size;
- `sha256`: integrity fingerprint;
- `line_count` or `record_count`: amount of data received;
- `first_event_time`: earliest event timestamp found;
- `last_event_time`: latest event timestamp found.

Timestamps are written as ISO 8601 UTC. When no timestamp can be extracted, the relevant field is set to `null`.

### Timestamp extraction

| File | Field or format used |
| --- | --- |
| Windows JSON | `timestamp_raw` |
| Linux `auth.log` and `syslog` | syslog prefix, with the year inferred from the evidence pack |
| Linux `audit.log` | Unix epoch inside `audit(...)` |
| Firewall CSV | Unix epoch in the `timestamp` column |
| Suricata EVE | `timestamp` field |
| PCAP summary | `start_time` and `end_time` fields |

### Usage

Run with the default paths:

```bash
chmod +x 0-source_inventory.sh
./0-source_inventory.sh
```

Run with path arguments:

```bash
./0-source_inventory.sh /path/to/evidence_pack /path/to/source_inventory.json
```

Run with environment variables:

```bash
EVIDENCE_ROOT=/path/to/evidence_pack \
OUTPUT_FILE=/path/to/source_inventory.json \
./0-source_inventory.sh
```

### Expected result

```text
windows : 3 files | 63.3 MB
linux   : 3 files | 15.7 MB
network : 3 files | 12.0 MB
total   : 9 files | 91.0 MB
manifest written to source_inventory.json
```

The values depend on the actual evidence pack contents. The figures shown in the project instructions are illustrative.

### Validation

```bash
shellcheck 0-source_inventory.sh
bash -n 0-source_inventory.sh
jq empty source_inventory.json
jq '.files | length' source_inventory.json
```

Check the distribution by source type:

```bash
jq -r '.files[].source_type' source_inventory.json | sort | uniq -c
```

Expected result for the primary pack:

```text
3 linux_text
1 network_csv
2 network_json
3 windows_json
```

### Idempotency test

```bash
./0-source_inventory.sh >/dev/null
sha256sum source_inventory.json
./0-source_inventory.sh >/dev/null
sha256sum source_inventory.json
```

Both hashes must be identical. This confirms that running the script twice against the same inputs produces exactly the same manifest.

### Relevance to a SOC analyst

An analyst should never assume that an evidence delivery matches the description in its handoff message. The inventory helps identify missing, empty, unexpected, or out-of-scope files before analysis begins. The SHA-256 value also makes it possible to verify whether evidence changed between collection and analysis.

For example, if `windows/security.json` keeps the same filename but has a different SHA-256 value during a later run, its contents have changed. The difference could represent a legitimate new export, corruption, or evidence modification and should be explained before the investigation continues.

## Task 2 — Windows Event Parsing

### Objective

Merge the three Windows NDJSON sources and the Windows student telemetry into one validated intermediate file named `windows_events.json`. Downstream normalization stages can therefore process a single Windows dataset instead of reading four independent files.

### Deliverables

- `2-windows_parse.sh`: validates, maps, and merges the Windows sources.
- `windows_events.json`: combined newline-delimited JSON dataset.

### Input order

The output preserves a deterministic source order:

1. `windows/security.json`
2. `windows/sysmon.json`
3. `windows/powershell.json`
4. `student_telemetry/windows_events.json`

This task does not sort records chronologically. Timeline ordering is performed by a later pipeline stage.

### Required intermediate fields

Every output record contains at least:

- `timestamp_raw`
- `hostname`
- `event_id`
- `channel`
- `provider`
- `raw_message`
- `event_data`
- `source_origin`

The script stops with a non-zero exit status if a record cannot satisfy this minimum contract. Output is built in a temporary directory and moved into place only after all sources pass validation, preventing a failed run from replacing a valid result with a partial file.

### Source-origin handling

Records from the three baseline Windows files must already contain:

```json
"source_origin": "evidence_pack"
```

The script verifies this value and preserves the records. Student telemetry receives:

```json
"source_origin": "student_telemetry"
```

when the field is not already present.

### Student telemetry mapping

The Module 2 student telemetry uses a smaller schema than the baseline Windows exports. The parser maps it to the required intermediate structure:

| Student telemetry | Intermediate record |
| --- | --- |
| `timestamp` | `timestamp_raw` |
| `hostname` | `hostname` |
| `event_id` | `event_id` |
| `source_type` and event context | `channel` |
| calculated channel | `provider` |
| `raw_message` | `raw_message` |
| `event_category`, `user`, `command_line`, `source_type` | `event_data` |
| generated tag | `source_origin` |

Event ID `4104` and PowerShell event categories are mapped to the PowerShell Operational channel even when an original telemetry record contains an inconsistent `source_type`. The original value is retained as `event_data.original_source_type`, preserving evidence provenance.

### Usage

Run with the default evidence pack and output paths:

```bash
chmod +x 2-windows_parse.sh
./2-windows_parse.sh
```

Run with explicit path arguments:

```bash
./2-windows_parse.sh /path/to/evidence_pack /path/to/windows_events.json
```

Run with environment variables:

```bash
EVIDENCE_ROOT=/path/to/evidence_pack \
OUTPUT_FILE=/path/to/windows_events.json \
./2-windows_parse.sh
```

The script prints a record count for every source and a combined total:

```text
reading security.json      ...  38498 records
reading sysmon.json        ...  72810 records
reading powershell.json    ...   9408 records
appending student telemetry ...  1859 records
windows_events.json: 122575 records
```

Counts depend on the evidence pack supplied to the script.

### Validation

Validate the script and the generated NDJSON:

```bash
shellcheck 2-windows_parse.sh
bash -n 2-windows_parse.sh
jq empty windows_events.json
wc -l windows_events.json
```

Check source-origin counts:

```bash
jq -r '.source_origin' windows_events.json | sort | uniq -c
```

Find records missing required fields:

```bash
jq -c '
    select(
        ([
            "timestamp_raw",
            "hostname",
            "event_id",
            "channel",
            "provider",
            "raw_message",
            "event_data",
            "source_origin"
        ] - keys) | length > 0
    )
' windows_events.json
```

The final command must produce no output.

### Idempotency test

```bash
./2-windows_parse.sh >/dev/null
sha256sum windows_events.json
./2-windows_parse.sh >/dev/null
sha256sum windows_events.json
```

Both hashes must be identical when the input files have not changed.

### Relevance to a SOC analyst

Windows Security, Sysmon, and PowerShell logs provide complementary visibility. A successful logon in Security Event ID `4624` can be correlated with Sysmon process creation Event ID `1` and PowerShell script-block Event ID `4104`. Combining these channels into one validated intermediate dataset prepares the pipeline to reconstruct activity across authentication, process execution, network connections, and script execution.

Task 2 does not decide whether an event is malicious. It creates a consistent and traceable Windows input for normalization, detection, hunting, and timeline analysis.

## Project status

| Task | Status |
| --- | --- |
| Task 0 — Evidence Pack Inventory | Implemented |
| Task 2 — Windows Event Parsing | Implemented |
| Remaining tasks | Pending |

