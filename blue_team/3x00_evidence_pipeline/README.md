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

## Task 3 — Linux Log Parsing

### Objective

Parse the plain-text Linux sources `auth.log`, `audit.log`, and `syslog` into structured NDJSON, then append the Module 2 Linux student telemetry. The resulting `linux_events.json` gives the normalization stage one consistent Linux intermediate dataset.

### Deliverables

- `3-linux_parse.sh`: parses, validates, maps, and combines the Linux sources.
- `linux_events.json`: structured newline-delimited JSON output.

### Input order

The output preserves a deterministic source order:

1. `linux/auth.log`
2. `linux/audit.log`
3. `linux/syslog`
4. `student_telemetry/linux_events.json`

Chronological sorting is intentionally deferred to the timeline stage.

### Input grammars

| Source | Grammar | Main information extracted |
| --- | --- | --- |
| `auth.log` | Traditional syslog | timestamp, hostname, program, PID, user, message, and key-value fields |
| `audit.log` | Linux auditd | audit timestamp and group ID, audit type, PID, user identifiers, hostname, and audit key-value fields |
| `syslog` | Traditional syslog with defensive fallback | timestamp, hostname, program, PID, message, and key-value fields |
| Student telemetry | NDJSON | mapped timestamp, host, source type, event category, user, command, and message |

The parser also recognizes malformed or prefixed syslog records where an ISO timestamp appears before the traditional syslog content. Lines that still cannot be parsed are preserved with `parse_status: "unparsed"` instead of being silently discarded.

### Required intermediate fields

Every output record contains:

- `timestamp_raw`
- `hostname`
- `program`
- `audit_type`
- `pid`
- `user`
- `raw_message`
- `parsed_fields`
- `source_origin`

Fields that do not apply to a particular source are explicitly set to `null`. For example, auditd records normally have `program: null`, while traditional syslog records have `audit_type: null`.

### Auditd record strategy

The project permits either grouping related auditd lines or emitting one record per line with a shared group identifier. In the supplied primary pack:

```text
audit.log lines:         67368
unique audit group IDs:  67368
```

Because every audit line has a unique ID, grouping would not reduce the number of records. The parser therefore emits one event per line and stores the identifier in:

```json
{
  "parsed_fields": {
    "audit_group_id": "1774385465.371:85"
  }
}
```

This preserves every original audit record and still allows later correlation by group ID.

### Student telemetry mapping

The student telemetry contains `timestamp`, `hostname`, `source_type`, `event_category`, `user`, `command`, and `raw_message`. It is mapped as follows:

| Student telemetry | Intermediate record |
| --- | --- |
| `timestamp` | `timestamp_raw` |
| `hostname` | `hostname` |
| `source_type: auditd` | `audit_type` derived from `event_category`; `program: null` |
| Other `source_type` values | `program`; `audit_type: null` |
| `user` | `user` |
| `event_category`, `command`, and original source | `parsed_fields` |
| `raw_message` | `raw_message` |
| generated tag | `source_origin: student_telemetry` |

### Parse-status handling

Each record records how it was handled:

| Status | Meaning |
| --- | --- |
| `parsed` | The baseline record matched the expected grammar |
| `partial` | An audit record was retained but lacked one of the main audit markers |
| `unparsed` | A text line did not match the supported syslog patterns and was preserved for later quality review |
| `mapped` | A student telemetry record was converted to the intermediate shape |

This approach separates parsing from later data-quality and quarantine decisions.

### Usage

Run with the default paths:

```bash
chmod +x 3-linux_parse.sh
./3-linux_parse.sh
```

Run with explicit paths:

```bash
./3-linux_parse.sh /path/to/evidence_pack /path/to/linux_events.json
```

Run with environment variables:

```bash
EVIDENCE_ROOT=/path/to/evidence_pack \
OUTPUT_FILE=/path/to/linux_events.json \
./3-linux_parse.sh
```

Expected counts for the supplied primary evidence pack:

```text
parsing auth.log      ... 24880 lines -> 24880 records
parsing audit.log     ... 67368 lines -> 67368 records
parsing syslog        ... 41736 lines -> 41736 records
appending student telemetry ... 1879 records
linux_events.json: 135863 records written
```

### Validation

```bash
shellcheck 3-linux_parse.sh
bash -n 3-linux_parse.sh
jq empty linux_events.json
wc -l linux_events.json
```

Check source-origin counts:

```bash
jq -r '.source_origin' linux_events.json | sort | uniq -c
```

Expected result:

```text
133984 evidence_pack
1879 student_telemetry
```

Find records that could not be fully parsed:

```bash
jq -c '
    select(
        .parsed_fields.parse_status == "unparsed"
        or .parsed_fields.parse_status == "partial"
    )
' linux_events.json
```

Check that every record contains the intermediate fields:

```bash
jq -c '
    select(
        ([
            "timestamp_raw",
            "hostname",
            "program",
            "audit_type",
            "pid",
            "user",
            "raw_message",
            "parsed_fields",
            "source_origin"
        ] - keys) | length > 0
    )
' linux_events.json
```

The final command must produce no output.

### Idempotency test

```bash
./3-linux_parse.sh >/dev/null
sha256sum linux_events.json
./3-linux_parse.sh >/dev/null
sha256sum linux_events.json
```

Both hashes must be identical when the inputs have not changed.

### Relevance to a SOC analyst

Linux authentication, system, and audit logs describe different parts of an incident. An SSH authentication in `auth.log` can be correlated with an auditd `EXECVE` or `SYSCALL` record and subsequent service or firewall messages in `syslog`. Structuring these grammars makes it possible to search consistently for users, processes, hosts, commands, and audit activity.

The parser deliberately preserves malformed lines in `raw_message`. Missing or irregular telemetry can itself be relevant evidence—for example, log corruption, a broken collector, or attacker tampering—and should not disappear merely because it failed a regular expression.

## Task 4 — Unified Event Schema Design

### Objective

Define the versioned contract that every Windows, Linux, firewall, Suricata, and PCAP record will follow after normalization.

### Deliverable

- `event_schema.json`: schema version `1.0.0`, authored by Pedro Cabral.

### Design principles

- Required fields form the minimum reliable contract for correlation and detection.
- Optional fields preserve source-specific context without quarantining unrelated event types.
- Every field documents mappings for `windows_json`, `linux_text`, `network_csv`, and `network_json`.
- `raw_message` and `details` prevent semantic loss during normalization.
- Process, identity, network, rule, audit, asset, and zone fields support later detection, triage, and enrichment stages.

The schema contains 38 uniquely named fields. Core required fields are `timestamp`, `source_type`, `source_origin`, `event_category`, `severity`, `raw_message`, and `details`; fields such as `hostname`, `user`, process data, and network addresses remain optional because they are not present in every event family.

### Severity vocabulary

Normalized severity uses:

```text
informational, low, medium, high, critical
```

Source-specific values such as Suricata numeric severity are translated through mappings during normalization.

### Validation

```bash
jq empty event_schema.json
jq -r '.version, .author, (.fields | length)' event_schema.json
```

Check for duplicate field names:

```bash
jq -r '.fields[].name' event_schema.json | sort | uniq -d
```

The duplicate check must produce no output.

Check that every field contains mappings for all source families:

```bash
jq -e '
  all(
    .fields[];
    (.source_mapping | has("windows_json")) and
    (.source_mapping | has("linux_text")) and
    (.source_mapping | has("network_csv")) and
    (.source_mapping | has("network_json"))
  )
' event_schema.json
```

Expected result:

```text
true
```

### Relevance to a SOC analyst

A unified schema lets one detection query correlate a Windows logon, Linux audit execution, firewall connection, and Suricata alert without knowing every vendor's original field names. It also prevents normalization from merging distinct concepts, such as process ID and parent process ID or source and destination network zones, that analysts need during triage.

