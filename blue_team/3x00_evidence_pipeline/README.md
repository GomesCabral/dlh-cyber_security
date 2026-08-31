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

- `event_schema.json`: schema version `1.1.0`, authored by Pedro Cabral.

### Design principles

- Required fields form the minimum reliable contract for correlation and detection.
- Optional fields preserve source-specific context without quarantining unrelated event types.
- Every field documents mappings for `windows_json`, `linux_text`, `network_csv`, and `network_json`.
- `raw_message` and `details` prevent semantic loss during normalization.
- Process, identity, network, rule, audit, asset, and zone fields support later detection, triage, and enrichment stages.

The schema contains 40 uniquely named fields. Core required fields are `timestamp`, `source_type`, `source_origin`, `event_category`, `severity`, `raw_message`, and `details`; fields such as `hostname`, `user`, process data, network addresses, `action`, and `signature` remain optional because they are not present in every event family.

Schema version 1.1.0 adds `action` to preserve source-native enforcement decisions and `signature` to preserve Suricata signature text for network alert investigation.

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

## Task 5 — Normalization

### Objective

Transform the Windows and Linux intermediate NDJSON files into one dataset that conforms to `event_schema.json`, while preserving records that cannot be normalized in a separate quarantine file.

### Deliverables

- `5-normalize.sh`: schema-driven Windows and Linux normalizer.
- `normalized_events.json`: valid normalized records in NDJSON format.
- `quarantine.json`: rejected records with source location and an explicit `quarantine_reason`.

### Processing behavior

The normalizer loads all field definitions from `event_schema.json` and initializes every output record with the complete field set. Optional values that are unavailable are therefore written explicitly as `null` instead of being omitted.

The script then:

1. Reads `windows_events.json` and `linux_events.json` in deterministic order.
2. Converts source timestamps to ISO 8601 UTC.
3. Applies Windows event-ID and Linux program or audit-type mappings.
4. Maps identity, process, network, file, audit, channel, and provider data.
5. Preserves source-specific structured data in `details`.
6. Validates required fields and schema data types.
7. Writes valid records to `normalized_events.json`.
8. Writes invalid records to `quarantine.json` without silently dropping them.

Both output files are built temporarily and moved into place only after processing completes, preventing a failed run from leaving partial production outputs.

### Timestamp handling

The normalizer supports:

- ISO 8601 timestamps, including `Z` and numeric UTC offsets;
- traditional Linux syslog timestamps, using the evidence year inferred from Windows telemetry;
- Linux audit timestamps such as `audit(1774385465.371:85)`.

An absent or unparseable timestamp results in quarantine because `timestamp` is required for reliable correlation and timeline analysis.

### Category and severity mapping

Windows categories and actions are derived from event ID and channel, while Linux categories are derived from `audit_type`, program, parsed fields, and message context. Severity is normalized to `informational`, `low`, `medium`, `high`, or `critical` rather than retaining incompatible vendor-specific scales.

### Quarantine format

A quarantined record preserves the original intermediate event and adds:

```json
{
  "quarantine_source_type": "linux_text",
  "quarantine_source_line": 123,
  "quarantine_reason": "unparseable timestamp; missing required field: timestamp"
}
```

This makes data-quality failures reviewable and recoverable.

### Usage

Run against files in the project directory:

```bash
chmod +x 5-normalize.sh
./5-normalize.sh
```

Run against another working directory:

```bash
./5-normalize.sh /path/to/working_directory
```

Paths can also be supplied with `WORK_DIR`, `SCHEMA_FILE`, `WINDOWS_FILE`, `LINUX_FILE`, `NORMALIZED_FILE`, and `QUARANTINE_FILE` environment variables.

### Primary-pack result

```text
windows_json     : normalized  122575       0 quarantined
linux_text       : normalized  135832      31 quarantined
total            : normalized  258407      31 quarantined
normalized_events.json written
quarantine.json written
```

The accounting reconciles exactly:

```text
122575 Windows inputs + 135863 Linux inputs = 258438 inputs
258407 normalized events + 31 quarantined events = 258438 outputs
```

No records were lost.

### Validation

```bash
shellcheck 5-normalize.sh
bash -n 5-normalize.sh
jq empty normalized_events.json
jq empty quarantine.json
```

Confirm that normalized and quarantined counts reconcile with the inputs:

```bash
wc -l \
  windows_events.json \
  linux_events.json \
  normalized_events.json \
  quarantine.json
```

Confirm that every normalized record has all 40 schema keys without loading the
entire dataset into memory:

```bash
jq -r 'keys | length' normalized_events.json | sort -nu
```

Expected result:

```text
40
```

Review quarantine reasons:

```bash
jq -r '.quarantine_reason' quarantine.json | sort | uniq -c | sort -nr
```

### Idempotency test

```bash
./5-normalize.sh >/dev/null
sha256sum normalized_events.json quarantine.json
./5-normalize.sh >/dev/null
sha256sum normalized_events.json quarantine.json
```

Both pairs of hashes must remain identical when the inputs and schema have not changed.

### Relevance to a SOC analyst

Normalization lets one detection query use fields such as `user`, `src_ip`, `process_name`, and `event_category` regardless of whether the event originated in Windows Security, Sysmon, PowerShell, Linux syslog, or auditd. Quarantine prevents malformed timestamps or incomplete records from corrupting chronological searches while retaining the original evidence for remediation and investigation.

## Task 6 — Network Artifact Normalization

### Objective

Parse the firewall CSV, Suricata EVE NDJSON, and PCAP summary NDJSON into schema-compliant network records, write them to `network_events.json`, and append them idempotently to the combined `normalized_events.json` dataset.

### Deliverables

- `6-network_normalize.sh`: network parser, normalizer, validator, and safe append stage.
- `network_events.json`: standalone NDJSON containing only normalized network records.
- Updated `normalized_events.json`: endpoint events followed by the normalized network records.

### Schema evolution

Task 6 requires two source-native fields that were added in schema version 1.1.0:

| Field | Purpose |
| --- | --- |
| `action` | Preserves firewall values such as `ALLOW` and `BLOCK` and Suricata actions such as `allowed` |
| `signature` | Preserves the exact Suricata alert signature text |

Because every optional field must be present explicitly, Task 5 must be rerun with schema 1.1.0 before Task 6. Endpoint records then contain these fields as `null`, while applicable network events populate them.

### Source mappings

#### Firewall CSV

- Unix epoch `timestamp` is converted to ISO 8601 UTC.
- `source_type` is `firewall`.
- `event_category` is `network`.
- Source `action` is preserved in uppercase.
- `BLOCK`, `DENY`, and `DROP` receive low severity; other actions default to informational.
- Addresses, ports, protocol, interface, rule ID, and byte counts are mapped to common fields.

#### Suricata EVE

- The timezone-aware ISO timestamp and microseconds are preserved in UTC.
- `source_type` is `suricata`.
- `event_category` is `network_alert`.
- `alert.signature` populates both `signature` and `rule_name`.
- `alert.signature_id` populates `event_id` and `rule_id`.
- Suricata severity 1 maps to high, 2 to medium, 3 to low, and other values to informational.
- Flow byte counts, addresses, ports, protocol, category, and action are preserved.

#### PCAP summary

- `start_time` is parsed from `MM/DD/YYYY HH:MM:SS AM/PM` and converted to ISO 8601 UTC.
- `source_type` is `pcap`.
- `event_category` is `network_flow`.
- Session ID, endpoints, ports, protocol, end time, duration, packet count, byte total, and TCP flags are retained.

### Idempotent append behavior

Before appending freshly generated network records, the script streams through `normalized_events.json` and removes records whose `source_type` is `firewall`, `suricata`, or `pcap`. This prevents duplicate network events when the task is executed more than once while preserving all endpoint records.

Both the standalone and combined outputs are written to temporary files and moved into place only after all records pass schema validation.

### Usage

Run with the default primary evidence pack and current project directory:

```bash
chmod +x 6-network_normalize.sh
./6-network_normalize.sh
```

Run with explicit evidence and working directories:

```bash
./6-network_normalize.sh /path/to/evidence_pack /path/to/working_directory
```

Paths can also be supplied using `EVIDENCE_ROOT`, `WORK_DIR`, `SCHEMA_FILE`, `NORMALIZED_FILE`, and `NETWORK_OUTPUT`.

### Output summary

```text
firewall.csv        : <count> records normalized
suricata_eve.json  : <count> records normalized
pcap_summary.json   : <count> records normalized
appended to normalized_events.json after <count> endpoint records
network_events.json written
```

The exact counts depend on the supplied evidence pack.

### Validation

```bash
shellcheck 6-network_normalize.sh
bash -n 6-network_normalize.sh
jq empty network_events.json
jq empty normalized_events.json
```

Check network counts by source:

```bash
jq -r '.source_type' network_events.json | sort | uniq -c
```

Check the schema field count without using memory-intensive `jq -s`:

```bash
jq -r 'keys | length' network_events.json | sort -nu
```

Expected result:

```text
40
```

Check firewall actions:

```bash
jq -r '
  select(.source_type == "firewall") |
  .action
' network_events.json | sort | uniq -c
```

Check that Suricata alerts contain signatures:

```bash
jq -c '
  select(
    .source_type == "suricata"
    and .signature != null
  )
' network_events.json | head
```

### Idempotency test

```bash
./6-network_normalize.sh >/dev/null
sha256sum normalized_events.json network_events.json
./6-network_normalize.sh >/dev/null
sha256sum normalized_events.json network_events.json
```

Both pairs of hashes must remain identical.

### Relevance to a SOC analyst

A normalized network dataset lets an analyst pivot from a suspicious endpoint process to its firewall decision, corresponding PCAP flow, and Suricata signature using the same fields and query language. Preserving both normalized concepts and source-native values prevents loss of enforcement context during detection and triage.

## Task 8 — Dirty Data Handling

### Objective

Detect and correct known data-quality defects in `normalized_events.json`, write
the usable records to `cleaned_events.json`, and preserve an audit trail of every
change in `cleaning_log.json`.

### Deliverables

- `8-data_quality.sh`: streaming detection, repair, deduplication, and logging.
- `cleaned_events.json`: corrected NDJSON dataset.
- `cleaning_log.json`: JSON document containing corrections and unrepairable records.

### Defect handling

| Defect | Action |
| --- | --- |
| Malformed timestamp | Try supported fallback formats, convert successful repairs to ISO 8601 UTC, and drop only unrepairable records |
| Duplicate event | Keep the first event with the same timestamp, hostname, source type, and raw message |
| Hostname case | Convert the hostname to lowercase for consistent correlation |
| Encoding error | Reverse common Latin-1 or Windows-1252 mojibake when the repair is unambiguous |
| Suspected wrong timezone | Preserve the timestamp and add the `suspected_wrong_tz` tag when it falls more than 12 hours outside the expected evidence window |

Every cleaning entry contains `defect_type`, `original_value`,
`corrected_value`, `record_id`, and `reason`. Unrepairable records are retained
inside the `unrepairable` section of the log rather than silently discarded.

### Usage

```bash
chmod +x 8-data_quality.sh
./8-data_quality.sh
```

An explicit evidence window can be supplied when it is known:

```bash
EXPECTED_START="2026-03-18T00:00:00Z" \
EXPECTED_END="2026-03-25T23:59:59Z" \
./8-data_quality.sh
```

Without those variables, the script infers the dominant date window from the
input. Processing is streaming and output replacement is atomic, which avoids
the excessive memory use caused by loading hundreds of megabytes with `jq -s`.

### Validation

```bash
shellcheck 8-data_quality.sh
bash -n 8-data_quality.sh
jq empty cleaned_events.json
jq empty cleaning_log.json
```

Review the cleaning totals:

```bash
jq '{
  corrections: (.corrections | length),
  unrepairable: (.unrepairable | length),
  expected_range
}' cleaning_log.json
```

### Relevance to a SOC analyst

Dirty timestamps can break an incident timeline, inconsistent hostnames can
split one asset into several apparent systems, and duplicate network events can
inflate alert counts. Cleaning these defects while retaining an audit trail
makes the evidence reliable without hiding what the pipeline changed.

## Task 9 — Context Enrichment

### Objective

Attach asset inventory and network-zone context to every cleaned event so
analysts can assess business impact and network direction without performing a
separate inventory join during each investigation.

### Deliverables

- `9-enrich.sh`: streaming asset and CIDR enrichment stage.
- `enriched_events.json`: enriched NDJSON dataset.

### Enrichment behavior

For a matching hostname, the script adds an `asset` object containing:

- `role`
- `criticality`
- `os`
- `owner`
- `zone`

Hostname matching is case-insensitive and supports both short names and fully
qualified domain names. Events without an inventory match receive
`"asset": null`.

When an event contains `src_ip` or `dst_ip`, the script searches the declared
CIDR ranges and adds `src_zone` or `dst_zone`. Overlapping networks are checked
from the longest prefix to the shortest, so the most specific network wins. An
address outside every declared range receives `"unknown"`; a missing address
receives `null`.

### Usage

```bash
chmod +x 9-enrich.sh
./9-enrich.sh
```

Explicit working and evidence-pack directories can also be supplied:

```bash
./9-enrich.sh /path/to/working_directory /path/to/evidence_pack_primary
```

### Primary-pack result

The Task 9 run against the primary evidence pack produced:

```text
events processed    : 339893
asset context added : 211528 (62.23%)
src_zone resolved   : 141061 (100.00% of 141061 events with src_ip)
dst_zone resolved   : 103868 (100.00% of 103868 events with dst_ip)
unknown hosts       : 128365
enriched_events.json written
```

All 339,893 cleaned records were preserved. Every event containing a source or
destination IP was successfully mapped to a declared network zone. The 128,365
unknown-host events are not processing failures: they include network records
that do not identify an endpoint hostname and hostnames absent from the asset
inventory.

The observed runtime was 2 minutes 44.387 seconds on the lab sandbox.

### Validation

```bash
shellcheck 9-enrich.sh
bash -n 9-enrich.sh
jq empty enriched_events.json
wc -l cleaned_events.json enriched_events.json
```

Both NDJSON files should contain 339,893 records.

Review critical assets:

```bash
jq -c '
  select(.asset.criticality == "critical") |
  {timestamp, hostname, event_category, asset, src_ip, src_zone, dst_ip, dst_zone}
' enriched_events.json | head
```

Review inventory gaps:

```bash
jq -r '
  select(.hostname != null and .asset == null) |
  .hostname
' enriched_events.json | sort -u | head -30
```

### Relevance to a SOC analyst

A failed login against a critical patient database should be prioritized above
the same event on a test system. Zone context also exposes risky traffic paths,
such as a connection from `GUEST` to `CLINICAL`, directly in the event used for
detection and triage.
