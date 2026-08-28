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

## Project status

| Task | Status |
| --- | --- |
| Task 0 — Evidence Pack Inventory | Implemented |
| Remaining tasks | Pending |
