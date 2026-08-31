#!/bin/bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${1:-$SCRIPT_DIR}"
EVIDENCE_ROOT="${2:-${EVIDENCE_PACK_ROOT:-$HOME/evidence_pack_primary}}"

INPUT_FILE="$WORK_DIR/cleaned_events.json"
ASSET_FILE="$EVIDENCE_ROOT/context/asset_inventory.json"
ZONE_FILE="$EVIDENCE_ROOT/context/network_zones.json"
OUTPUT_FILE="$WORK_DIR/enriched_events.json"

for required_file in "$INPUT_FILE" "$ASSET_FILE" "$ZONE_FILE"; do
    if [[ ! -r "$required_file" ]]; then
        echo "error: required file is not readable: $required_file" >&2
        exit 1
    fi
done

mkdir -p -- "$WORK_DIR"

python3 - "$INPUT_FILE" "$ASSET_FILE" "$ZONE_FILE" "$OUTPUT_FILE" <<'PYTHON'
import ipaddress
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


input_file = Path(sys.argv[1])
asset_file = Path(sys.argv[2])
zone_file = Path(sys.argv[3])
output_file = Path(sys.argv[4])


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: cannot parse {path}: {exc}") from exc


def normalize_hostname(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().rstrip(".").lower()
    return normalized or None


def first_present(record: Dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return None


def record_lists(document: Any, preferred_keys: Iterable[str]) -> List[Any]:
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        return []
    for key in preferred_keys:
        value = document.get(key)
        if isinstance(value, list):
            return value
    return []


def build_asset_index(document: Any) -> Tuple[Dict[str, Dict[str, Any]], set]:
    records = record_lists(document, ("assets", "asset_inventory", "inventory", "hosts"))

    # Also accept an object keyed directly by hostname.
    if not records and isinstance(document, dict):
        records = []
        for hostname, details in document.items():
            if isinstance(details, dict):
                item = dict(details)
                item.setdefault("hostname", hostname)
                records.append(item)

    exact: Dict[str, Dict[str, Any]] = {}
    short_candidates: Dict[str, List[Dict[str, Any]]] = {}

    for item in records:
        if not isinstance(item, dict):
            continue
        hostname = normalize_hostname(
            first_present(item, ("hostname", "host", "name", "asset_name", "fqdn"))
        )
        if hostname is None:
            continue

        context = {
            "role": first_present(item, ("role", "asset_role", "function")),
            "criticality": first_present(
                item, ("criticality", "asset_criticality", "priority")
            ),
            "os": first_present(item, ("os", "operating_system", "platform")),
            "owner": first_present(item, ("owner", "asset_owner", "business_owner")),
            "zone": first_present(item, ("zone", "network_zone", "segment")),
        }
        exact[hostname] = context
        short_candidates.setdefault(hostname.split(".", 1)[0], []).append(context)

    # A short-name match is safe only if it maps to exactly one inventory item.
    ambiguous_short_names = {
        name for name, candidates in short_candidates.items() if len(candidates) != 1
    }
    for name, candidates in short_candidates.items():
        if name not in ambiguous_short_names and name not in exact:
            exact[name] = candidates[0]

    return exact, ambiguous_short_names


def add_zone_network(
    result: List[Tuple[ipaddress._BaseNetwork, str]],
    zone_name: Any,
    network_value: Any,
) -> None:
    if zone_name in (None, "") or network_value in (None, ""):
        return
    try:
        network = ipaddress.ip_network(str(network_value).strip(), strict=False)
    except ValueError as exc:
        raise SystemExit(
            f"error: invalid CIDR {network_value!r} for zone {zone_name!r}: {exc}"
        ) from exc
    result.append((network, str(zone_name)))


def build_zone_index(document: Any) -> List[Tuple[ipaddress._BaseNetwork, str]]:
    result: List[Tuple[ipaddress._BaseNetwork, str]] = []
    records = record_lists(document, ("zones", "network_zones", "networks"))

    if records:
        for item in records:
            if not isinstance(item, dict):
                continue
            zone_name = first_present(item, ("zone", "name", "zone_name", "id"))
            networks = first_present(
                item,
                ("cidrs", "ranges", "networks", "subnets", "cidr", "network", "subnet"),
            )
            if not isinstance(networks, list):
                networks = [networks]
            for network_value in networks:
                add_zone_network(result, zone_name, network_value)
    elif isinstance(document, dict):
        # Also accept {"CLINICAL": ["10.1.0.0/16"], ...}.
        for zone_name, value in document.items():
            if isinstance(value, dict):
                networks = first_present(
                    value,
                    ("cidrs", "ranges", "networks", "subnets", "cidr", "network", "subnet"),
                )
            else:
                networks = value
            if not isinstance(networks, list):
                networks = [networks]
            for network_value in networks:
                add_zone_network(result, zone_name, network_value)

    if not result:
        raise SystemExit(f"error: no usable CIDR ranges found in {zone_file}")

    # Longest-prefix first makes overlapping ranges deterministic and specific.
    result.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
    return result


def resolve_zone(value: Any, networks: List[Tuple[ipaddress._BaseNetwork, str]]) -> str:
    if value in (None, ""):
        return "unknown"
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "unknown"
    for network, zone_name in networks:
        if address.version == network.version and address in network:
            return zone_name
    return "unknown"


assets, ambiguous_short_names = build_asset_index(load_json(asset_file))
networks = build_zone_index(load_json(zone_file))

if not assets:
    raise SystemExit(f"error: no usable assets found in {asset_file}")

total = 0
asset_added = 0
unknown_hosts = 0
src_present = 0
dst_present = 0
src_resolved = 0
dst_resolved = 0

output_file.parent.mkdir(parents=True, exist_ok=True)
temporary_path: Optional[Path] = None

try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=output_file.parent,
        prefix=f".{output_file.name}.",
        suffix=".tmp",
        delete=False,
    ) as output_handle:
        temporary_path = Path(output_handle.name)

        with input_file.open("r", encoding="utf-8-sig") as input_handle:
            for line_number, line in enumerate(input_handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SystemExit(
                        f"error: invalid JSON at {input_file}:{line_number}: {exc.msg}"
                    ) from exc
                if not isinstance(event, dict):
                    raise SystemExit(
                        f"error: record at {input_file}:{line_number} is not an object"
                    )

                total += 1
                hostname = normalize_hostname(event.get("hostname"))
                asset_context = assets.get(hostname) if hostname else None
                if asset_context is not None:
                    event["asset"] = dict(asset_context)
                    asset_added += 1
                else:
                    event["asset"] = None
                    unknown_hosts += 1

                src_ip = event.get("src_ip")
                if src_ip not in (None, ""):
                    src_present += 1
                    event["src_zone"] = resolve_zone(src_ip, networks)
                    if event["src_zone"] != "unknown":
                        src_resolved += 1
                else:
                    event["src_zone"] = None

                dst_ip = event.get("dst_ip")
                if dst_ip not in (None, ""):
                    dst_present += 1
                    event["dst_zone"] = resolve_zone(dst_ip, networks)
                    if event["dst_zone"] != "unknown":
                        dst_resolved += 1
                else:
                    event["dst_zone"] = None

                json.dump(event, output_handle, ensure_ascii=False, separators=(",", ":"))
                output_handle.write("\n")

        output_handle.flush()
        os.fsync(output_handle.fileno())

    os.replace(temporary_path, output_file)
    temporary_path = None
except (OSError, UnicodeError) as exc:
    raise SystemExit(f"error: enrichment failed: {exc}") from exc
finally:
    if temporary_path is not None:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def percentage(count: int, denominator: int) -> float:
    return (count * 100.0 / denominator) if denominator else 0.0


print(f"events processed    : {total}")
print(
    f"asset context added : {asset_added} "
    f"({percentage(asset_added, total):.2f}%)"
)
print(
    f"src_zone resolved   : {src_resolved} "
    f"({percentage(src_resolved, src_present):.2f}% of {src_present} events with src_ip)"
)
print(
    f"dst_zone resolved   : {dst_resolved} "
    f"({percentage(dst_resolved, dst_present):.2f}% of {dst_present} events with dst_ip)"
)
print(f"unknown hosts       : {unknown_hosts}")
print(f"{output_file.name} written")
PYTHON
