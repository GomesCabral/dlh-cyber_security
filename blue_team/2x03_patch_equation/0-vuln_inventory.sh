#!/bin/bash
# name: 0-vuln_inventory.sh
# purpose: Build a structured inventory of installed packages with outstanding security updates and known CVE enrichment.
# author: Pedro Cabral
# Project: 2x03 - Patch Equation
# Task: 0 - The Vulnerability Inventory
# CVE discovery:
# - Primary source: apt-get changelog
# - Fallback source: locally cached Ubuntu Security Notice (USN) mapping
# - USN cache location: /usr/share/ubuntu-advantage-tools

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
OUTPUT_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

INSTALLED="${TMP_DIR}/installed.txt"
UPGRADABLE="${TMP_DIR}/upgradable.txt"
ROWS="${TMP_DIR}/rows.jsonl"
: > "${ROWS}"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[FAIL] Required command not found: $1"
        exit 1
    }
}

for c in dpkg-query apt apt-cache apt-get jq awk grep sed sort date wc; do
    need "$c"
done

[[ -f "${CVE_FEED}" ]] || {
    echo "[FAIL] cve_feed.json not found in ${SCRIPT_DIR}"
    exit 1
}

jq empty "${CVE_FEED}" >/dev/null 2>&1 || {
    echo "[FAIL] cve_feed.json is invalid JSON"
    exit 1
}

severity_from_cvss() {
    awk -v s="$1" 'BEGIN {
        if (s >= 9.0) print "critical";
        else if (s >= 7.0) print "high";
        else if (s >= 4.0) print "medium";
        else if (s > 0) print "low";
        else print "unknown";
    }'
}

get_pocket() {
    local pkg="$1"
    local candidate="$2"

    apt-cache policy "${pkg}" 2>/dev/null |
    awk -v cand="${candidate}" '
        BEGIN { active=0 }
        /^[[:space:]]*\*\*\*/ {
            active=($2==cand)
            next
        }
        /^[[:space:]]+[0-9]+[[:space:]]+/ {
            active=($2==cand)
            next
        }
        active && /-security/ {
            if (match($0, /[A-Za-z0-9._-]+-security/)) {
                print substr($0,RSTART,RLENGTH)
                exit
            }
            print "security"
            exit
        }
        active && /-updates/ {
            if (match($0, /[A-Za-z0-9._-]+-updates/)) {
                print substr($0,RSTART,RLENGTH)
                exit
            }
            print "updates"
            exit
        }
        active && /-backports/ {
            if (match($0, /[A-Za-z0-9._-]+-backports/)) {
                print substr($0,RSTART,RLENGTH)
                exit
            }
            print "backports"
            exit
        }
    '
}

get_changelog_cves() {
    local pkg="$1"
    apt-get changelog "${pkg}" 2>/dev/null |
        grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' |
        sort -u || true
}

get_local_usn_cves() {
    local pkg="$1"
    local root="/usr/share/ubuntu-advantage-tools"

    [[ -d "${root}" ]] || return 0

    grep -RIl --include='*.json' --include='*.txt' -- "${pkg}" "${root}" 2>/dev/null |
    while IFS= read -r f; do
        grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' "${f}" 2>/dev/null || true
    done |
    sort -u
}

lookup_feed() {
    local cve="$1"

    jq -c --arg id "${cve}" '
      def norm($r):
        {
          cvss: ($r.cvss // $r.cvss_base // $r.cvss_score // $r.base_score // 0),
          in_cisa_kev: ($r.in_cisa_kev // $r.cisa_kev // $r.kev // false)
        };

      if type=="object" and has($id) then
        norm(.[$id])
      elif type=="object" and (.cves? | type)=="object" and .cves[$id] then
        norm(.cves[$id])
      elif type=="array" then
        ([.[] | select((.id // .cve // .cve_id // "")==$id) | norm(.)][0]
         // {cvss:0,in_cisa_kev:false})
      else
        {cvss:0,in_cisa_kev:false}
      end
    ' "${CVE_FEED}"
}

echo "[*] Enumerating installed packages..."
dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' > "${INSTALLED}"

INSTALLED_COUNT="$(
    awk '$3=="install" && $4=="ok" && $5=="installed" {n++} END{print n+0}' "${INSTALLED}"
)"
echo "    Installed packages: ${INSTALLED_COUNT}"

echo "[*] Reading upgradable packages..."
apt list --upgradable 2>/dev/null | sed '1d;/^[[:space:]]*$/d' > "${UPGRADABLE}"
UPGRADABLE_COUNT="$(wc -l < "${UPGRADABLE}" | tr -d ' ')"
echo "    Upgradable packages: ${UPGRADABLE_COUNT}"

echo "[*] Identifying security-pocket upgrades..."

while IFS= read -r line; do
    [[ -n "${line}" ]] || continue

    pkg_arch="${line%%/*}"
    pkg="${pkg_arch%%:*}"
    candidate="$(awk '{print $2}' <<< "${line}")"

    installed_version="$(
        dpkg-query -W -f='${Version}\n' "${pkg_arch}" 2>/dev/null ||
        dpkg-query -W -f='${Version}\n' "${pkg}" 2>/dev/null ||
        true
    )"

    [[ -n "${installed_version}" ]] || continue

    pocket="$(get_pocket "${pkg}" "${candidate}")"
    [[ -n "${pocket}" ]] || pocket="unknown"

    case "${pocket}" in
        *security*) ;;
        *) continue ;;
    esac

    echo "    [security] ${pkg}: ${installed_version} -> ${candidate}"

    cves="$(get_changelog_cves "${pkg}")"
    if [[ -z "${cves}" ]]; then
        cves="$(get_local_usn_cves "${pkg}")"
    fi

    if [[ -n "${cves}" ]]; then
        cve_json="$(printf '%s\n' "${cves}" | jq -Rsc 'split("\n")|map(select(length>0))|unique')"
    else
        cve_json='[]'
    fi

    max_cvss=0
    in_kev=false

    while IFS= read -r cve; do
        [[ -n "${cve}" ]] || continue
        rec="$(lookup_feed "${cve}")"
        score="$(jq -r '.cvss // 0' <<< "${rec}")"
        kev="$(jq -r '.in_cisa_kev // false' <<< "${rec}")"

        max_cvss="$(awk -v a="${max_cvss}" -v b="${score}" 'BEGIN{print (b+0>a+0)?b+0:a+0}')"
        [[ "${kev}" == "true" ]] && in_kev=true
    done < <(jq -r '.[]' <<< "${cve_json}")

    severity="$(severity_from_cvss "${max_cvss}")"

    jq -cn \
      --arg package "${pkg}" \
      --arg installed_version "${installed_version}" \
      --arg candidate_version "${candidate}" \
      --arg source_pocket "${pocket}" \
      --argjson cves "${cve_json}" \
      --argjson max_cvss "${max_cvss}" \
      --arg severity "${severity}" \
      --argjson in_cisa_kev "${in_kev}" \
      '{
         package:$package,
         installed_version:$installed_version,
         candidate_version:$candidate_version,
         source_pocket:$source_pocket,
         cves:$cves,
         max_cvss:$max_cvss,
         severity:$severity,
         in_cisa_kev:$in_cisa_kev
       }' >> "${ROWS}"

done < "${UPGRADABLE}"

if [[ -s "${ROWS}" ]]; then
    packages="$(jq -s 'sort_by(-.max_cvss,.package)' "${ROWS}")"
else
    packages='[]'
fi

vuln_count="$(jq 'length' <<< "${packages}")"
kev_count="$(jq '[.[]|select(.in_cisa_kev==true)]|length' <<< "${packages}")"

jq -n \
  --arg generated_at_utc "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg hostname "$(hostname)" \
  --argjson installed_packages "${INSTALLED_COUNT}" \
  --argjson upgradable_packages "${UPGRADABLE_COUNT}" \
  --argjson vulnerable_packages "${vuln_count}" \
  --argjson cisa_kev_packages "${kev_count}" \
  --argjson packages "${packages}" \
  '{
     metadata:{
       report:"2x03 Patch Equation - Vulnerability Inventory",
       generated_at_utc:$generated_at_utc,
       hostname:$hostname,
       package_manager:"dpkg/apt",
       cve_feed:"cve_feed.json"
     },
     summary:{
       installed_packages:$installed_packages,
       upgradable_packages:$upgradable_packages,
       vulnerable_security_packages:$vulnerable_packages,
       cisa_kev_packages:$cisa_kev_packages
     },
     packages:$packages
   }' > "${OUTPUT_FILE}"

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || {
    echo "[FAIL] vulnerability_inventory.json is invalid JSON"
    exit 1
}

echo "[*] Inventory complete."
echo "    Vulnerable security packages: ${vuln_count}"
echo "    Packages with CISA KEV CVEs:  ${kev_count}"
echo "Report saved to: vulnerability_inventory.json"