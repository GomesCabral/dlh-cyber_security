#!/bin/bash
# name: 0-vuln_inventory.sh
# purpose: Build a structured inventory of installed packages with outstanding
#          security updates and known CVE enrichment.
# Project: 2x03 - Patch Equation
# Task:    0 - The Vulnerability Inventory
#
# CVE discovery:
#   - Primary source:  apt-get changelog
#   - Fallback source: locally cached Ubuntu Security Notice (USN) mapping
#   - USN cache path:  /usr/share/ubuntu-advantage-tools
#
# Notes:
#   - Only packages whose upgrade candidate comes from the "security" pocket
#     are enriched with CVE data (per spec, step 4).
#   - Missing CVEs in cve_feed.json must not abort the run (per spec note).

set -uo pipefail
# NOTE: intentionally not using -e globally; several helper calls (apt-get
# changelog, grep on absent dirs, etc.) are expected to fail/return non-zero
# under normal conditions and must not kill the whole run.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
OUTPUT_FILE="${SCRIPT_DIR}/vulnerability_inventory.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

INSTALLED="${TMP_DIR}/installed.txt"
UPGRADABLE="${TMP_DIR}/upgradable.txt"
ROWS="${TMP_DIR}/rows.jsonl"
: > "${ROWS}"

log()  { echo "[*] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

for c in dpkg-query apt apt-cache apt-get jq awk grep sed sort date wc hostname; do
    need "$c"
done

[[ -f "${CVE_FEED}" ]] || fail "cve_feed.json not found in ${SCRIPT_DIR}"
jq empty "${CVE_FEED}" >/dev/null 2>&1 || fail "cve_feed.json is invalid JSON"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

severity_from_cvss() {
    awk -v s="$1" 'BEGIN {
        if (s >= 9.0)      print "critical";
        else if (s >= 7.0) print "high";
        else if (s >= 4.0) print "medium";
        else if (s > 0)    print "low";
        else               print "unknown";
    }'
}

# Determine the origin pocket (security / updates / backports / unknown) of
# the currently pinned candidate version for a package, using apt-cache
# policy. More robust than string-position matching: it walks the version
# block for the exact candidate and inspects every origin line under it.
get_pocket() {
    local pkg="$1"
    local candidate="$2"

    apt-cache policy "${pkg}" 2>/dev/null | awk -v cand="${candidate}" '
        # A version block can have MULTIPLE origin lines at the same
        # priority (e.g. the same fixed version is published to both
        # -updates and -security simultaneously). We must collect every
        # origin line under the matching version header and THEN pick by
        # priority (security > updates > backports) -- deciding on the
        # first origin line alone is wrong, since -updates commonly sorts
        # before -security in apt-cache policy output.
        function decide(   i, tag) {
            for (i=1;i<=n;i++) {
                if (match(tags[i], /[A-Za-z0-9._-]+-security/)) {
                    print substr(tags[i],RSTART,RLENGTH); return 1
                }
            }
            for (i=1;i<=n;i++) {
                if (match(tags[i], /[A-Za-z0-9._-]+-updates/)) {
                    print substr(tags[i],RSTART,RLENGTH); return 1
                }
            }
            for (i=1;i<=n;i++) {
                if (match(tags[i], /[A-Za-z0-9._-]+-backports/)) {
                    print substr(tags[i],RSTART,RLENGTH); return 1
                }
            }
            return 0
        }
        BEGIN { in_block = 0; n = 0; done = 0 }
        # A version header line looks like:
        #    1.2.3-4 500   (or "*** 1.2.3-4 500" for the installed one)
        # The version token must NOT contain a colon, which excludes the
        # unrelated "Installed:"/"Candidate:" summary lines above the table,
        # and the trailing priority must be purely numeric to the end of
        # the line (excludes "Candidate: 5.15.0-97.107" style lines too).
        /^[[:space:]]*(\*\*\*[[:space:]]+)?[^[:space:]:]+[[:space:]]+[0-9]+[[:space:]]*$/ {
            if (in_block) { done = decide(); if (done) exit }
            ver = $0
            gsub(/^[[:space:]]*\*\*\*[[:space:]]*/, "", ver)
            gsub(/^[[:space:]]+/, "", ver)
            gsub(/[[:space:]]+$/, "", ver)
            split(ver, parts, /[[:space:]]+/)
            in_block = (parts[1] == cand)
            n = 0
            next
        }
        in_block && /^[[:space:]]+[0-9]+[[:space:]]+/ {
            n++
            tags[n] = $0
            next
        }
        END { if (in_block && !done) decide() }
    '
}

get_changelog_cves() {
    local pkg="$1"
    apt-get changelog "${pkg}" 2>/dev/null |
        grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' |
        sort -u
    return 0
}

get_local_usn_cves() {
    local pkg="$1"
    local root="/usr/share/ubuntu-advantage-tools"

    [[ -d "${root}" ]] || return 0

    grep -RIl --include='*.json' --include='*.txt' -- "${pkg}" "${root}" 2>/dev/null |
    while IFS= read -r f; do
        grep -Eo 'CVE-[0-9]{4}-[0-9]{4,7}' "${f}" 2>/dev/null
    done | sort -u
    return 0
}

# Look up a single CVE id in cve_feed.json regardless of its exact shape:
#   {"CVE-xxxx": {...}}                (flat map)
#   {"cves": {"CVE-xxxx": {...}}}      (nested map)
#   {"cves": [{"id"/"cve"/"cve_id": "CVE-xxxx", ...}, ...]}  (array)
# Accepts cvss under cvss / cvss_base / cvss_score / base_score, and the KEV
# flag under in_cisa_kev / cisa_kev / kev. Returns {cvss:0,in_cisa_kev:false}
# when not found, so a missing CVE never aborts the script.
lookup_feed() {
    local cve="$1"

    jq -c --arg id "${cve}" '
      def norm($r):
        {
          cvss: ($r.cvss // $r.cvss_base // $r.cvss_score // $r.base_score // 0),
          in_cisa_kev: ($r.in_cisa_kev // $r.cisa_kev // $r.kev // false)
        };

      if type=="object" and (.cves? | type)=="object" and (.cves[$id]? != null) then
        norm(.cves[$id])
      elif type=="object" and (.cves? | type)=="array" then
        ([.cves[] | select((.id // .cve // .cve_id // "")==$id) | norm(.)][0]
         // {cvss:0,in_cisa_kev:false})
      elif type=="object" and (has($id)) then
        norm(.[$id])
      elif type=="array" then
        ([.[] | select((.id // .cve // .cve_id // "")==$id) | norm(.)][0]
         // {cvss:0,in_cisa_kev:false})
      else
        {cvss:0,in_cisa_kev:false}
      end
    ' "${CVE_FEED}" 2>/dev/null || echo '{"cvss":0,"in_cisa_kev":false}'
}

# ---------------------------------------------------------------------------
# 1. Enumerate installed packages
# ---------------------------------------------------------------------------
log "Enumerating installed packages..."
dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' > "${INSTALLED}"

INSTALLED_COUNT="$(
    awk '$3=="install" && $4=="ok" && $5=="installed" {n++} END{print n+0}' "${INSTALLED}"
)"
echo "    Installed packages: ${INSTALLED_COUNT}"

# ---------------------------------------------------------------------------
# 2. Cross-reference against apt list --upgradable
# ---------------------------------------------------------------------------
log "Reading upgradable packages..."
apt list --upgradable 2>/dev/null | sed '1d;/^[[:space:]]*$/d' > "${UPGRADABLE}"
UPGRADABLE_COUNT="$(wc -l < "${UPGRADABLE}" | tr -d ' ')"
echo "    Upgradable packages: ${UPGRADABLE_COUNT}"

# ---------------------------------------------------------------------------
# 3-6. Pocket detection, CVE extraction, feed enrichment, row emission
# ---------------------------------------------------------------------------
log "Identifying security-pocket upgrades and enriching with CVE data..."

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

    echo "    [security] ${pkg}: ${installed_version} -> ${candidate} (${pocket})"

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

jq empty "${OUTPUT_FILE}" >/dev/null 2>&1 || fail "vulnerability_inventory.json is invalid JSON"

log "Inventory complete."
echo "    Vulnerable security packages: ${vuln_count}"
echo "    Packages with CISA KEV CVEs:  ${kev_count}"
echo "Report saved to: vulnerability_inventory.json"