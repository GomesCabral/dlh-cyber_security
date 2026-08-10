#!/bin/bash

# name: 14-coverage_assessment.sh
# purpose: Produce the final cross-platform telemetry coverage assessment from the SOC handoff, detection matrices, telemetry quality reports, and Sysmon coverage matrix.
# author: Pedro Cabral
#
# Project: 2x02 - Eyes on Endpoint
# Task: 14 - Cross-Platform Coverage Assessment
#
# Detection matrix summary:
# - total simulated actions
# - captured actions
# - missed actions
# - multi-source detections
#
# Output:
# - telemetry_coverage_assessment.json
#
# Safety:
# - READ-ONLY with respect to telemetry and source reports.
# - Writes only telemetry_coverage_assessment.json.

set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
    pwd -P
)"

HANDOFF_DIR="${SCRIPT_DIR}/telemetry_handoff"

WINDOWS_EVENTS="${HANDOFF_DIR}/windows_events.json"
LINUX_EVENTS="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH="${HANDOFF_DIR}/attack_ground_truth.json"

WINDOWS_DETECTION="${SCRIPT_DIR}/windows_detection_matrix.json"
LINUX_DETECTION="${SCRIPT_DIR}/linux_detection_matrix.json"

WINDOWS_QUALITY="${SCRIPT_DIR}/windows_telemetry_quality.json"
LINUX_QUALITY="${SCRIPT_DIR}/linux_telemetry_quality.json"
SYSMON_COVERAGE="${SCRIPT_DIR}/sysmon_coverage_matrix.json"

OUTPUT_FILE="${SCRIPT_DIR}/telemetry_coverage_assessment.json"

require_command() {
    local command_name="$1"
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf '[FAIL] Required command not found: %s\n' "${command_name}"
        exit 1
    fi
}

require_command jq
require_command date

for input_file in \
    "${WINDOWS_EVENTS}" \
    "${LINUX_EVENTS}" \
    "${GROUND_TRUTH}" \
    "${WINDOWS_DETECTION}" \
    "${LINUX_DETECTION}" \
    "${WINDOWS_QUALITY}" \
    "${LINUX_QUALITY}" \
    "${SYSMON_COVERAGE}"
do
    if [[ ! -f "${input_file}" ]]; then
        printf '[FAIL] Required input file not found: %s\n' "${input_file}"
        exit 1
    fi

    if ! jq empty "${input_file}" >/dev/null 2>&1; then
        printf '[FAIL] Invalid JSON: %s\n' "${input_file}"
        exit 1
    fi
done

printf '[*] Loading telemetry handoff package...\n'

WINDOWS_EVENT_COUNT="$(jq '.events | length' "${WINDOWS_EVENTS}")"
LINUX_EVENT_COUNT="$(jq '.events | length' "${LINUX_EVENTS}")"
GROUND_TRUTH_COUNT="$(jq '.actions | length' "${GROUND_TRUTH}")"

printf 'Windows events: %s\n' "${WINDOWS_EVENT_COUNT}"
printf 'Linux events: %s\n' "${LINUX_EVENT_COUNT}"
printf 'Ground truth actions: %s\n' "${GROUND_TRUTH_COUNT}"

# -----------------------------------------------------------------------------
# Build normalized detection/action summaries:
# captured, missed, and multi-source detections.
#
# Windows and Linux detection reports may differ slightly in schema.  The
# function below supports:
#   metadata totals
#   detections[]
#   status strings such as [CAPTURED]/[MISSED]
#   action_number as the correlation identifier
# -----------------------------------------------------------------------------

jq -n \
    --slurpfile we "${WINDOWS_EVENTS}" \
    --slurpfile le "${LINUX_EVENTS}" \
    --slurpfile gt "${GROUND_TRUTH}" \
    --slurpfile wd "${WINDOWS_DETECTION}" \
    --slurpfile ld "${LINUX_DETECTION}" \
    --slurpfile wq "${WINDOWS_QUALITY}" \
    --slurpfile lq "${LINUX_QUALITY}" \
    --slurpfile sc "${SYSMON_COVERAGE}" \
'
def dist($events; $field):
    [
        $events[]
        | .[$field]
        | select(. != null and . != "")
    ]
    | group_by(.)
    | map({
        value: .[0],
        count: length,
        percentage_of_platform:
            (
                if ($events | length) == 0 then 0
                else ((length / ($events | length)) * 100)
                end
            )
    });

def score_of($q):
    (
        $q.quality_score.score
        // $q.quality_score
        // $q.score
        // $q.metadata.quality_score
        // 0
    ) | tonumber;

def assessment_of($q):
    (
        $q.quality_score.assessment
        // $q.assessment
        // $q.metadata.assessment
        // "unknown"
    );

def detection_rows($doc; $platform):
    [
        ($doc.detections // [])[]
        | . + {platform: $platform}
    ];

def is_captured:
    ((.status // "") | ascii_upcase | contains("CAPTURED"));

def action_key:
    (.platform + ":" + ((.action_number // .action // "unknown") | tostring));

def summarize_detection($rows):
    (
        $rows
        | group_by(action_key)
        | map({
            action_key: (.[0] | action_key),
            platform: .[0].platform,
            action_number: .[0].action_number,
            action: (.[0].action // .[0].description // ""),
            captured: any(.[]; is_captured),
            sources:
                [
                    .[]
                    | select(is_captured)
                    | .source
                    | select(. != null and . != "" and . != "-")
                ]
                | unique,
            details:
                [
                    .[]
                    | {
                        source: (.source // "-"),
                        detail: (.detail // "Unknown"),
                        status: (.status // ""),
                        audit_key: (.audit_key // null)
                    }
                ]
        })
    );

def gt_actions($gt):
    [
        ($gt.actions // [])[]
        | {
            platform:
                (
                    .platform
                    // if ((.hostname // "") | ascii_downcase | contains("linux"))
                       then "Linux"
                       else "Unknown"
                       end
                ),
            action_number: .action_number,
            timestamp: .timestamp,
            description: (.description // .action // ""),
            technique_id:
                (
                    .mitre_attack.technique_id
                    // .technique_id
                    // .mitre_technique
                    // "UNKNOWN"
                ),
            technique_name:
                (
                    .mitre_attack.technique_name
                    // .technique_name
                    // ""
                )
        }
    ];

def technique_source($summary; $platform; $number):
    [
        $summary[]
        | select(
            .platform == $platform
            and (.action_number | tostring) == ($number | tostring)
        )
        | .sources[]
    ] | unique;

def technique_state($summary; $platform; $number):
    (
        [
            $summary[]
            | select(
                .platform == $platform
                and (.action_number | tostring) == ($number | tostring)
            )
        ]
        | if length == 0 then
            "blind"
          elif .[0].captured == false then
            "blind"
          elif (.[0].sources | length) > 1 then
            "covered"
          elif
            (
                [
                    .[0].details[]
                    | select(
                        ((.status // "") | ascii_upcase | contains("CAPTURED"))
                        and ((.detail // "") | ascii_downcase == "full")
                    )
                ] | length
            ) > 0
          then
            "covered"
          else
            "partial"
          end
    );

def sysmon_gap_hints($sc):
    [
        (
            $sc.coverage
            // $sc.matrix
            // $sc.events
            // $sc.detections
            // []
        )[]
        | select(
            (
                (.status // .coverage // .detail // "")
                | tostring
                | ascii_downcase
            )
            | test("miss|blind|partial|not covered|disabled")
        )
        | {
            description:
                (
                    "Sysmon coverage limitation: "
                    + (
                        .description
                        // .event
                        // .event_name
                        // .name
                        // ("Event ID " + ((.event_id // "?") | tostring))
                    )
                ),
            impacted_platform: "Windows",
            impacted_technique:
                (
                    .technique_id
                    // .mitre_attack.technique_id
                    // "Unspecified"
                ),
            reason:
                (
                    .reason
                    // .status
                    // .coverage
                    // "Sysmon coverage matrix reports incomplete visibility."
                ),
            recommended_instrumentation_improvement:
                (
                    .recommendation
                    // .recommended_improvement
                    // "Review the Sysmon configuration and enable the required event type and fields."
                )
        }
    ];

($we[0].events // []) as $windows_events |
($le[0].events // []) as $linux_events |
(detection_rows($wd[0]; "Windows") + detection_rows($ld[0]; "Linux")) as $drows |
summarize_detection($drows) as $dsummary |
gt_actions($gt[0]) as $ground_truth |

[
    $ground_truth[]
    | . as $a
    | . + {
        coverage:
            technique_state(
                $dsummary;
                $a.platform;
                $a.action_number
            ),
        sources:
            technique_source(
                $dsummary;
                $a.platform;
                $a.action_number
            )
    }
] as $attack_actions |

[
    $attack_actions
    | group_by(.technique_id)[]
    | {
        technique_id: .[0].technique_id,
        technique_name: .[0].technique_name,
        platforms: ([.[].platform] | unique),
        action_count: length,
        sources: ([.[].sources[]] | unique),
        coverage:
            (
                if any(.[]; .coverage == "blind") then
                    if any(.[]; .coverage == "covered" or .coverage == "partial")
                    then "partial"
                    else "blind"
                    end
                elif any(.[]; .coverage == "partial") then
                    "partial"
                else
                    "covered"
                end
            )
    }
] as $techniques |

[
    $attack_actions[]
    | select(.coverage == "blind" or .coverage == "partial")
    | {
        description:
            (
                if .coverage == "blind"
                then "No adequate detection was found for simulated action: " + .description
                else "Only partial telemetry detail was available for simulated action: " + .description
                end
            ),
        impacted_platform: .platform,
        impacted_technique: .technique_id,
        reason:
            (
                if .coverage == "blind"
                then "The detection matrix did not contain a captured event for this ground-truth action."
                else "The action was captured, but the detection matrix did not provide full-detail coverage."
                end
            ),
        recommended_instrumentation_improvement:
            (
                if .platform == "Windows"
                then "Review Windows audit policy, Sysmon configuration, PowerShell logging, and required event fields for this technique."
                else "Review auditd rules/keys, auth/syslog collection, and required event fields for this technique."
                end
            )
    }
] as $detection_gaps |

(sysmon_gap_hints($sc[0])) as $sysmon_gaps |

(score_of($wq[0])) as $windows_score |
(score_of($lq[0])) as $linux_score |
(($windows_score + $linux_score) / 2) as $average_quality |

(
    if
        ($techniques | map(select(.coverage == "blind")) | length) > 0
        or $average_quality < 65
    then "poor"
    elif
        ($techniques | map(select(.coverage == "partial")) | length) > 0
        or $average_quality < 90
    then "acceptable"
    else "good"
    end
) as $confidence |

{
    metadata: {
        report: "2x02 Eyes on Endpoint - Cross-Platform Coverage Assessment",
        generated_at_utc: (now | todateiso8601),
        inputs: [
            "telemetry_handoff/windows_events.json",
            "telemetry_handoff/linux_events.json",
            "telemetry_handoff/attack_ground_truth.json",
            "windows_detection_matrix.json",
            "linux_detection_matrix.json",
            "windows_telemetry_quality.json",
            "linux_telemetry_quality.json",
            "sysmon_coverage_matrix.json"
        ]
    },

    total_events: {
        total: (($windows_events | length) + ($linux_events | length)),
        by_platform: {
            Windows: ($windows_events | length),
            Linux: ($linux_events | length)
        },
        by_source_type: {
            Windows: dist($windows_events; "source_type"),
            Linux: dist($linux_events; "source_type")
        },
        by_event_category: {
            Windows: dist($windows_events; "event_category"),
            Linux: dist($linux_events; "event_category")
        }
    },

    detection_matrix_summary: {
        total_simulated_actions: ($ground_truth | length),
        captured_actions: ($dsummary | map(select(.captured == true)) | length),
        missed_actions:
            (
                ($ground_truth | length)
                -
                ($dsummary | map(select(.captured == true)) | length)
            ),
        multi_source_detections:
            (
                $dsummary
                | map(select(.captured == true and (.sources | length) > 1))
                | length
            ),
        by_platform: {
            Windows: {
                total:
                    ($ground_truth | map(select(.platform == "Windows")) | length),
                captured:
                    ($dsummary | map(select(.platform == "Windows" and .captured == true)) | length),
                multi_source:
                    ($dsummary | map(select(.platform == "Windows" and .captured == true and (.sources | length) > 1)) | length)
            },
            Linux: {
                total:
                    ($ground_truth | map(select(.platform == "Linux")) | length),
                captured:
                    ($dsummary | map(select(.platform == "Linux" and .captured == true)) | length),
                multi_source:
                    ($dsummary | map(select(.platform == "Linux" and .captured == true and (.sources | length) > 1)) | length)
            }
        }
    },

    attack_coverage: {
        covered_count: ($techniques | map(select(.coverage == "covered")) | length),
        partial_count: ($techniques | map(select(.coverage == "partial")) | length),
        blind_count: ($techniques | map(select(.coverage == "blind")) | length),

        covered_techniques:
            ($techniques | map(select(.coverage == "covered"))),

        partially_covered_techniques:
            ($techniques | map(select(.coverage == "partial"))),

        blind_techniques:
            ($techniques | map(select(.coverage == "blind")))
    },

    known_gaps:
        (($detection_gaps + $sysmon_gaps) | unique_by(.description)),

    quality_summary: {
        Windows: {
            score: $windows_score,
            source_assessment: assessment_of($wq[0])
        },
        Linux: {
            score: $linux_score,
            source_assessment: assessment_of($lq[0])
        },
        average_score: $average_quality,
        final_handoff_confidence: $confidence,
        confidence_logic:
            "poor if any blind ATT&CK technique exists or average quality <65; acceptable if any partial technique exists or average quality <90; otherwise good"
    }
}
' > "${OUTPUT_FILE}"

if ! jq empty "${OUTPUT_FILE}" >/dev/null 2>&1; then
    printf '[FAIL] telemetry_coverage_assessment.json is invalid JSON.\n'
    exit 1
fi

CAPTURED="$(jq '.detection_matrix_summary.captured_actions' "${OUTPUT_FILE}")"
TOTAL_ACTIONS="$(jq '.detection_matrix_summary.total_simulated_actions' "${OUTPUT_FILE}")"
COVERED="$(jq '.attack_coverage.covered_count' "${OUTPUT_FILE}")"
PARTIAL="$(jq '.attack_coverage.partial_count' "${OUTPUT_FILE}")"
BLIND="$(jq '.attack_coverage.blind_count' "${OUTPUT_FILE}")"
WINDOWS_SCORE="$(jq -r '.quality_summary.Windows.score' "${OUTPUT_FILE}")"
LINUX_SCORE="$(jq -r '.quality_summary.Linux.score' "${OUTPUT_FILE}")"
CONFIDENCE="$(jq -r '.quality_summary.final_handoff_confidence' "${OUTPUT_FILE}")"

printf 'Detection matrix: %s/%s captured\n' "${CAPTURED}" "${TOTAL_ACTIONS}"
printf 'ATT&CK covered: %s\n' "${COVERED}"
printf 'ATT&CK partial: %s\n' "${PARTIAL}"
printf 'ATT&CK blind: %s\n' "${BLIND}"
printf 'Windows quality: %s\n' "${WINDOWS_SCORE}"
printf 'Linux quality: %s\n' "${LINUX_SCORE}"
printf 'Confidence: %s\n' "${CONFIDENCE}"
printf 'Report saved to: telemetry_coverage_assessment.json\n'

exit 0