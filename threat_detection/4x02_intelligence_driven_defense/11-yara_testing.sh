#!/bin/bash
set -euo pipefail

# 11-yara_testing.sh
# HEALTHBANE YARA validation harness.
#
# This project has no Task 10, so the script tests every .yar file available
# in the project directory. At minimum, 9-yara_phishing_pdf.yar is expected.
#
# Expected project layout:
#   9-yara_phishing_pdf.yar
#   11-yara_testing.sh
#   samples/
#     samples_manifest.txt
#     phishing_sample.pdf
#     healthbane_lure_02.pdf
#     clean_invoice.pdf
#     benign_invoice.pdf
#     ...

SAMPLES_DIR="${SAMPLES_DIR:-samples}"
MANIFEST="${MANIFEST:-$SAMPLES_DIR/samples_manifest.txt}"

# If rule paths are passed as arguments, test those.
# Otherwise discover all .yar files in the current project directory.
if (($# > 0)); then
    RULE_FILES=("$@")
else
    mapfile -t RULE_FILES < <(find . -maxdepth 1 -type f -name '*.yar' -printf '%p\n' | sort)
fi

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

command -v yara >/dev/null 2>&1 || die "yara is not installed or not in PATH."
[[ -d "$SAMPLES_DIR" ]] || die "Samples directory not found: $SAMPLES_DIR"
[[ -f "$MANIFEST" ]] || die "Manifest not found: $MANIFEST"
((${#RULE_FILES[@]} > 0)) || die "No .yar rule files found."

# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------
# We first try to derive labels from samples_manifest.txt.
# If the manifest wording is not machine-friendly, the known corpus fallback
# below provides explicit labels from the exercise instructions.
#
# Label meanings:
#   malicious -> a detection is expected for a rule intended for that file type
#   benign    -> no detection is expected
#
# IMPORTANT:
# A PDF-specific rule must not be penalized for not matching malicious .eml
# files. Each rule is evaluated only against the sample class it is designed
# to cover. This prevents meaningless false negatives.

declare -A LABEL
declare -A FAMILY

# Known supplied corpus / task ground truth.
LABEL["phishing_sample.pdf"]="malicious"
FAMILY["phishing_sample.pdf"]="pdf"

LABEL["healthbane_lure_02.pdf"]="malicious"
FAMILY["healthbane_lure_02.pdf"]="pdf"

LABEL["clean_invoice.pdf"]="benign"
FAMILY["clean_invoice.pdf"]="pdf"

LABEL["benign_invoice.pdf"]="benign"
FAMILY["benign_invoice.pdf"]="pdf"

LABEL["healthbane_email_01.eml"]="malicious"
FAMILY["healthbane_email_01.eml"]="email"

LABEL["healthbane_email_02.eml"]="malicious"
FAMILY["healthbane_email_02.eml"]="email"

# Known variant: malicious campaign sample. If an email rule misses it,
# that result must be recorded as a false negative rather than ignored.
LABEL["healthbane_email_03.eml"]="malicious"
FAMILY["healthbane_email_03.eml"]="email"

LABEL["benign_newsletter.eml"]="benign"
FAMILY["benign_newsletter.eml"]="email"

# Any additional files are classified from manifest text where possible.
classify_from_manifest() {
    local file="$1"
    local base
    base="$(basename "$file")"

    if [[ -n "${LABEL[$base]+x}" ]]; then
        printf '%s\n' "${LABEL[$base]}"
        return 0
    fi

    local line
    line="$(grep -i -F "$base" "$MANIFEST" | head -n 1 || true)"

    if [[ "$line" =~ [Mm]alicious|[Pp]hishing|[Hh][Ee][Aa][Ll][Tt][Hh][Bb][Aa][Nn][Ee] ]]; then
        printf 'malicious\n'
    elif [[ "$line" =~ [Bb]enign|[Cc]lean ]]; then
        printf 'benign\n'
    else
        printf 'unknown\n'
    fi
}

family_for_file() {
    local file="$1"
    local base ext
    base="$(basename "$file")"

    if [[ -n "${FAMILY[$base]+x}" ]]; then
        printf '%s\n' "${FAMILY[$base]}"
        return
    fi

    ext="${base##*.}"
    case "${ext,,}" in
        pdf) printf 'pdf\n' ;;
        eml) printf 'email\n' ;;
        *)   printf 'other\n' ;;
    esac
}

# Infer the intended sample family from rule content/name.
rule_family() {
    local rule="$1"

    if grep -Eqi 'PDF|pdf_magic|wkhtmltopdf' "$rule"; then
        printf 'pdf\n'
    elif grep -Eqi 'email|header|PHPMailer|Received:|From:|DKIM|DMARC|SPF' "$rule"; then
        printf 'email\n'
    else
        # Composite/generic rules are tested against the complete corpus.
        printf 'all\n'
    fi
}

pct() {
    local num="$1"
    local den="$2"
    awk -v n="$num" -v d="$den" 'BEGIN {
        if (d == 0) printf "N/A";
        else printf "%.2f%%", (n / d) * 100
    }'
}

recommendation() {
    local tp="$1" tn="$2" fp="$3" fn="$4"
    local positives=$((tp + fn))
    local negatives=$((tn + fp))

    # Conservative deployment policy:
    # DEPLOY  = no observed FP/FN in the controlled relevant test set.
    # TUNE    = any false positive or material false-negative rate.
    # MONITOR = no errors but test set lacks one side of the evaluation.
    if (( fp == 0 && fn == 0 && positives > 0 && negatives > 0 )); then
        printf 'DEPLOY\n'
    elif (( fp > 0 || fn > 0 )); then
        printf 'TUNE\n'
    else
        printf 'MONITOR\n'
    fi
}

explain_fn() {
    local file="$1"
    local family="$2"

    echo "  False negative: $file"
    case "$family" in
        pdf)
            echo "    Why: the sample did not satisfy enough of the rule's PDF/tooling/URL predicates."
            echo "    Tuning: compare strings with the detected variants; add a stable structural signal rather than weakening the rule to one generic string."
            ;;
        email)
            echo "    Why: the variant likely changed or omitted one or more header/infrastructure strings required by the email rule."
            echo "    Tuning: identify the changed header and add alternative stable campaign signals while preserving a multi-signal condition."
            ;;
        *)
            echo "    Why: the malicious sample did not satisfy the current rule condition."
            echo "    Tuning: inspect the missed sample and add stable shared campaign features without relying only on a filename/hash."
            ;;
    esac
}

explain_fp() {
    local file="$1"
    local family="$2"

    echo "  False positive: $file"
    case "$family" in
        pdf)
            echo "    Why: benign PDF content overlapped with strings used by the rule."
            echo "    Tuning: require a stronger conjunction such as tooling + multiple credential-harvesting URL signals."
            ;;
        email)
            echo "    Why: benign email headers/content overlapped with campaign strings."
            echo "    Tuning: combine authentication anomalies, sender/tooling and campaign-specific infrastructure instead of one broad string."
            ;;
        *)
            echo "    Why: the rule condition is broad enough to match benign content."
            echo "    Tuning: increase specificity using independent campaign signals."
            ;;
    esac
}

echo "=== YARA TESTING ==="
echo "Samples: $SAMPLES_DIR"
echo "Manifest: $MANIFEST"
echo

# Compile/check every rule before testing.
for rule in "${RULE_FILES[@]}"; do
    [[ -f "$rule" ]] || die "Rule file not found: $rule"

    # yara itself parses/compiles the rule before scanning.
    # Scan /dev/null to fail early on syntax/compile errors.
    if ! yara "$rule" /dev/null >/dev/null 2>&1; then
        die "YARA compilation failed: $rule"
    fi
    echo "[PASS] Compiles: $rule"
done

echo
echo "=== YARA TESTING SUMMARY ==="

for rule in "${RULE_FILES[@]}"; do
    family="$(rule_family "$rule")"

    tp=0
    tn=0
    fp=0
    fn=0
    tested=0

    false_negatives=()
    false_positives=()

    # Extract rule names for display. Multiple rules per .yar are supported.
    mapfile -t names < <(grep -E '^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)?rule[[:space:]]+[A-Za-z0-9_]+' "$rule" \
        | sed -E 's/^[[:space:]]*(private[[:space:]]+|global[[:space:]]+)?rule[[:space:]]+([A-Za-z0-9_]+).*/\2/')

    display_name="$(IFS=,; echo "${names[*]:-$(basename "$rule")}")"

    while IFS= read -r -d '' sample; do
        base="$(basename "$sample")"
        sample_family="$(family_for_file "$sample")"

        # Rule-specific evaluation avoids counting unrelated malicious formats
        # as false negatives (e.g. an email against a PDF-only rule).
        if [[ "$family" != "all" && "$sample_family" != "$family" ]]; then
            continue
        fi

        expected="$(classify_from_manifest "$sample")"
        if [[ "$expected" == "unknown" ]]; then
            echo "[WARN] Skipping unlabelled sample: $base" >&2
            continue
        fi

        tested=$((tested + 1))

        # Any YARA match in this rule file means "detected".
        if yara "$rule" "$sample" 2>/dev/null | grep -q .; then
            actual="match"
        else
            actual="no_match"
        fi

        if [[ "$expected" == "malicious" && "$actual" == "match" ]]; then
            tp=$((tp + 1))
            result="TP"
        elif [[ "$expected" == "benign" && "$actual" == "no_match" ]]; then
            tn=$((tn + 1))
            result="TN"
        elif [[ "$expected" == "benign" && "$actual" == "match" ]]; then
            fp=$((fp + 1))
            false_positives+=("$sample")
            result="FP"
        else
            fn=$((fn + 1))
            false_negatives+=("$sample")
            result="FN"
        fi

        printf "  %-3s %-28s expected=%-9s actual=%s\n" \
            "$result" "$base" "$expected" "$actual"

    done < <(find "$SAMPLES_DIR" -maxdepth 1 -type f ! -name 'samples_manifest.txt' -print0 | sort -z)

    echo
    echo "Rule file: $(basename "$rule")"
    echo "Rule: $display_name"
    echo "Scope: $family"
    echo "Files evaluated: $tested"
    echo "TP: $tp | TN: $tn | FP: $fp | FN: $fn"
    echo "Detection rate: $(pct "$tp" "$((tp + fn))")"
    echo "False positive rate: $(pct "$fp" "$((fp + tn))")"
    echo "Precision: $(pct "$tp" "$((tp + fp))")"
    echo "Recommendation: $(recommendation "$tp" "$tn" "$fp" "$fn")"

    if ((${#false_negatives[@]} > 0)); then
        echo
        echo "False-negative analysis:"
        for sample in "${false_negatives[@]}"; do
            explain_fn "$(basename "$sample")" "$family"
        done
    fi

    if ((${#false_positives[@]} > 0)); then
        echo
        echo "False-positive analysis:"
        for sample in "${false_positives[@]}"; do
            explain_fp "$(basename "$sample")" "$family"
        done
    fi

    echo
    echo "----------------------------------------"
done

echo
echo "Testing complete."
echo "DEPLOY means zero FP/FN in this controlled relevant corpus only;"
echo "it does not by itself prove production readiness."
