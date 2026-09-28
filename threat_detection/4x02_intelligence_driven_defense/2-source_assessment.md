# 2 — Source Credibility Matrix

## Objective

Assess the reliability and credibility of the four intelligence sources related to the HEALTHBANE campaign using an adapted Admiralty Code methodology.

The four required sources assessed in this document are:

- `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`
- `commercial_feed_extract.json`
- `researcher_blog_analysis.txt`
- `meddefense_4x00_findings.txt`

---

## 1. Assessment Methodology

This assessment uses the **Admiralty Code**, also known as the NATO intelligence evaluation system, adapted for cyber threat intelligence.

The methodology evaluates two separate dimensions:

1. **Source Reliability (A–F)** — how trustworthy and reliable the source itself is.
2. **Information Credibility (1–6)** — how credible the specific information reported by that source is.

A reliable source can still publish an uncertain assessment. Likewise, a less-established source may provide technically accurate information.

### Source Reliability — A to F

| Rating | Meaning |
|---|---|
| **A** | Completely reliable |
| **B** | Usually reliable |
| **C** | Fairly reliable |
| **D** | Not usually reliable |
| **E** | Unreliable |
| **F** | Reliability cannot be judged |

### Information Credibility — 1 to 6

| Rating | Meaning |
|---|---|
| **1** | Confirmed by other sources or direct evidence |
| **2** | Probably true |
| **3** | Possibly true |
| **4** | Doubtful |
| **5** | Improbable |
| **6** | Cannot be judged |

### Confidence Levels

This project also uses the following analytical confidence levels:

- **HIGH** — strong evidence and/or independent corroboration.
- **MEDIUM** — credible evidence exists, but important uncertainty remains.
- **LOW** — limited, indirect or weakly corroborated evidence.

The Admiralty rating and analytical confidence are related but should not be treated as identical measurements.

---

# 2. Source Assessments

## 2.1 HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt

**Source name:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`

**Source type:** Government advisory

**Source reliability:** **A — Completely reliable**

**Information credibility:** **1 — Confirmed** for the core campaign facts and confirmed indicators.

**Overall confidence:** **HIGH**

### Timeliness

The HC3 advisory was published shortly after the observed campaign activity and contains information collected from multiple affected healthcare organizations.

**Assessment:** HIGH timeliness.

### Relevance to MedDefense

The source is highly relevant because it specifically covers attacks against healthcare organizations and contains indicators and behaviors that overlap with MedDefense's own investigation.

**Assessment:** VERY HIGH relevance.

### Strengths

- Healthcare-sector-specific intelligence.
- Information from multiple affected organizations.
- Indicators corroborated by MedDefense.
- Describes multiple stages of the HEALTHBANE campaign.
- Separates confirmed observations from analytical assessments.
- Does not claim confirmed threat-actor attribution.

### Limitations

HC3 does not have complete visibility into every affected organization or every system controlled by the attacker.

Some attacker infrastructure may therefore remain unidentified.

Its assessment of attacker motivation is an analytical judgment rather than a directly observed technical fact.

### Bias or visibility constraints

HC3 has strong visibility into healthcare-sector incidents but depends partly on reporting and information sharing from affected organizations.

Organizations that did not report incidents may not be represented.

### SOC Assessment

`HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` should be prioritized for **confirmed healthcare-sector campaign facts**.

**Confidence: HIGH**

---

## 2.2 commercial_feed_extract.json

**Source name:** `commercial_feed_extract.json`

**Source type:** Commercial threat intelligence feed

**Source reliability:** **C — Fairly reliable**

**Information credibility:** **3 — Possibly true overall**

Individual corroborated indicators may reach credibility levels **1 or 2**.

**Overall confidence:** **MEDIUM / variable by indicator**

### Timeliness

The feed was produced during the active HEALTHBANE campaign period.

**Assessment:** HIGH timeliness.

### Relevance to MedDefense

`commercial_feed_extract.json` contains several indicators that overlap with HC3 and MedDefense evidence.

However, it also contains indicators derived from automated clustering and infrastructure relationships that may not actually belong to the campaign.

**Assessment:** HIGH relevance but variable precision.

### Strengths

- Broad IOC coverage.
- Contains several indicators corroborated by stronger sources.
- Provides additional infrastructure for investigation.
- Useful for IOC enrichment.
- Useful for identifying possible infrastructure relationships.
- Useful for generating threat-hunting leads.

### Limitations

The source explicitly contains:

- automated clustering;
- ML similarity;
- keyword-based clustering;
- indicators without human review;
- shared hosting infrastructure;
- CDN infrastructure;
- cloud-provider infrastructure;
- potentially unrelated indicators.

Some indicators therefore have a significant false-positive risk.

### Bias or visibility constraints

Commercial intelligence providers often collect large volumes of data.

This provides broad visibility but can also introduce noise when automated clustering associates unrelated infrastructure with a campaign.

The feed therefore has greater breadth than MedDefense's internal investigation but lower certainty for some indicators.

### VITALSCORE

`commercial_feed_extract.json` uses the proprietary label:

`VITALSCORE`

This should be treated as a **commercial campaign or clustering label**, not as confirmed identification of a threat actor.

### SOC Assessment

Use `commercial_feed_extract.json` primarily for:

- enrichment;
- pivoting;
- infrastructure discovery;
- threat hunting.

Do **not** automatically use the entire feed as a firewall or proxy blocklist.

Indicators must first be individually validated.

**Confidence: MEDIUM / indicator-dependent**

---

## 2.3 researcher_blog_analysis.txt

**Source name:** `researcher_blog_analysis.txt`

**Source type:** Open-source research

**Source reliability:** **B — Usually reliable**

**Information credibility:** **2 — Probably true** for technical findings.

The APT-MEDAGENT attribution is assessed separately as:

**3 — Possibly true**

**Overall confidence:** **MEDIUM**

### Timeliness

The analysis was published during the same general campaign period.

**Assessment:** HIGH timeliness.

### Relevance to MedDefense

`researcher_blog_analysis.txt` contains technical information that overlaps with HC3 and MedDefense findings.

It also provides additional information about:

- phishing infrastructure;
- attacker tooling;
- phishing-kit structure;
- malware;
- C2 infrastructure.

**Assessment:** HIGH relevance.

### Strengths

- Detailed technical analysis.
- Additional attacker tooling information.
- Additional infrastructure relationships.
- Several indicators overlap with HC3 reporting.
- Clearly communicates uncertainty regarding attribution.

### Limitations

The researcher is a solo analyst and does not have the same victim telemetry available to HC3 or MedDefense.

The proposed relationship with `APT-MEDAGENT` is primarily based on:

- tooling overlap;
- infrastructure overlap.

These characteristics alone are insufficient to prove actor identity.

Infrastructure and tooling can be:

- reused;
- purchased;
- shared;
- copied;
- provided by third parties.

### Bias or visibility constraints

An independent researcher can have excellent technical visibility into malware or infrastructure while having limited visibility into affected organizations.

This means the technical analysis can be useful even when attribution remains uncertain.

### APT-MEDAGENT Attribution

The researcher proposes a connection between HEALTHBANE and:

`APT-MEDAGENT`

The researcher assigns only **MEDIUM confidence** to this assessment.

MedDefense should therefore treat this as an **attribution hypothesis**, not a confirmed fact.

### SOC Assessment

Use `researcher_blog_analysis.txt` primarily for:

- technical enrichment;
- infrastructure relationships;
- malware analysis context;
- threat-hunting hypotheses.

Treat the APT-MEDAGENT attribution separately and maintain **MEDIUM confidence**.

---

## 2.4 meddefense_4x00_findings.txt

**Source name:** `meddefense_4x00_findings.txt`

**Source type:** Internal investigation

**Source reliability:** **A — Completely reliable** for directly observed MedDefense evidence.

**Information credibility:** **1 — Confirmed** for local observations.

**Overall confidence:** **HIGH**

### Timeliness

`meddefense_4x00_findings.txt` was produced directly from the MedDefense phishing investigation close to the time of the incident.

**Assessment:** VERY HIGH timeliness.

### Relevance to MedDefense

This source has the highest direct relevance because it contains evidence collected from MedDefense's own environment.

**Assessment:** MAXIMUM relevance.

### Strengths

- Direct internal evidence.
- Known campaign context.
- Known affected user.
- Observed phishing domains.
- Observed phishing URLs.
- Observed sender addresses.
- Evidence collected during an actual internal investigation.
- Avoids unsupported threat-actor attribution.

### Limitations

The investigation only represents activity observed at MedDefense.

MedDefense stopped the attack during the early phishing stage.

Therefore, the internal investigation did not directly observe the later:

- malware-delivery stage;
- C2 activity;
- persistence;
- data-exfiltration stage.

The source cannot independently describe the entire HEALTHBANE campaign.

### Bias or visibility constraints

Internal telemetry provides strong depth but limited breadth.

MedDefense has excellent visibility into its own environment but limited visibility into attacks against other healthcare organizations.

### Attribution

`meddefense_4x00_findings.txt` intentionally avoids threat-actor attribution.

This is analytically appropriate because the available internal evidence was insufficient to identify the operator.

### SOC Assessment

Prioritize `meddefense_4x00_findings.txt` when determining **what definitely occurred inside MedDefense**.

Do not automatically extrapolate internal findings to the entire campaign without external corroboration.

**Confidence: HIGH**

---

# 3. Source Comparison Matrix

| Criterion | `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` | `commercial_feed_extract.json` | `researcher_blog_analysis.txt` | `meddefense_4x00_findings.txt` |
|---|---|---|---|---|
| Source type | Government advisory | Commercial CTI feed | Open-source research | Internal investigation |
| Reliability | **A** | **C** | **B** | **A** |
| Information credibility | **1** core facts | **3** overall | **2** technical / **3** attribution | **1** local evidence |
| Confidence | **HIGH** | **MEDIUM / variable** | **MEDIUM** | **HIGH** |
| Timeliness | High | High | High | Very high |
| MedDefense relevance | Very high | High but variable | High | Maximum |
| Best use | Confirmed sector facts | Enrichment and discovery | Technical details | Confirmed local facts |
| Main limitation | Incomplete global visibility | Noise and weak clustering | Limited victim telemetry | Narrow local scope |
| Attribution | Unconfirmed | VITALSCORE | APT-MEDAGENT, MEDIUM confidence | No attribution |

---

# 4. Attribution Conflict

The four required sources do not use the same attribution terminology.

This conflict must be preserved rather than artificially resolved.

## HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt

HC3 uses:

`HEALTHBANE`

as the campaign designation.

HC3 does **not** confirm attribution to a named threat actor and does not endorse the commercial `VITALSCORE` label as an actor identity.

**Assessment: HIGH confidence**

HEALTHBANE should be used as the campaign name.

---

## commercial_feed_extract.json

The commercial feed uses:

`VITALSCORE`

This is a proprietary commercial label.

A commercial provider may group infrastructure and related activity under an internal label without knowing the real-world identity of the operator.

**Assessment: HIGH confidence**

`VITALSCORE` should **not** be treated as confirmed threat-actor attribution.

---

## researcher_blog_analysis.txt

The researcher proposes overlap with:

`APT-MEDAGENT`

The researcher explicitly describes the attribution as **MEDIUM confidence**.

The relationship is based primarily on tooling and infrastructure overlap.

**Assessment: MEDIUM confidence**

The relationship is plausible but not confirmed.

---

## meddefense_4x00_findings.txt

The internal MedDefense investigation makes **no threat-actor attribution**.

This is appropriate because the internal evidence does not establish who operated the campaign.

**Assessment: HIGH confidence**

---

# 5. Attribution Recommendation

The recommended intelligence position is:

```text
Campaign:
HEALTHBANE

Campaign confidence:
HIGH

VITALSCORE:
Commercial proprietary cluster label

VITALSCORE as confirmed actor identity:
NOT ESTABLISHED

APT-MEDAGENT:
Possible overlap

APT-MEDAGENT attribution confidence:
MEDIUM

Named threat actor:
UNCONFIRMED
```

MedDefense should therefore refer to the activity as the **HEALTHBANE campaign** without claiming that VITALSCORE or APT-MEDAGENT is definitively responsible.

---

# 6. Weighting Recommendation

## Priority 1 — meddefense_4x00_findings.txt

Use `meddefense_4x00_findings.txt` as the primary authority for determining:

- what occurred inside MedDefense;
- which users were affected;
- which phishing infrastructure was directly observed;
- which actions were confirmed locally.

**Weight: VERY HIGH for MedDefense-specific facts**

---

## Priority 2 — HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt

Use `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` as the primary external source for:

- confirmed healthcare-sector facts;
- cross-victim campaign activity;
- confirmed campaign infrastructure;
- campaign stages;
- later-stage activity not observed internally.

**Weight: VERY HIGH for healthcare-sector intelligence**

---

## Priority 3 — researcher_blog_analysis.txt

Use `researcher_blog_analysis.txt` for:

- technical details;
- phishing-kit analysis;
- malware information;
- infrastructure relationships;
- behavioral analysis;
- threat-hunting leads.

**Weight: MEDIUM-HIGH for technical enrichment**

The `APT-MEDAGENT` attribution must remain **MEDIUM confidence**.

---

## Priority 4 — commercial_feed_extract.json

Use `commercial_feed_extract.json` primarily for:

- enrichment;
- pivoting;
- discovering possible related infrastructure;
- generating investigation leads.

**Weight: MEDIUM and indicator-dependent**

Indicators based only on:

- weak ML similarity;
- keyword similarity;
- shared hosting;
- cloud infrastructure;
- CDN infrastructure;

must receive additional validation before operational use.

---

# 7. Handling Conflicting Claims

When intelligence sources disagree, the analyst should not automatically choose one source and discard the others.

The analyst should:

1. Separate directly observed facts from analytical assessments.
2. Preserve the original source.
3. Preserve the original confidence level.
4. Search for independent corroboration.
5. Consider the source's visibility and access.
6. Distinguish technical evidence from attribution claims.
7. Downgrade claims based only on weak clustering or indirect relationships.
8. Clearly document unresolved uncertainty.

For HEALTHBANE, the evidence supporting the **technical campaign activity** is significantly stronger than the evidence supporting **named threat-actor attribution**.

---

# 8. Final Assessment

**HIGH confidence:** MedDefense was targeted by activity associated with the HEALTHBANE campaign.

**HIGH confidence:** `HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt` and `meddefense_4x00_findings.txt` provide the strongest evidence for confirmed sector-level and local facts respectively.

**MEDIUM confidence:** `researcher_blog_analysis.txt` provides useful technical enrichment, but its `APT-MEDAGENT` attribution remains an analytical hypothesis.

**MEDIUM / variable confidence:** `commercial_feed_extract.json` is useful for enrichment and discovery but contains acknowledged noise, weak clustering and shared infrastructure.

**HIGH confidence:** Current evidence does not justify confirmed attribution to a named threat actor.

The appropriate intelligence position remains:

**Campaign: HEALTHBANE**  
**Threat actor attribution: UNCONFIRMED**