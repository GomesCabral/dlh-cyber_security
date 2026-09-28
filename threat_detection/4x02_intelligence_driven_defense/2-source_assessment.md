# 2 --- Source Credibility Matrix

## Objective

Assess the reliability of the four HEALTHBANE intelligence sources and
the credibility of the information they provide, using a structured
cyber-intelligence adaptation of the Admiralty Code.

------------------------------------------------------------------------

## 1. Assessment Methodology

This assessment uses an adapted **Admiralty Code / NATO source
evaluation system**.

The methodology deliberately evaluates two different questions:

1.  **How reliable is the source?**
2.  **How credible is the specific information being reported?**

A reliable source can still publish an uncertain assessment, and a
less-established source can still provide technically credible
information.

### Source Reliability --- A to F

  -----------------------------------------------------------------------
  Rating                  Meaning                 Cyber-intelligence
                                                  interpretation
  ----------------------- ----------------------- -----------------------
  **A**                   Completely reliable     Highly authoritative
                                                  source with strong
                                                  access, established
                                                  processes and a
                                                  consistent record of
                                                  reliable reporting.

  **B**                   Usually reliable        Generally dependable
                                                  source with good
                                                  expertise or access,
                                                  but not infallible.

  **C**                   Fairly reliable         Useful source, but
                                                  reporting may depend on
                                                  incomplete visibility,
                                                  automated analysis or
                                                  limited validation.

  **D**                   Not usually reliable    Reporting has
                                                  significant reliability
                                                  concerns or a weak
                                                  record.

  **E**                   Unreliable              Source is known to
                                                  provide inaccurate or
                                                  misleading reporting.

  **F**                   Reliability cannot be   Insufficient
                          judged                  information exists to
                                                  assess the source's
                                                  reliability.
  -----------------------------------------------------------------------

### Information Credibility --- 1 to 6

  -----------------------------------------------------------------------
  Rating                  Meaning                 Cyber-intelligence
                                                  interpretation
  ----------------------- ----------------------- -----------------------
  **1**                   Confirmed               Independently
                                                  corroborated or
                                                  directly supported by
                                                  strong technical
                                                  evidence.

  **2**                   Probably true           Consistent with known
                                                  facts and supported by
                                                  credible evidence, but
                                                  not fully confirmed.

  **3**                   Possibly true           Plausible, but
                                                  corroboration or
                                                  evidence is incomplete.

  **4**                   Doubtful                Significant
                                                  uncertainty, weak
                                                  support or
                                                  contradictory evidence
                                                  exists.

  **5**                   Improbable              Available evidence
                                                  suggests the claim is
                                                  unlikely to be correct.

  **6**                   Cannot be judged        There is insufficient
                                                  evidence to assess the
                                                  information.
  -----------------------------------------------------------------------

### Analytical Confidence

This project also uses:

-   **HIGH** --- strong evidence, good source access and/or independent
    corroboration;
-   **MEDIUM** --- credible evidence exists but important uncertainty
    remains;
-   **LOW** --- limited, weakly corroborated or indirect evidence.

**Important:** Admiralty ratings and analytical confidence are related
but are not interchangeable.

------------------------------------------------------------------------

# 2. Individual Source Assessments

## 2.1 HC3 HEALTHBANE Advisory

**Source type:** Government healthcare-sector advisory\
**Campaign designation:** HEALTHBANE\
**Source reliability:** **A --- Completely reliable**\
**Information credibility:** **1 --- Confirmed** for the core campaign
facts and confirmed indicators\
**Overall analytical confidence:** **HIGH**

### Timeliness

The advisory was published shortly after the observed campaign activity
and incorporates reporting from multiple affected healthcare
organizations.

**Assessment: HIGH relevance in time.**

### Relevance to MedDefense

The advisory is directly focused on the healthcare sector and contains
infrastructure, phishing, malware and exfiltration behavior that
overlaps with MedDefense's internal findings.

**Assessment: VERY HIGH relevance.**

### Strengths

-   Healthcare-sector-specific visibility.
-   Information from multiple affected organizations.
-   Corroboration of indicators observed by MedDefense.
-   Separates confirmed activity from analytical assessments.
-   Does not overclaim actor attribution.
-   Describes later campaign stages that MedDefense did not observe
    locally.

### Limitations

HC3 does not have unlimited visibility into every victim or attacker
system. Some campaign infrastructure may remain undiscovered.

The advisory's assessment of attacker motivation is an analytical
judgment rather than a directly observable fact.

### Bias / visibility constraints

HC3 has strong visibility into healthcare-sector reporting but its
perspective is naturally centered on organizations that report incidents
or share indicators.

### SOC judgment

**Prioritize HC3 for confirmed healthcare-sector campaign facts.**

The core technical findings can be used with HIGH confidence, while
actor identity should remain unconfirmed because HC3 explicitly does not
endorse a named actor attribution.

------------------------------------------------------------------------

## 2.2 Acme Commercial CTI Feed

**Source type:** Commercial threat-intelligence feed\
**Campaign designation:** VITALSCORE\
**Source reliability:** **C --- Fairly reliable**\
**Information credibility:** **3 --- Possibly true** overall; individual
high-confidence/corroborated indicators may rate 1--2\
**Overall analytical confidence:** **MEDIUM**, varying significantly by
indicator

### Timeliness

The feed is timely and contains infrastructure associated with the
active campaign period.

**Assessment: HIGH timeliness.**

### Relevance to MedDefense

The feed contains several indicators that overlap with HC3 and
MedDefense evidence, making part of it directly relevant.

However, it also contains infrastructure with weak or automated
associations.

**Assessment: HIGH relevance but variable precision.**

### Strengths

-   Broad indicator coverage.
-   Provides additional infrastructure for investigation.
-   Contains indicators corroborated by stronger sources.
-   Useful for enrichment and discovery of possible relationships.

### Limitations

The feed explicitly includes:

-   automated clustering;
-   weak ML similarity;
-   healthcare-keyword similarity;
-   shared hosting;
-   CDN/cloud infrastructure;
-   indicators that were not human-reviewed;
-   possible unrelated infrastructure.

The commercial label `VITALSCORE` is proprietary and does not prove a
unique threat-actor identity.

### Bias / visibility constraints

Commercial providers are incentivized to provide broad coverage. Their
telemetry and clustering can reveal relationships that other sources
miss, but broad automated collection can also increase false positives.

The feed has wider infrastructure visibility than MedDefense but weaker
contextual certainty for some indicators.

### SOC judgment

**Use the feed for enrichment and discovery, not as an automatic
blocklist.**

Each indicator must be independently triaged. Shared Microsoft, Azure,
Cloudflare, CDN and multi-tenant hosting infrastructure must not be
treated as attacker-specific solely because it appears in the feed.

------------------------------------------------------------------------

## 2.3 Researcher Technical Analysis

**Source type:** Open-source technical research\
**Campaign / actor label:** HEALTHBANE with proposed overlap to
APT-MEDAGENT\
**Source reliability:** **B --- Usually reliable**\
**Information credibility:** **2 --- Probably true** for technical
findings; **3 --- Possibly true** for APT-MEDAGENT attribution\
**Overall analytical confidence:** **MEDIUM**

### Timeliness

The analysis was published during the same general campaign period and
is therefore operationally timely.

**Assessment: HIGH timeliness.**

### Relevance to MedDefense

The researcher provides technical details that overlap with HC3 and
MedDefense findings and adds details about attacker tooling, kit
structure and infrastructure relationships.

**Assessment: HIGH relevance.**

### Strengths

-   Detailed technical analysis.
-   Provides additional malware/phishing-kit context.
-   Several indicators overlap with HC3 and commercial reporting.
-   Explicitly communicates uncertainty around attribution.
-   Useful for understanding attacker implementation and behavior.

### Limitations

The researcher is a solo analyst and does not have the victim telemetry
available to HC3 or MedDefense.

The proposed `APT-MEDAGENT` relationship is based primarily on tooling
and infrastructure overlap.

Infrastructure and tooling can be:

-   reused;
-   shared;
-   purchased;
-   copied;
-   or supplied by third parties.

Therefore, overlap does not establish actor identity.

### Bias / visibility constraints

Open-source researchers see the evidence they can independently collect
or obtain. They may have excellent technical visibility into malware or
infrastructure while lacking incident-response telemetry from affected
organizations.

### SOC judgment

**Use the researcher primarily for technical enrichment and behavioral
understanding.**

The APT-MEDAGENT attribution should remain an analytical hypothesis with
**MEDIUM confidence**, not a confirmed fact.

------------------------------------------------------------------------

## 2.4 MedDefense 4x00 Internal Findings

**Source type:** Internal incident investigation\
**Attribution:** None\
**Source reliability:** **A --- Completely reliable** for directly
observed MedDefense evidence\
**Information credibility:** **1 --- Confirmed** for local observations\
**Overall analytical confidence:** **HIGH** within its scope

### Timeliness

The findings were produced directly from the MedDefense phishing
investigation close to the time of the incident.

**Assessment: VERY HIGH timeliness.**

### Relevance to MedDefense

This is the most directly relevant source because it describes activity
observed in MedDefense's own environment.

**Assessment: MAXIMUM relevance.**

### Strengths

-   Direct internal evidence.
-   Known affected user and campaign context.
-   Observed phishing domains, URLs and sender addresses.
-   Evidence was collected as part of an incident investigation.
-   Avoids unsupported actor attribution.

### Limitations

The investigation only represents what happened at MedDefense.

MedDefense stopped the campaign early and therefore did not directly
observe the later malware-delivery and data-exfiltration stages reported
by other victims.

The report cannot independently establish the full campaign scope.

### Bias / visibility constraints

Internal telemetry provides excellent depth but limited breadth.

MedDefense knows its own environment well but does not have direct
visibility into other victims or all external attacker infrastructure.

### SOC judgment

**Prioritize MedDefense evidence when determining what definitely
occurred inside MedDefense.**

Do not extrapolate local observations into claims about the entire
campaign without external corroboration.

------------------------------------------------------------------------

# 3. Source Comparison Matrix

  ---------------------------------------------------------------------------------------
  Criterion         HC3 Advisory   Commercial Feed        Researcher Blog MedDefense 4x00
  ----------------- -------------- ---------------------- --------------- ---------------
  **Source type**   Government     Commercial CTI         Open-source     Internal
                    advisory                              research        investigation

  **Reliability**   **A**          **C**                  **B**           **A**

  **Core            **1**          **3** overall          **2** technical **1** local
  information                                             / **3**         evidence
  credibility**                                           attribution     

  **Confidence**    **HIGH**       **MEDIUM / variable**  **MEDIUM**      **HIGH**

  **Timeliness**    High           High                   High            Very high

  **MedDefense      Very high      High but variable      High            Maximum
  relevance**                                                             

  **Best use**      Confirmed      Enrichment/discovery   Technical       Confirmed local
                    sector facts                          details         facts

  **Main weakness** Incomplete     Noise and weak         Limited victim  Narrow local
                    global         clustering             telemetry       scope
                    visibility                                            

  **Attribution     Unconfirmed    VITALSCORE label       APT-MEDAGENT,   No attribution
  position**                                              MEDIUM          
                                                          confidence      
  ---------------------------------------------------------------------------------------

------------------------------------------------------------------------

# 4. Attribution Conflict

The sources use different labels, but these labels do **not** provide
sufficient evidence to conclude that they represent the same named
threat actor.

## Confirmed facts

-   HC3 tracks the coordinated campaign as **HEALTHBANE**.
-   The commercial provider groups related activity under its
    proprietary label **VITALSCORE**.
-   The researcher proposes overlap with **APT-MEDAGENT**.
-   MedDefense's internal investigation intentionally makes no actor
    attribution.

## Assessment

### HEALTHBANE

**HIGH confidence:** HEALTHBANE is the most appropriate campaign
designation for this project because it is used by the authoritative
healthcare-sector source and describes the activity without asserting an
unsupported actor identity.

### VITALSCORE

**HIGH confidence:** VITALSCORE should be treated as a **commercial
clustering label**, not as proof of a specific threat actor.

A vendor can group related infrastructure or activity under an internal
name even when the real-world operator is unknown.

### APT-MEDAGENT

**MEDIUM confidence:** The researcher's proposed overlap is analytically
interesting but insufficient for confirmed attribution.

Shared tooling and infrastructure can support an attribution hypothesis,
but they are not independently conclusive.

### Recommended attribution statement

> **MedDefense assesses with HIGH confidence that the observed activity
> is associated with the HEALTHBANE campaign. Attribution to a specific
> named threat actor remains UNCONFIRMED. Commercial reporting tracks
> related activity as VITALSCORE, while an independent researcher
> assesses possible overlap with APT-MEDAGENT at MEDIUM confidence.
> Available evidence is insufficient to treat these labels as confirmed
> aliases of the same actor.**

------------------------------------------------------------------------

# 5. Weighting Recommendation

## Priority 1 --- MedDefense internal evidence

Use MedDefense 4x00 as the primary authority for:

-   what occurred inside MedDefense;
-   which users/systems were involved;
-   which phishing infrastructure was directly observed;
-   which actions were confirmed locally.

**Weight: VERY HIGH for local facts.**

------------------------------------------------------------------------

## Priority 2 --- HC3

Use HC3 as the primary external authority for:

-   confirmed healthcare-sector campaign facts;
-   cross-victim infrastructure;
-   campaign stages;
-   confirmed healthcare targeting;
-   later-stage activity not observed at MedDefense.

**Weight: VERY HIGH for sector-level intelligence.**

------------------------------------------------------------------------

## Priority 3 --- Researcher

Use the researcher for:

-   technical implementation details;
-   phishing-kit analysis;
-   malware/infrastructure relationships;
-   behavioral hypotheses;
-   leads for additional hunting.

**Weight: MEDIUM-HIGH for technical enrichment.**

Treat actor attribution separately at **MEDIUM confidence**.

------------------------------------------------------------------------

## Priority 4 --- Commercial feed

Use the commercial feed for:

-   enrichment;
-   pivoting;
-   discovery of possible related infrastructure;
-   generating investigation leads.

Do **not** automatically operationalize every feed indicator.

**Weight: MEDIUM and indicator-dependent.**

Weak ML clustering, shared cloud/CDN infrastructure and unreviewed
indicators require additional corroboration.

------------------------------------------------------------------------

# 6. Handling Conflicting Claims

When sources disagree, MedDefense should not resolve the conflict by
simply choosing the source with the strongest reputation.

The analyst should:

1.  separate directly observed facts from assessments;
2.  preserve the original source and its confidence;
3.  look for independent corroboration;
4.  consider the source's access and visibility;
5.  determine whether the claim concerns technical activity or actor
    attribution;
6.  downgrade claims supported only by weak clustering or indirect
    overlap;
7.  explicitly document unresolved uncertainty.

For HEALTHBANE, technical campaign activity has substantially stronger
evidence than named actor attribution.

Therefore:

``` text
Campaign: HEALTHBANE
Campaign confidence: HIGH

VITALSCORE relationship:
Commercial clustering label
Confidence as actor identity: LOW / NOT ESTABLISHED

APT-MEDAGENT relationship:
Possible overlap
Confidence: MEDIUM

Named threat actor:
UNCONFIRMED
```

------------------------------------------------------------------------

# SOC Takeaway

A source credibility matrix prevents an analyst from treating all threat
intelligence equally.

The practical model is:

``` text
Source reports something
        ↓
How reliable is the source?
        ↓
How did the source obtain the information?
        ↓
Is the specific claim corroborated?
        ↓
What visibility or bias limitations exist?
        ↓
Fact or assessment?
        ↓
Assign confidence
        ↓
Decide how much operational weight to give it
```

The most important conclusion in this case is that **technical evidence
and actor attribution require different evidentiary thresholds**.

MedDefense can have **HIGH confidence** that HEALTHBANE activity
occurred without claiming HIGH confidence about who operated the
campaign.
