#!/bin/bash

# Task 13 - Hunt-Derived Detection Rules
# HEALTHBANE Stage 4
#
# Produces local detection-rule drafts only.
# No live SIEM deployment is performed.

set -euo pipefail

OUTPUT_DIR="detection_rules"

mkdir -p "$OUTPUT_DIR"

WAZUH_FILE="$OUTPUT_DIR/wazuh_hunt_rules.xml"
NETWORK_FILE="$OUTPUT_DIR/network_hunt_rules.rules"
DOC_FILE="$OUTPUT_DIR/detection_rule_notes.md"

# ============================================================
# WAZUH-STYLE RULE DRAFTS
# ============================================================

cat > "$WAZUH_FILE" <<'EOF'
<!--
  HEALTHBANE Stage 4
  Hunt-derived Wazuh-style detection rule drafts.

  These are local drafts and must be validated/tuned before deployment.
-->

<group name="healthbane,threat_hunting,">

  <!-- ===================================================== -->
  <!-- Rule 100100 - PsExec from unexpected source           -->
  <!-- ===================================================== -->

  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>

    <field name="win.eventdata.image"
           type="pcre2">(?i)psexec(64)?\.exe$</field>

    <field name="agent.name"
           type="pcre2">^(?!WS-ADMIN-01$).+</field>

    <description>
      HEALTHBANE: PsExec execution from non-admin workstation
    </description>

    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>


  <!-- ===================================================== -->
  <!-- Rule 100101 - Suspicious LSASS memory access          -->
  <!-- ===================================================== -->

  <rule id="100101" level="14">
    <if_group>sysmon_event_10</if_group>

    <field name="win.eventdata.targetImage"
           type="pcre2">(?i)\\lsass\.exe$</field>

    <field name="win.eventdata.grantedAccess"
           type="pcre2">(?i)^0x(0010|1010)$</field>

    <field name="win.eventdata.sourceImage"
           type="pcre2">(?i)\\(Temp|Public|ProgramData)\\</field>

    <description>
      HEALTHBANE: Suspicious process accessing LSASS memory
    </description>

    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>


  <!-- ===================================================== -->
  <!-- Rule 100102 - Service account from workstation        -->
  <!-- ===================================================== -->

  <rule id="100102" level="14">
    <if_sid>60106</if_sid>

    <field name="win.eventdata.targetUserName"
           type="pcre2">(?i)^svc_</field>

    <field name="win.eventdata.workstationName"
           type="pcre2">(?i)^WS-</field>

    <description>
      HEALTHBANE: Service account authentication from workstation
    </description>

    <mitre>
      <id>T1078.002</id>
    </mitre>
  </rule>


  <!-- ===================================================== -->
  <!-- Rule 100103 - WMI child process anomaly               -->
  <!-- ===================================================== -->

  <rule id="100103" level="12">
    <if_group>sysmon_event1</if_group>

    <field name="win.eventdata.parentImage"
           type="pcre2">(?i)\\WmiPrvSE\.exe$</field>

    <field name="win.eventdata.image"
           type="pcre2">(?i)\\(cmd|powershell)\.exe$</field>

    <description>
      HEALTHBANE: WMI provider spawned command shell
    </description>

    <mitre>
      <id>T1047</id>
    </mitre>
  </rule>


  <!-- ===================================================== -->
  <!-- Rule 100104 - Service account NTLM network logon      -->
  <!-- ===================================================== -->

  <rule id="100104" level="13">
    <if_sid>60106</if_sid>

    <field name="win.eventdata.targetUserName"
           type="pcre2">(?i)^svc_</field>

    <field name="win.eventdata.logonType">3</field>

    <field name="win.eventdata.authenticationPackageName"
           type="pcre2">(?i)^NTLM$</field>

    <field name="win.eventdata.workstationName"
           type="pcre2">(?i)^WS-</field>

    <description>
      HEALTHBANE: Service account NTLM network logon from workstation
    </description>

    <mitre>
      <id>T1078.002</id>
    </mitre>
  </rule>


  <!-- ===================================================== -->
  <!-- Rule 100105 - PowerShell Remoting from workstation    -->
  <!-- ===================================================== -->

  <rule id="100105" level="12">
    <if_group>sysmon_event1</if_group>

    <field name="win.eventdata.commandLine"
           type="pcre2">(?i)(Enter-PSSession|New-PSSession|Invoke-Command|Copy-Item.+-ToSession)</field>

    <field name="agent.name"
           type="pcre2">^(?!WS-ADMIN-01$).+</field>

    <description>
      HEALTHBANE: PowerShell Remoting from non-admin workstation
    </description>

    <mitre>
      <id>T1021.006</id>
    </mitre>
  </rule>

</group>
EOF


# ============================================================
# NETWORK-LEVEL RULE DRAFT
# ============================================================

cat > "$NETWORK_FILE" <<'EOF'
# HEALTHBANE Stage 4
# Network-level draft
#
# Conceptual Suricata-style detection.
# Validate syntax and tune HOME_NET before deployment.

alert tcp $HOME_NET any -> $HOME_NET 445 (
    msg:"HEALTHBANE Possible PsExec SMB Lateral Movement";
    flow:established,to_server;
    content:"PSEXESVC";
    nocase;
    classtype:trojan-activity;
    sid:9000030;
    rev:1;
)
EOF


# ============================================================
# DOCUMENTATION
# ============================================================

cat > "$DOC_FILE" <<'EOF'
# HEALTHBANE Stage 4 - Hunt-Derived Detection Rules

These rules were created from findings identified during the 4x04
threat-hunting project.

They are detection drafts only and must be validated and tuned before
production deployment.

---

## Rule 100100 - PsExec from Non-Admin Workstation

**Technique:** T1021.002 - SMB/Windows Admin Shares

**Behavior detected:**  
PsExec execution from a workstation other than WS-ADMIN-01.

**Hunt evidence:**  
Task 4 identified PsExec originating from WS-RECV-03 using
svc_healthsync against server infrastructure.

**Expected false-positive rate:** VERY LOW

**Baseline comparison:**  
Robert Kim's legitimate PsExec activity originates from WS-ADMIN-01
during approved maintenance windows.

**Detection logic:**  
PsExec + source != WS-ADMIN-01.

**Production improvement:**  
Add approved maintenance-window logic and target allowlisting.

---

## Rule 100101 - LSASS Memory Access from Suspicious Process

**Technique:** T1003.001 - LSASS Memory

**Behavior detected:**  
Process from Temp/Public/ProgramData accessing lsass.exe with a
memory-read access mask.

**Hunt evidence:**  
Task 6 identified debug_tool.exe accessing lsass.exe with GrantedAccess
0x1010.

**Expected false-positive rate:** LOW

**Baseline comparison:**  
Known legitimate Windows and security processes should be allowlisted.

**Detection logic:**  
TargetImage = lsass.exe  
AND GrantedAccess = 0x0010 or 0x1010  
AND SourceImage originates from a suspicious writable directory.

---

## Rule 100102 - Service Account from Workstation

**Technique:** T1078.002 - Domain Accounts

**Behavior detected:**  
A service account authenticating from a workstation endpoint.

**Hunt evidence:**  
Task 9 identified svc_healthsync authentication originating from
WS-RECV-03.

**Expected false-positive rate:** VERY LOW

**Baseline comparison:**  
Service accounts must follow reference/service_accounts.txt.
Workstation-originated service-account authentication is unauthorized.

**Detection logic:**  
TargetUserName = svc_*  
AND WorkstationName = WS-*

---

## Rule 100103 - WMI Child Process Anomaly

**Technique:** T1047 - Windows Management Instrumentation

**Behavior detected:**  
WmiPrvSE.exe spawning cmd.exe or powershell.exe.

**Hunt evidence:**  
The WMI hunt identified remote execution behavior associated with the
Stage 4 lateral-movement chain.

**Expected false-positive rate:** MEDIUM

**Baseline comparison:**  
Robert Kim has legitimate WMI activity. Context must therefore include
source workstation, user, time and target.

**Detection logic:**  
ParentImage = WmiPrvSE.exe  
AND Image = cmd.exe or powershell.exe.

**Production improvement:**  
Reduce severity when activity matches Robert Kim's documented baseline.

---

## Rule 100104 - Service Account NTLM Network Logon

**Techniques:** T1078.002 / T1550.002 investigation support

**Behavior detected:**  
Service account performing an NTLM Type 3 network logon from a
workstation.

**Hunt evidence:**  
svc_healthsync generated Type 3 NTLM authentication from WS-RECV-03
during lateral movement.

**Expected false-positive rate:** VERY LOW

**Baseline comparison:**  
The service-account authorization matrix expects documented service
hosts and Kerberos. NTLM from workstation endpoints is anomalous.

**Detection logic:**  
TargetUserName = svc_*  
AND LogonType = 3  
AND AuthenticationPackageName = NTLM  
AND WorkstationName = WS-*

**Important:**  
NTLM alone does not prove Pass-the-Hash. This rule should trigger
investigation and correlation with remote-administration activity.

---

## Rule 100105 - PowerShell Remoting from Non-Admin Workstation

**Technique:** T1021.006 - Windows Remote Management

**Behavior detected:**  
PowerShell Remoting commands initiated from a workstation other than
WS-ADMIN-01.

**Hunt evidence:**  
The hunt identified Enter-PSSession activity from WS-RECV-03 using
svc_healthsync against server infrastructure.

**Expected false-positive rate:** LOW

**Baseline comparison:**  
Authorized administrative PowerShell Remoting is expected from
WS-ADMIN-01 during documented maintenance periods.

**Detection logic:**  
Enter-PSSession / New-PSSession / Invoke-Command / Copy-Item -ToSession  
AND source != WS-ADMIN-01.

---

## Network Rule 9000030 - Possible PsExec SMB Lateral Movement

**Technique:** T1021.002

**Behavior detected:**  
PSEXESVC-related SMB traffic over TCP/445.

**Hunt evidence:**  
PsExec lateral movement was identified from WS-RECV-03 to critical
server infrastructure.

**Expected false-positive rate:** LOW

**Baseline comparison:**  
SMB/PsExec from the authorized administration workstation may be
legitimate. Traffic from ordinary workstation VLANs should receive
higher severity.

**Production improvement:**  
Correlate TCP/445 activity with endpoint process creation and service
installation telemetry.

---

# Detection Posture Update

## Before the Hunt

The post-4x03 ATT&CK mapping documented:

- 29 techniques tracked
- 16 OBSERVED
- 3 INFERRED
- 10 NOT COVERED
- 55% observed coverage
- 66% mapped coverage

Stage 4 gaps included:

- T1021.002 - SMB/Windows Admin Shares
- T1021.006 - Windows Remote Management
- T1047 - WMI
- T1003.001 - LSASS Memory
- T1078.002 - Domain Accounts
- T1550.002 - Pass the Hash

The required telemetry was largely available, but behavioral detection
and correlation logic was missing.

## After the Hunt

Hunt-derived detection drafts now provide coverage logic for:

- T1021.002 - PsExec / SMB lateral movement
- T1003.001 - LSASS credential access
- T1047 - WMI remote execution
- T1021.006 - PowerShell Remoting
- T1078.002 - Service account misuse
- T1550.002 - NTLM / Pass-the-Hash-style investigation

The hunt therefore converted previously uncovered Stage 4 behaviors
into detection candidates.

These techniques should not be marked fully OBSERVED in production
until the rules are validated, tested and deployed.

---

# Threat Hunting Cycle

Threat Intelligence
        |
        v
      Hunt
        |
        v
    Findings
        |
        v
 Detection Gaps
        |
        v
 Detection Rules
        |
        v
 Validation / Tuning
        |
        v
      Deploy
        |
        v
    Hunt Again
EOF


# ============================================================
# CONSOLE OUTPUT
# ============================================================

echo "================================================================"
echo "   DETECTION ENGINEERING - Hunt-Derived Rules"
echo "================================================================"

echo
echo "=== WAZUH-STYLE RULE DRAFTS ==="

echo
echo "[Rule 100100] PsExec from Non-Admin Workstation"
echo "  Behavior: PsExec execution from non-admin workstation"
echo "  Evidence: Hunt Task 4"
echo "  FP Rate: VERY LOW"
echo "  ATT&CK: T1021.002"

echo
echo "[Rule 100101] LSASS Memory Access from Non-System Process"
echo "  Behavior: Suspicious LSASS memory access"
echo "  Evidence: Hunt Task 6"
echo "  FP Rate: LOW"
echo "  ATT&CK: T1003.001"

echo
echo "[Rule 100102] Service Account Authentication from Workstation"
echo "  Behavior: Service account used from workstation"
echo "  Evidence: Hunt Task 9"
echo "  FP Rate: VERY LOW"
echo "  ATT&CK: T1078.002"

echo
echo "[Rule 100103] WMI Remote Child Process Anomaly"
echo "  Behavior: WmiPrvSE.exe spawning cmd.exe or powershell.exe"
echo "  Evidence: Hunt WMI findings"
echo "  FP Rate: MEDIUM"
echo "  ATT&CK: T1047"

echo
echo "[Rule 100104] Service Account NTLM Network Logon"
echo "  Behavior: svc_* Type 3 NTLM authentication from workstation"
echo "  Evidence: Hunt Tasks 6 and 9"
echo "  FP Rate: VERY LOW"
echo "  ATT&CK: T1078.002 / T1550.002 investigation"

echo
echo "[Rule 100105] PowerShell Remoting from Non-Admin Workstation"
echo "  Behavior: PSRemoting initiated outside admin baseline"
echo "  Evidence: PSRemoting hunt"
echo "  FP Rate: LOW"
echo "  ATT&CK: T1021.006"

echo
echo "=== NETWORK RULE DRAFTS ==="

echo
echo "[Rule 9000030] SMB Lateral Movement - PsExec Service Pattern"
echo "  Behavior: PSEXESVC pattern over SMB/TCP 445"
echo "  Evidence: Hunt Task 4"
echo "  FP Rate: LOW"
echo "  ATT&CK: T1021.002"

echo
echo "=== DETECTION POSTURE UPDATE ==="
echo
echo "  Before hunt:"
echo "    Observed coverage: 55%"
echo "    Mapped coverage:   66%"
echo "    Stage 4 NOT COVERED techniques: 6"
echo
echo "  After hunt:"
echo "    Detection drafts created for all 6 Stage 4 hunt gaps."
echo "    Coverage is improved at the detection-design level."
echo "    Production coverage should only be updated after validation"
echo "    and deployment."

echo
echo "FILES CREATED:"
echo "  $WAZUH_FILE"
echo "  $NETWORK_FILE"
echo "  $DOC_FILE"

echo
echo "================================================================"