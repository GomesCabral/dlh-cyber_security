# Hardening Updates: IR-2026-0414-01

**Organization:** MedDefense  
**Evidence:** `forensic_findings_summary.md` (5x02)  
**Gap register:** `gap_analysis.md` (Task 2)  
**Status:** Proposed configurations; pilot, change approval and validation required before production.

## HRD-001: PowerShell Constrained Language Mode (CLM)

**Closes:** GAP-005 (primary), GAP-004 (defense-in-depth; the Sigma detection remains necessary).  
**Evidence:** ART-001-F01 (`update.xml` inline MSBuild task in user Temp); ART-002-M01 (PowerShell PID 7812 spawning MSBuild PID 8104); ART-001-E01.

**Control:** Enforce application control on non-administrative clinical workstation users so PowerShell operates in `ConstrainedLanguage` for untrusted scripts. Apply to `WST-WS-031`, `WST-WS-017` and the clinical workstation OU after a pilot.

**Configuration:**

1. Create an App Control for Business (Windows Defender Application Control / WDAC) policy allowing trusted signed Windows components and approved clinical applications, with untrusted scripts subject to policy enforcement. Deploy in **audit mode** first; review compatibility, then enforce via supported App Control deployment (Intune or GPO startup deployment of the signed policy where applicable).
2. If using AppLocker script rules as the chosen application-control mechanism, configure via **Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker > Script Rules**, enable the Application Identity service, and set enforcement after an audit pilot. Confirm the effective PowerShell language mode under the selected application-control configuration.
3. **Requested registry reference (lab only, not an approved production security control):** GPO **Computer Configuration > Preferences > Windows Settings > Registry**; `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`; value `__PSLockdownPolicy` (REG_SZ) = `4`. This is an unsupported/testing mechanism and can be bypassed or ignored; **do not rely on this registry value as production enforcement**. It must not be the only hardening action.

**Effect:** Under supported application-control enforcement, untrusted PowerShell is constrained: arbitrary .NET type invocation and methods such as `[System.Management.Automation.ScriptBlock]::Create(...)` are restricted. CLM alone does not stop a user from starting `MSBuild.exe`; HRD-002 separately restricts MSBuild.

**Validation:** Sign in as a standard clinical user and run `powershell.exe -NoProfile -Command "$ExecutionContext.SessionState.LanguageMode"`; expect `ConstrainedLanguage` for untrusted execution. Verify a controlled `[System.Management.Automation.ScriptBlock]::Create('1+1')` attempt is blocked; confirm application-control enforcement and event logs. Repeat for `pwsh.exe` if deployed. An administrator or trusted script may behave differently; test the intended user context.

---

## HRD-002: AppLocker MSBuild execution restrictions

**Closes:** GAP-005 (primary), GAP-004 (defense-in-depth).  
**Evidence:** ART-001-F01, ART-001-F02, ART-001-E01 and ART-002-M01 show an MSBuild loader and payload under `C:\Users\dmarsh\AppData\Local\Temp\` and PowerShell spawning MSBuild.

**Control:** AppLocker executable allowlisting for `MSBuild.exe` on clinical and administrative workstations; allow only `BUILTIN\Administrators` and explicitly named MedDefense CI/CD service accounts (to be approved and enumerated before deployment).

**Configuration:**

- GPO: **Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules**; start in **Audit only**, then **Enforce rules**. Ensure the **Application Identity** service is running.
- Define publisher- or hash-constrained allow rules for approved signed Microsoft MSBuild binaries and approved installed paths. Do **not** use a broad `Everyone` allow rule for `C:\Windows\*` or `C:\Program Files\*` that inadvertently permits MSBuild to all users. Review inherited/default executable rules and other allow rules for bypasses.
- Example **illustrative rule XML structure** (replace placeholders with actual AD SIDs and verified binary publisher information before import):

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="11111111-1111-4111-8111-111111111111"
                  Name="Allow MSBuild for local Administrators"
                  Description="Restricted developer utility"
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\Microsoft Visual Studio\*\MSBuild\Current\Bin\MSBuild.exe" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="22222222-2222-4222-8222-222222222222"
                  Name="Allow MSBuild for approved CI service group"
                  Description="Replace SID with MedDefense CI group SID"
                  UserOrGroupSid="S-1-5-21-REPLACE-WITH-APPROVED-GROUP-SID" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\Microsoft Visual Studio\*\MSBuild\Current\Bin\MSBuild.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

**Important:** This XML is a policy *skeleton*, not an import-ready complete production policy. AppLocker evaluates the union of all applicable allow rules: audit existing rules, cover all installed MSBuild paths (including .NET Framework variants), and confirm the executable collection has suitable general Windows/application allow rules without granting MSBuild to standard users. A path allow rule alone is weaker than publisher/hash restrictions and must be assessed for writable-path abuse.

**Validation:** Run `Get-AppLockerPolicy -Effective -Xml` on a target workstation; use `Test-AppLockerPolicy -Path '<actual MSBuild path>' -User 'MEDDEFENSE\dmarsh'` and repeat for a named CI identity and an administrator. Expected: standard user denied, approved identities allowed; verify AppLocker EXE/DLL event logs and an actual standard-user execution attempt after enforcement.

---

## HRD-003: Conditional access for new-country VPN authentication

**Closes:** GAP-002 (primary), GAP-003 (VPN coverage verification).  
**Evidence:** Compromised `MEDDEFENSE\dmarsh` account; foreign-IP Office 365 session from `45.63.9.88` (described as RU) at 2026-04-13 18:14:41Z; Entra risk signals suppressed by a `compliant device` rule. **VPN login is not established by the forensic summary.**

**Control:** Apply phishing-resistant MFA and sign-in-risk protection to VPN authentication, with a 30-day new-country signal in the SIEM/identity workflow.

**Configuration / policy logic:**

1. Confirm that the VPN is integrated with Microsoft Entra ID (SAML/OIDC or another supported method) and that VPN sign-ins are present in Entra sign-in logs; otherwise enforce equivalent controls at the VPN identity provider and ingest concentrator logs.
2. In **Microsoft Entra admin center > Protection > Conditional Access > Policies**, create `MD-VPN-PhishingResistantMFA`: include authorized VPN users, target the integrated VPN enterprise application, and require an **authentication strength: Phishing-resistant MFA** (for example FIDO2/passkeys or supported certificate-based authentication). Do not create an exception that allows device compliance to bypass the risk/MFA requirement. Configure emergency access exclusions separately under formal governance.
3. Configure a separate sign-in-risk policy for relevant users/apps where licensing and signal availability support it; pilot in **Report-only** mode, examine policy evaluation, then enforce. Use Entra named locations for approved geographic restrictions where justified; named locations are static policy objects, not an automatic per-user 30-day history.
4. **Thirty-day new-country detection (not native Conditional Access syntax):** normalize successful VPN authentication events; compare `user + country` against that user's successful VPN logins during the **preceding 30 days**. If the country is absent, create a high-priority SIEM alert, notify identity operations and trigger a supported risk/remediation workflow (or block at the VPN gateway if its policy engine supports this signal). Do not claim a custom SIEM alert alone can synchronously force an Entra step-up challenge. For deterministic pre-authentication blocking, use supported VPN/identity policy integration or a static country restriction.
5. Correlate the observed `45.63.9.88` Office 365 event with VPN concentrator logs before asserting VPN use.

**Validation:** Use a test account with an approved VPN integration; verify phishing-resistant MFA is required, device compliance does not bypass it, and report-only/enforced policy logs record the decision. Inject or simulate a first-seen-country VPN event against the preceding 30-day baseline; verify SIEM alert and documented response action. Confirm any gateway block separately.

---

## HRD-004: Windows Defender Credential Guard

**Closes:** GAP-008 (primary), GAP-009 (complementary monitoring remains necessary).  
**Evidence:** ART-002-M04 reports `dmarsh` NTLM hash material present in LSASS at capture; the summary maps T1003.001 and T1558.003, but does **not** independently prove a successful LSASS dump or ticket extraction.

**Control:** Enable **Windows Defender Credential Guard** on supported MedDefense endpoints to protect eligible NTLM/Kerberos secrets using virtualization-based security (VBS).

**Configuration:**

- GPO: **Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security** = **Enabled**.
- Set **Select Platform Security Level** to a hardware-supported secure-boot option; set **Credential Guard Configuration** to **Enabled without UEFI lock** for the initial manageable pilot (choose UEFI lock only after a recovery/change-control assessment).
- Supporting policy registry reference: `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` (DWORD `1`); `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` (DWORD `2` for enabled without UEFI lock; `1` for with lock). Prefer GPO/MDM to manually editing registry values.
- Confirm VBS prerequisites: supported 64-bit Windows, UEFI/Secure Boot and required virtualization hardware; Windows 10 Enterprise/Education and supported Windows 11 Enterprise/Education editions are common supported managed-client targets, with availability/default behavior varying by edition, version, hardware and deployment. Windows Server support varies by release and configuration. **Verify the exact MedDefense endpoint build and Microsoft's current support matrix before rollout.**
- Pilot with clinical applications, authentication, remote management and any legacy protocols; Credential Guard does not protect all credentials, eliminate every LSASS attack path, or replace EDR/LSASS monitoring.

**Validation:** Run `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning`; confirm value `1` (Credential Guard) is present. Check `msinfo32` > **Virtualization-based Security Services Running** for Credential Guard and review relevant Device Guard/WinInit event logs after restart. Registry configuration alone is not proof the service is running.

---

## Deployment and evidence notes

| Control | Primary gap IDs | Pilot validation evidence | Rollout gate |
| --- | --- | --- | --- |
| HRD-001 CLM | GAP-005, GAP-004 | Standard-user `LanguageMode`, blocked .NET test, App Control events | Clinical workflow compatibility; supported policy enforcement |
| HRD-002 MSBuild AppLocker | GAP-005, GAP-004 | Effective policy, standard-user deny, CI/admin allow | Complete executable allowlist and all MSBuild paths reviewed |
| HRD-003 VPN conditional access | GAP-002, GAP-003 | Entra policy logs, VPN logs, 30-day first-seen-country alert | VPN integration confirmed; report-only tests; no compliance bypass |
| HRD-004 Credential Guard | GAP-008, GAP-009 | `SecurityServicesRunning` includes `1` | Hardware/OS support and clinical application compatibility |

**Evidence limits:** The supplied forensic hand-off confirms MSBuild execution and network activity, compromised credentials and PHI reads. It does not prove that VPN access occurred, Credential Guard was disabled, or an LSASS dump succeeded. Proposed controls must be tested and recorded before their gaps are marked closed.
