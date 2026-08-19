#Requires -Version 5.1
<#
.SYNOPSIS
    TEST FIXTURE ONLY -- stand-in for the project-provided audit helper at
    /home/analyst/MedDefense_Lab/capstone/win_audit.ps1

    This is NOT the real MedDefense CIS Level 1 audit helper. It exists
    purely so 1-baseline_snapshot.ps1 could be validated end-to-end with a
    real PowerShell interpreter in this sandbox. Replace with the actual
    project-provided win_audit.ps1 in the real environment.

.DESCRIPTION
    Emits one line per simulated CIS Level 1 control in the form:
        <control-id>  <description>  <PASS|FAIL|NOT_APPLICABLE>
#>
[CmdletBinding()]
param()

$controls = @(
    @{ Id = 'CIS-1.1.1';  Desc = 'Enforce password history';           Result = 'PASS' }
    @{ Id = 'CIS-1.1.2';  Desc = 'Maximum password age';                Result = 'PASS' }
    @{ Id = 'CIS-1.1.3';  Desc = 'Minimum password age';                Result = 'FAIL' }
    @{ Id = 'CIS-1.1.4';  Desc = 'Minimum password length';              Result = 'PASS' }
    @{ Id = 'CIS-1.2.1';  Desc = 'Account lockout duration';             Result = 'PASS' }
    @{ Id = 'CIS-1.2.2';  Desc = 'Account lockout threshold';            Result = 'FAIL' }
    @{ Id = 'CIS-2.2.1';  Desc = 'Access Credential Manager as trusted'; Result = 'PASS' }
    @{ Id = 'CIS-2.3.1.1';Desc = 'Administrator account status';        Result = 'PASS' }
    @{ Id = 'CIS-5.1';    Desc = 'Bluetooth Audio Gateway service';      Result = 'NOT_APPLICABLE' }
    @{ Id = 'CIS-5.2';    Desc = 'Bluetooth Support service';            Result = 'NOT_APPLICABLE' }
    @{ Id = 'CIS-9.1.1';  Desc = 'Windows Firewall Domain state';        Result = 'PASS' }
    @{ Id = 'CIS-9.2.1';  Desc = 'Windows Firewall Private state';       Result = 'PASS' }
    @{ Id = 'CIS-18.9.1'; Desc = 'PowerShell Script Block Logging';      Result = 'FAIL' }
)

foreach ($control in $controls) {
    Write-Output ("{0}  {1}  {2}" -f $control.Id, $control.Desc, $control.Result)
}
