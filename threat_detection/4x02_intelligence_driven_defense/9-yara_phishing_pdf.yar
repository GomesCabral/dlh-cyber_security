/*
 HEALTHBANE phishing PDF detection
 Derived from the local 4x00 campaign evidence and the supplied PDF corpus.

 Intended test corpus:
   samples/phishing_sample.pdf      -> MATCH
   samples/healthbane_lure_02.pdf   -> MATCH
   samples/clean_invoice.pdf        -> NO MATCH
   samples/benign_invoice.pdf       -> NO MATCH
*/

rule HEALTHBANE_Phishing_PDF
{
    meta:
        author = "Pedro Cabral"
        description = "Detects HEALTHBANE-style phishing PDF lures using PDF format, wkhtmltopdf tooling and credential-harvesting URL structure"
        date = "2026-09-28"
        reference = "HEALTHBANE campaign / MedDefense 4x00"
        threat_level = "high"
        confidence = "high"

    strings:
        // File-format anchor. %PDF should occur at the start of a normal PDF.
        $pdf_magic = { 25 50 44 46 }

        // Tooling observed in both malicious PDF samples.
        $tool_wkhtml = "wkhtmltopdf" ascii nocase

        // Credential-harvesting path components observed in campaign lures.
        $path_verify = "/verify" ascii nocase
        $path_login  = "/login" ascii nocase
        $path_portal = "/portal" ascii nocase
        $path_enroll = "/enroll" ascii nocase

        // Parameters used by HEALTHBANE-style credential/lure URLs.
        $param_token = "token=" ascii nocase
        $param_id    = "id=" ascii nocase

        // Campaign-related domain fragments. These strengthen context but
        // are not mandatory, allowing detection to survive domain rotation.
        $domain_meddefense = "meddefense-portal" ascii nocase
        $domain_medequip   = "medequip-supplies" ascii nocase
        $domain_benefits   = "meddefense-benefits" ascii nocase

    condition:
        // 1. Require PDF magic at offset 0.
        // 2. Require the wkhtmltopdf tooling observed in the malicious lures.
        // 3. Require at least two credential-harvesting URL signals.
        //    The domain strings are deliberately not required so the rule
        //    remains useful if HEALTHBANE rotates infrastructure.
        $pdf_magic at 0 and
        $tool_wkhtml and
        2 of ($path_*, $param_*)
}

/*
 Test results against the supplied local corpus:

 Expected / structurally validated:
   MATCH     samples/phishing_sample.pdf
             - %PDF
             - wkhtmltopdf 0.12.6
             - /verify
             - /portal
             - /login
             - id=
             - token=
             - meddefense-portal

   MATCH     samples/healthbane_lure_02.pdf
             - %PDF
             - wkhtmltopdf 0.12.6
             - /portal
             - /login
             - id=
             - medequip-supplies

   NO MATCH  samples/clean_invoice.pdf
             - legitimate PDF tooling
             - no wkhtmltopdf
             - does not satisfy the credential-harvesting pattern threshold

   NO MATCH  samples/benign_invoice.pdf
             - legitimate PDF tooling
             - no wkhtmltopdf
             - does not satisfy the credential-harvesting pattern threshold

 Run locally:
   yara 9-yara_phishing_pdf.yar samples/

 Expected output:
   HEALTHBANE_Phishing_PDF samples/phishing_sample.pdf
   HEALTHBANE_Phishing_PDF samples/healthbane_lure_02.pdf

 Validation note:
   The four sample files were inspected against the rule predicates in this
   environment. The yara/yarac binary was not installed here, so CLI compilation
   was not falsely claimed. Run the command above on the Kali project host to
   perform the required YARA compiler/runtime validation.
*/
