from utils.requester import get
import re
from core.finding import Finding

class WixTechFingerprint:
    name = "wix_tech_fingerprint"

    def run(self, target):
        r = get(target)
        if not r:
            return {"is_wix": False}

        score = 0
        evidence = []

        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        if "x-wix-request-id" in headers:
            score += 3
            evidence.append("x-wix-request-id header")

        if headers.get("server") == "pepyaka":
            score += 3
            evidence.append("Server: Pepyaka")

        if re.search(r"(wixstatic|parastorage|frog\.wix\.com)", r.text, re.I):
            score += 2
            evidence.append("Wix JS/CDN references")

        if 'Wix.com Website Builder' in r.text:
            score += 2
            evidence.append("Meta generator Wix")

        api_test = get(target + "/_api/")
        if api_test and api_test.status_code != 404:
            score += 1
            evidence.append("/_api endpoint exists")

        findings = []

        if evidence:
            f = Finding(
                module=self.name,
                title="Wix Technology Fingerprinting",
                severity="high",
                description="Wix technology is detected on the target website.",
                endpoint=target,
                evidence=evidence
            )

            f.business_impact = (
                "Identifying the use of Wix technology can help attackers tailor their strategies, "
                "such as targeting known vulnerabilities in Wix components or exploiting Wix-specific features."
            )

            f.remediation = (
                "No remediation necessary if Wix usage is intended; however, ensure that all Wix components are kept up to date and follow best security practices."
            )

            f.exploitability = "low"

            findings.append(f.to_dict())

            return findings
        return None
