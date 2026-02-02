from core.finding import Finding
from utils.requester import get

class WixCORSScanner:
    name = "wix_cors_misconfig_scanner"
    requires = ["endpoints"]

    TEST_ORIGIN = "https://evil.com"

    def check_cors(self, url):
        headers = {"Origin": self.TEST_ORIGIN}

        r = get(url, headers=headers)
        if not r:
            return None

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            return None

        # Casos perigosos
        if acao == "*" and acc.lower() == "true":
            return {"url": url, "issue": "Wildcard origin with credentials allowed"}

        if self.TEST_ORIGIN in acao and acc.lower() == "true":
            return {"url": url, "issue": "Arbitrary origin reflected with credentials"}

        return None

    def run(self, discovered_endpoints):
        if not discovered_endpoints:
            return None

        sensitive_findings = []

        for ep in discovered_endpoints:
            # Suporta ep como dict ou string
            if isinstance(ep, dict) and "url" in ep:
                url = ep["url"]
            elif isinstance(ep, str):
                url = ep
            else:
                continue

            result = self.check_cors(url)
            if result:
                sensitive_findings.append(result)

        if not sensitive_findings:
            return None

        # Criar um único Finding consolidado
        f = Finding(
            module=self.name,
            title="Wix CORS Misconfiguration Detected",
            severity="high",
            description="CORS misconfigurations were detected that may allow unauthorized cross-origin requests.",
            endpoint="Multiple endpoints",
            evidence=sensitive_findings
        )

        f.business_impact = (
            "CORS misconfigurations can allow unauthorized cross-origin requests, potentially leading to data exposure, session hijacking, and other security issues."
        )

        f.remediation = (
            "Ensure CORS headers are properly configured to restrict access to trusted origins only. "
            "Avoid using wildcard origins (*) and ensure credentials are not allowed from untrusted origins."
        )

        f.exploitability = "high"

        return [f.to_dict()]
