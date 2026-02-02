from core.finding import Finding
import re
import json


class WixSensitiveDataClassifier:
    name = "wix_sensitive_data_classifier"
    requires = ["idor"]

    PATTERNS = {
        "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Phone": r"\+?\d[\d\s\-]{8,}",
        "CPF": r"\d{3}\.\d{3}\.\d{3}\-\d{2}",
        "JWT": r"eyJ[A-Za-z0-9_\-\.]+",
        "Credit Card": r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    }

    SENSITIVE_KEYS = [
        "email", "name", "phone", "cpf", "address",
        "token", "secret", "document", "userId", "memberId"
    ]

    # 🔍 Recursivo pra varrer qualquer JSON
    def scan_json(self, obj, indicators):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if any(s.lower() in k.lower() for s in self.SENSITIVE_KEYS):
                    indicators.add(f"Sensitive key name: {k}")
                self.scan_json(v, indicators)

        elif isinstance(obj, list):
            for i in obj:
                self.scan_json(i, indicators)

        elif isinstance(obj, str):
            for name, pattern in self.PATTERNS.items():
                if re.search(pattern, obj):
                    indicators.add(f"Sensitive data pattern: {name}")

    # 🔧 Parser resiliente
    def parse_body(self, body):
        if isinstance(body, dict):
            return body

        if not body:
            return None

        if isinstance(body, str):
            try:
                return json.loads(body)
            except:
                return None

        return None

    def run(self, idor_results):
        if not idor_results:
            return None

        all_findings = []
        evidence_list = []

        for result in idor_results:

            endpoint = result.get("endpoint", "unknown")
            parameter = result.get("parameter", "unknown")

            responses = result.get("responses", [])

            # 🔥 Se vier um único dict, transforma em lista
            if isinstance(responses, dict):
                responses = [responses]

            # 🔥 Se vier string (sim, já vi API fazer isso), ignora
            if isinstance(responses, str):
                continue

            for resp in responses:

                # Pode ser dict ou string
                if isinstance(resp, dict):
                    body = resp.get("body")
                else:
                    body = resp

                data = self.parse_body(body)
                if not data:
                    continue

                indicators = set()
                self.scan_json(data, indicators)

                if indicators:
                    evidence_list.append({
                        "endpoint": endpoint,
                        "parameter": parameter,
                        "indicators": list(indicators)
                    })

        if not evidence_list:
            return None

        f = Finding(
            module=self.name,
            title="Wix IDOR Sensitive Data Exposure",
            severity="high",
            description="IDOR vulnerabilities exposing sensitive data were discovered.",
            endpoint="Multiple endpoints",
            evidence=evidence_list
        )

        f.business_impact = (
            "Sensitive data exposure through IDOR vulnerabilities can lead to privacy violations, "
            "identity theft, account takeover, and regulatory penalties."
        )

        f.remediation = (
            "Implement object-level access control (BOLA protection). Validate ownership of resources "
            "server-side and never rely on client-provided identifiers."
        )

        f.exploitability = "high"

        all_findings.append(f.to_dict())

        return all_findings
