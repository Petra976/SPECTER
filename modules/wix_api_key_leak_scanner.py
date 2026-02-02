from core.finding import Finding
from utils.requester import get
from urllib.parse import urljoin
import re
import math

class WixGenericSecretScanner:
    name = "wix_generic_secret_scanner"

    SUSPICIOUS_NAMES = [
        "key", "api", "secret", "token", "auth", "passwd",
        "password", "bearer", "jwt", "client_secret"
    ]

    def extract_js_urls(self, html, base):
        urls = re.findall(r'<script[^>]+src="([^"]+)"', html)
        return [urljoin(base, u) for u in urls]

    def shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log2(p_x)
        return entropy

    def looks_like_secret(self, key, value):
        if len(value) < 16:
            return False

        # nome suspeito
        if any(s in key.lower() for s in self.SUSPICIOUS_NAMES):
            return True

        # entropia alta
        if self.shannon_entropy(value) > 4.3:
            return True

        # JWT
        if value.startswith("eyJ") and "." in value:
            return True

        # base64 longo
        if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", value):
            return True

        return False

    def scan_js(self, content):
        findings = []

        # procura pares tipo key = "value"
        pairs = re.findall(r'([A-Za-z0-9_\-]+)\s*[:=]\s*["\']([^"\']{16,})["\']', content)

        for k, v in pairs:
            if self.looks_like_secret(k, v):
                findings.append({
                    "variable": k,
                    "value_preview": v[:6] + "..."
                })

        # Authorization headers
        auth_matches = re.findall(r'Authorization["\']?\s*[:=]\s*["\']Bearer\s+([^"\']+)', content)
        for token in auth_matches:
            findings.append({
                "type": "Bearer Token",
                "value_preview": token[:8] + "..."
            })

        return findings

    def run(self, target):
        r = get(target)
        if not r:
            return {}

        js_urls = self.extract_js_urls(r.text, target)
        all_findings = []

        for js in js_urls[:15]:
            js_resp = get(js)
            if not js_resp or len(js_resp.text) > 3_000_000:
                continue

            secrets = self.scan_js(js_resp.text)
            if secrets:
                all_findings.append({
                    "file": js,
                    "secrets": secrets
                })
        findings = []

        if all_findings:
            f = Finding(
                module=self.name,
                title="Wix API Key Leakage Detection",
                severity="medium",
                description="Sensitive API keys or tokens were discovered in publicly accessible JavaScript files.",
                endpoint=target,
                evidence=all_findings
            )

            f.business_impact = (
                "Identifying sensitive API keys or tokens in publicly accessible JavaScript files can allow attackers to gain unauthorized access to third-party services, potentially leading to data breaches or misuse of resources."
            )

            f.remediation = (
                "Ensure that API keys and tokens are not exposed in client-side JavaScript files. Use server-side rendering or secure token management practices to prevent exposure of sensitive credentials."
            )

            f.exploitability = "medium"

            findings.append(f.to_dict())

            return findings
        return None
