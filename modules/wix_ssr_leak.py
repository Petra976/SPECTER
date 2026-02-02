from core.finding import Finding
from utils.requester import get
import re

class WixSsrLeakScanner:
    name = "wix_ssr_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por campos ocultos que contenham 'internal', 'debug' ou 'test'
        hidden_data = re.findall(r'style=["\']display:\s*none;?["\'][^>]*>(.*?)</div>', r.text)
        
        findings = []
        for content in hidden_data:
            if len(content) > 10 and any(x in content.lower() for x in ["password", "internal", "config", "admin"]):
                findings.append(content[:50])

        if findings:
            f = Finding(
                module=self.name,
                title="Information Leakage in SSR/SEO HTML",
                severity="low",
                description="Sensitive strings or hidden debug info were found in the Server-Side Rendered HTML, visible to crawlers.",
                endpoint=target,
                evidence=findings
            )
            f.business_impact = "Information intended only for admins or developers might be cached by search engines or visible to attackers inspecting the raw HTML."
            f.remediation = "Ensure that sensitive data is never rendered in the DOM, even as hidden elements."
            f.exploitability = "medium"
            return [f.to_dict()]
        return None