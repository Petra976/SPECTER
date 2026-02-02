from core.finding import Finding
from utils.requester import get
from urllib.parse import urljoin
import re

class WixSensitiveFileScanner:
    name = "wix_sensitive_file_discovery"

    SENSITIVE_PATHS = [
        "robots.txt",
        "sitemap.xml",
        "_api/v1/site-configuration",
        "assets/manifest.json",
        "pro-gallery-backend"
    ]

    def check_sourcemaps(self, html, base):
        # Tenta encontrar .map files que revelam o código fonte original (Node/React)
        scripts = re.findall(r'src="([^"]+\.js)"', html)
        maps_found = []
        for s in scripts:
            map_url = urljoin(base, s + ".map")
            r = get(map_url)
            if r and r.status_code == 200 and '"sources":' in r.text:
                maps_found.append(map_url)
        return maps_found

    def run(self, target):
        findings = []
        discovered_issues = []

        r_main = get(target)
        if not r_main: return None

        # 1. Busca por Source Maps (Crítico para reconstruir o backend/logic)
        maps = self.check_sourcemaps(r_main.text, target)
        if maps:
            discovered_issues.append({"issue": "JavaScript Source Maps Exposed", "files": maps})

        # 2. Busca por arquivos de configuração
        for path in self.SENSITIVE_PATHS:
            url = urljoin(target, path)
            res = get(url)
            if res and res.status_code == 200:
                if "error" not in res.text.lower() and len(res.text) > 0:
                    discovered_issues.append({"issue": "Sensitive Path Accessible", "url": url})

        if discovered_issues:
            f = Finding(
                module=self.name,
                title="Wix Infrastructure Information Leakage",
                severity="medium",
                description="Sensitive files or source maps were discovered. Source maps allow attackers to decompile client-side code to its original state.",
                endpoint=target,
                evidence=discovered_issues
            )
            f.business_impact = "Attackers can use source maps to understand complex logic, find hidden API keys, or identify vulnerabilities in the original source code."
            f.remediation = "Disable the generation of source maps in production environments and restrict access to internal configuration endpoints."
            f.exploitability = "medium"

            findings.append(f.to_dict())
            return findings
        
        return None