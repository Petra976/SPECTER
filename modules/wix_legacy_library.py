from core.finding import Finding
from utils.requester import get
import re

class WixLegacyLibraryScanner:
    name = "wix_legacy_library"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por versões antigas do Wix SDK ou jQuery injetado
        legacy_scripts = re.findall(r'src="([^"]+/(?:jquery/1\.|wix-sdk/2\.)[^"]+)"', r.text)

        if legacy_scripts:
            f = Finding(
                module=self.name,
                title="Outdated Wix/Third-party Libraries",
                severity="medium",
                description="The site uses legacy versions of JavaScript libraries which may have known CVEs.",
                endpoint=target,
                evidence={"legacy_scripts": legacy_scripts}
            )
            f.business_impact = "Using outdated libraries increases the risk of exploitation through known vulnerabilities like Prototype Pollution or XSS."
            f.remediation = "Update to the latest Wix Editor (Turbo) and ensure all custom scripts use modern, patched library versions."
            f.exploitability = "medium"
            return [f.to_dict()]
        return None