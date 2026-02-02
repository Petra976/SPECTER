from core.finding import Finding
from utils.requester import get
import re

class WixCustomElementXssScanner:
    name = "wix_custom_element_xss"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por definições de elementos customizados e scripts associados
        custom_elements = re.findall(r'customElements\.define\(["\']([^"\']+)["\']', r.text)
        
        findings = []
        if custom_elements:
            for elem in custom_elements:
                findings.append({"element_tag": elem, "potential_sink": "attributeChangedCallback"})

            f = Finding(
                module=self.name,
                title="Potential XSS in Wix Custom Element",
                severity="medium",
                description=f"Custom Elements ({custom_elements}) detected. These components often insecurely handle data via attributeChangedCallback.",
                endpoint=target,
                evidence=findings
            )
            f.business_impact = "An attacker could inject malicious scripts if the custom element handles attributes without proper sanitization."
            f.remediation = "Review the JavaScript code for the custom element. Use textContent instead of innerHTML when rendering attribute values."
            f.exploitability = "medium"
            return [f.to_dict()]
        return None