from core.finding import Finding
from utils.requester import get
import re

class WixStorageLeakScanner:
    name = "wix_storage_leak_detection"

    # Padrões que indicam persistência de dados sensíveis no navegador
    LEAK_PATTERNS = [
        r'local\.setItem\(["\'](user|profile|token|auth|pii)',
        r'session\.setItem\(["\'](payment|order|creditCard)',
        r'wixStorage\.local\.insert',
        r'JSON\.stringify\(.*\.currentUser\)'
    ]

    def run(self, target):
        r = get(target)
        if not r:
            return None

        findings = []
        
        # O scanner busca no HTML e nos scripts carregados por padrões de persistência
        for pattern in self.LEAK_PATTERNS:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern_found": pattern,
                    "location": "Main Page Source"
                })

        # Também verifica se há referências a trackers de terceiros que podem acessar o storage
        third_party_scripts = re.findall(r'src=["\'](https?://(?!.*wix).*?\.(?:js))["\']', r.text)
        
        if findings and third_party_scripts:
            f = Finding(
                module=self.name,
                title="Sensitive Data Persistence in Client-Side Storage",
                severity="medium",
                description="The site appears to store sensitive user or session data in LocalStorage/SessionStorage while also loading third-party scripts.",
                endpoint=target,
                evidence={
                    "storage_patterns": [f["pattern_found"] for f in findings],
                    "third_party_scripts_count": len(third_party_scripts)
                }
            )

            f.business_impact = (
                "Data stored in LocalStorage is accessible to any script running on the page. "
                "If a third-party script is compromised or malicious, it can exfiltrate "
                "user PII, authentication tokens, or payment details stored there."
            )

            f.remediation = (
                "Avoid storing sensitive data in LocalStorage or SessionStorage. "
                "Use Wix Session variables (server-side) or keep sensitive state in the Velo backend. "
                "If persistence is necessary, encrypt the data before storing it on the client side."
            )

            f.exploitability = "medium"
            return [f.to_dict()]
            
        return None