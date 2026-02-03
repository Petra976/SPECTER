from utils.requester import get
from core.finding import Finding
import re

class WixClientSideKeyScanner:
    name = "wix_client_key_leak"

    def run(self, target):
        r = get(target)
        # Regex para capturar padrões comuns de chaves de API inseridas via Velo
        keys = re.findall(r'(?:api_key|secret|token|authorization):\s*["\'](sk_[a-zA-Z0-9]{20,})["\']', r.text, re.I)
        if keys:
            f = Finding(
                module=self.name,
                title="Wix Client-Side Secret Leak",
                severity="critical",
                description="Sensitive API secrets (e.g., Stripe, SendGrid) were found in client-side Velo code.",
                endpoint=target,
                evidence={"keys_found": len(keys)}
            )
            return [f.to_dict()]
        return None