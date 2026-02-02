from core.finding import Finding
from utils.requester import get
import re

class WixAppTokenLeakScanner:
    name = "wix_app_token_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por tokens de instância do Wix em iframes de Apps
        # O parâmetro 'instance=' é um JWT que dá acesso às APIs do App
        instance_tokens = re.findall(r'instance=([a-zA-Z0-9\.\-_]{50,})', r.text)

        if instance_tokens:
            f = Finding(
                module=self.name,
                title="Wix App Instance Token Leakage",
                severity="medium",
                description="Wix App Instance Tokens (JWT) were found exposed in the source code. These tokens identify the site to third-party Wix Apps.",
                endpoint=target,
                evidence={"token_count": len(instance_tokens), "preview": instance_tokens[0][:15] + "..."}
            )
            f.business_impact = "If intercepted, these tokens can be used to perform actions in third-party apps as if they were the site owner or a user."
            f.remediation = "Review third-party app settings and ensure that the site does not leak the full iframe URLs to external analytics or logs."
            f.exploitability = "medium"
            return [f.to_dict()]
        return None