from core.finding import Finding
from utils.requester import get
import re

class WixPostMessageScanner:
    name = "wix_postmessage_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por listeners de mensagens que não verificam a origem
        # Padrão: escuta 'message' mas não contém check de 'origin'
        if "addEventListener('message'" in r.text or 'addEventListener("message"' in r.text:
            if ".origin" not in r.text:
                f = Finding(
                    module=self.name,
                    title="Insecure PostMessage Listener",
                    severity="medium",
                    description="The site uses postMessage listeners but does not appear to validate the origin of incoming messages.",
                    endpoint=target,
                    evidence="Missing 'event.origin' check in script."
                )
                f.business_impact = "An attacker can execute cross-site scripting (XSS) or trigger internal actions by sending specially crafted messages from a malicious site."
                f.remediation = "Always check 'if (event.origin !== \"https://trusted.domain.com\") return;' inside your message event listeners."
                f.exploitability = "medium"
                return [f.to_dict()]
        return None