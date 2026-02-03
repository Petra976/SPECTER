from core.finding import Finding
from utils.requester import get

class WixDomainTakeoverScanner:
    name = "wix_domain_takeover"

    def run(self, target):
        r = get(target)
        if r and "This domain is not yet connected to a website" in r.text:
            f = Finding(
                module=self.name,
                title="Potential Wix Domain Takeover",
                severity="high",
                description="The domain points to Wix but shows a 'not connected' page. An attacker might be able to claim it.",
                endpoint=target
            )
            return [f.to_dict()]
        return None