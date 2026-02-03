from core.finding import Finding
from utils.requester import get, post

class WixCorsScanner:
    name = "wix_cors_misconfiguration"

    def run(self, target):
        # Tenta disparar uma requisição com um Origin malicioso
        headers = {"Origin": "https://attacker.com"}
        r = get(target + "/_functions/v1/query", headers=headers) # Endpoint comum
        
        if r and r.headers.get("Access-Control-Allow-Origin") == "https://attacker.com":
            f = Finding(
                module=self.name,
                title="Critical CORS Misconfiguration",
                severity="high",
                description="The server reflects the Origin header, allowing any domain to perform cross-origin requests.",
                endpoint=target,
                evidence=r.headers
            )
            f.business_impact = "Attackers can steal sensitive user data by making requests from a malicious site while the user is logged in to Wix."
            f.remediation = "Restrict Access-Control-Allow-Origin to specific, trusted domains."
            return [f.to_dict()]
        return None