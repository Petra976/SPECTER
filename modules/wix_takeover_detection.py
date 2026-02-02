from core.finding import Finding
from utils.requester import get
import socket

class WixTakeoverScanner:
    name = "wix_takeover_detection"

    def is_wix_missing(self, target):
        r = get(target)
        # Assinaturas de domínios que apontam para o Wix mas não têm site ativo
        indicators = [
            "Connect this domain to a Wix site",
            "Domain Not Found",
            "This domain is not yet connected to a website",
            "Looks like this domain isn't connected to a website yet"
        ]
        if r and r.status_code == 404:
            return any(indicator in r.text for indicator in indicators)
        return False

    def run(self, target):
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        try:
            # Verifica se o CNAME aponta para infraestrutura Wix
            # Em um scanner real, você usaria dnspython, aqui simulamos via socket/info
            is_pointing_to_wix = False
            try:
                cname_info = socket.gethostbyname_ex(domain)
                if any("wix.com" in str(alias) for alias in cname_info[1]):
                    is_pointing_to_wix = True
            except:
                pass

            if is_pointing_to_wix and self.is_wix_missing(target):
                f = Finding(
                    module=self.name,
                    title="Potential Wix Subdomain Takeover",
                    severity="critical",
                    description=f"The domain {domain} points to Wix infrastructure, but no active site is associated with it.",
                    endpoint=target,
                    evidence={"domain": domain, "reason": "Dangling DNS CNAME pointing to Wix"}
                )
                f.business_impact = "An attacker can claim this domain in their own Wix account, hosting malicious content or stealing session cookies from the main domain."
                f.remediation = "If the domain is no longer in use, remove the DNS CNAME/A record. If it should be active, ensure it is correctly linked in the Wix Dashboard."
                f.exploitability = "high"

                return [f.to_dict()]
        except Exception:
            return None
        
        return None