from core.finding import Finding
from utils.requester import get

class WixOpenRedirectScanner:
    name = "wix_open_redirect"

    def run(self, target):
        payload = "/_api/users/login?redirectUrl=https://malicious-site.com"
        url = target.rstrip('/') + payload
        
        r = get(url)
        if r and r.status_code in [301, 302] and "malicious-site.com" in r.headers.get("Location", ""):
            f = Finding(
                module=self.name,
                title="Open Redirect in Wix Login",
                severity="low",
                description="The login flow allows redirecting users to arbitrary external domains.",
                endpoint=url,
                evidence=r.headers.get("Location")
            )
            return [f.to_dict()]
        return None