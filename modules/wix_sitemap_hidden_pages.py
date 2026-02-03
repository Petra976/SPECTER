from core.finding import Finding
from utils.requester import get
import re

class WixSitemapHiddenPagesScanner:
    name = "wix_sitemap_hidden_pages"

    def run(self, target):
        r = get(f"{target}/sitemap.xml")
        if not r: return None
        
        suspicious = re.findall(r'<(?:loc)>(.*?/(?:test|draft|copy-of|dev).*?)</(?:loc)>', r.text)
        if suspicious:
            f = Finding(
                module=self.name,
                title="Wix Hidden/Development Pages in Sitemap",
                severity="medium",
                description="Development, test, or draft pages were found in the public sitemap.xml.",
                endpoint=target,
                evidence={"pages": suspicious[:5]}
            )
            return [f.to_dict()]
        return None