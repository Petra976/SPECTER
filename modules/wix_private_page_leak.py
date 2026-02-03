from utils.requester import get
from core.finding import Finding
import re

class WixPrivatePageLeakScanner:
    name = "wix_private_page_leak"

    def run(self, target):
        r = get(target)
        # O Wix muitas vezes carrega a estrutura de todas as páginas no JSON de inicialização
        private_data = re.findall(r'"pageUriSEO":"(.*?)"[^}]*"isProtected":true', r.text)
        if private_data:
            f = Finding(
                module=self.name,
                title="Wix Private Page Structure Exposure",
                severity="low",
                description="The titles and URIs of password-protected pages are visible in the site's manifest.",
                endpoint=target,
                evidence={"hidden_pages": private_data}
            )
            return [f.to_dict()]
        return None