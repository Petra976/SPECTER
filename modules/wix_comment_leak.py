import re
from core.finding import Finding
from utils.requester import get

class WixCommentLeakScanner:
    name = "wix_comment_leak"

    def run(self, target):
        r = get(target)
        if not r: return None
        
        # Procura comentários sensíveis em arquivos JS carregados
        # Este regex foca em flags de desenvolvedores
        pattern = r'//\s*(DEBUG|TODO|FIXME|SECRET|CREDENTIAL|KEY)'
        matches = re.findall(pattern, r.text, re.IGNORECASE)
        
        if matches:
            f = Finding(
                module=self.name,
                title="Sensitive Comments in Source Code",
                severity="info",
                description="Developer comments found in production code may leak internal logic or credentials.",
                endpoint=target,
                evidence=matches
            )
            return [f.to_dict()]
        return None