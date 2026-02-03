from utils.requester import get
from core.finding import Finding
import re

class WixEditorTokenScanner:
    name = "wix_editor_token_leak"

    def run(self, target):
        r = get(target)
        # Procura por tokens de convite de edição
        tokens = re.findall(r'metaSiteId=([a-z0-9\-]{36}).*?editorToken=([a-zA-Z0-9\._\-]*)', r.text)
        if tokens:
            f = Finding(
                module=self.name,
                title="Wix Editor Collaboration Token Leak",
                severity="high",
                description="An internal Editor token was found in the source code. This could facilitate unauthorized site access.",
                endpoint=target,
                evidence={"metaSiteId": tokens[0][0]}
            )
            return [f.to_dict()]
        return None