import re
from core.finding import Finding
from utils.requester import get

class WixGlobalVarLeak:
    name = "wix_global_var_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por chaves de API dentro de objetos de configuração globais do Wix
        patterns = {
            "Google Maps": r'["\']googleMapsApiKey["\']\s*:\s*["\'](AIza[0-9A-Za-z-_]{35})["\']',
            "Firebase Key": r'["\']apiKey["\']\s*:\s*["\'](AIza[0-9A-Za-z-_]{35})["\']'
        }

        findings = []
        for service, pattern in patterns.items():
            matches = re.findall(pattern, r.text)
            if matches:
                findings.append({"service": service, "key": matches[0]})

        if findings:
            f = Finding(
                module=self.name,
                title="Sensitive Keys in Wix Global Config",
                severity="medium",
                description="API keys were found inside window.__WIX_CONFIG__ or similar objects.",
                endpoint=target,
                evidence=findings
            )
            return [f.to_dict()]
        return None