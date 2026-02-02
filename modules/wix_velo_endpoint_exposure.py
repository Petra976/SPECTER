from core.finding import Finding
from utils.requester import get
import re

class WixVeloEndpointScanner:
    name = "wix_velo_endpoint_exposure"

    # Padrões comuns de rotas de funções backend do Wix Velo
    VELO_PATTERNS = [
        "/_functions/",
        "/_api/v2/dynamic-model/",
        "web-modules/"
    ]

    def run(self, target):
        findings = []
        exposed_endpoints = []

        # Tenta identificar chamadas para web-modules no HTML principal
        r = get(target)
        if not r:
            return None

        # Procura por referências a módulos de backend expostos no frontend
        modules = re.findall(r'import\s+.*\s+from\s+["\'](backend/.*\.jsw)["\']', r.text)
        
        for module in modules:
            exposed_endpoints.append({"type": "JSW Module Reference", "source": module})

        # Verifica se o diretório de funções customizadas está acessível (Information Exposure)
        functions_url = target.rstrip('/') + "/_functions-list" # Endpoint teórico de debug
        r_func = get(functions_url)
        
        if r_func and r_func.status_code == 200 and "functionName" in r_func.text:
            exposed_endpoints.append({"type": "Velo Function List", "url": functions_url})

        if exposed_endpoints:
            f = Finding(
                module=self.name,
                title="Wix Velo Backend Module Exposure",
                severity="low",
                description="References to backend web modules (.jsw) or custom functions were found. While not a direct exploit, this reveals internal API structure.",
                endpoint=target,
                evidence=exposed_endpoints
            )
            f.business_impact = "Exposure of backend logic can assist an attacker in mapping the application's attack surface and finding vulnerable API parameters."
            f.remediation = "Ensure that sensitive logic is properly encapsulated and that no debug information or function lists are publicly accessible."
            f.exploitability = "low"
            
            findings.append(f.to_dict())
            return findings
        
        return None