from core.finding import Finding
from utils.requester import get
import re

class WixDebugModeScanner:
    name = "wix_debug_exposure"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Verifica se o site está rodando com parâmetros de debug ou se há logs verbosos
        indicators = [
            "wixHtmlEditor", 
            "is_debug=true", 
            "rendererModel",
            "Wix.Performance.measure"
        ]
        
        found_indicators = [i for i in indicators if i in r.text]

        if len(found_indicators) > 2:
            f = Finding(
                module=self.name,
                title="Wix Verbose Debug Information",
                severity="low",
                description="The site is exposing verbose renderer models or performance metrics that reveal internal Wix structure.",
                endpoint=target,
                evidence={"indicators": found_indicators}
            )
            f.business_impact = "Excessive information in the DOM makes it easier for attackers to identify the Wix version and internal object structures."
            f.remediation = "Ensure the site is published in production mode and remove all debug-related scripts and logs."
            f.exploitability = "medium"
            return [f.to_dict()]
        return None