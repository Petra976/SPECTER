from core.finding import Finding
from utils.requester import get
import re

class WixTpaConfigLeakScanner:
    name = "wix_tpa_config_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Procura por configurações de Apps de terceiros expostas no window.wixEmbedsConfig
        tpa_configs = re.findall(r'["\']appDefinitionId["\']\s*:\s*["\']([^"\']+)["\']', r.text)
        instance_ids = re.findall(r'["\']instance["\']\s*:\s*["\']([^"\']+)["\']', r.text)

        if tpa_configs and instance_ids:
            f = Finding(
                module=self.name,
                title="Wix TPA Instance ID Leakage",
                severity="low",
                description="Internal App Instance IDs and TPA (Third Party App) configurations are exposed in the frontend source code.",
                endpoint=target,
                evidence={"apps_found": len(tpa_configs), "sample_instance": instance_ids[0][:10] + "..."}
            )
            f.business_impact = "Exposed instance IDs can be used to forge requests to specific App APIs, potentially bypassing frontend restrictions."
            f.remediation = "Ensure that sensitive app logic and validation occur on the server side using the Wix Instance Secret."
            f.exploitability = "low"
            return [f.to_dict()]
        return None