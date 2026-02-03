import re
from core.finding import Finding
from utils.requester import get

class WixFormActionScanner:
    name = "wix_form_action_leak"

    def run(self, target):
        r = get(target)
        if not r: return None
        
        actions = re.findall(r'action="(https://.*?\.wixforms\.com/.*?)"', r.text)
        if actions:
            f = Finding(
                module=self.name,
                title="Wix Form Action URL Exposure",
                severity="low",
                description="Direct form submission URLs found. These can be used for automated spam attacks.",
                endpoint=target,
                evidence={"urls": actions}
            )
            return [f.to_dict()]
        return None