from utils.requester import get
from core.finding import Finding
import re

class WixChatInfoLeakScanner:
    name = "wix_chat_info_leak"

    def run(self, target):
        r = get(target)
        if not r: return None
        
        chat_config = re.findall(r'window\.__CHAT_CONFIG__ = ({.*?});', r.text)
        if chat_config:
            f = Finding(
                module=self.name,
                title="Wix Chat Configuration Exposure",
                severity="low",
                description="The site is exposing internal chat configurations which may contain operator IDs or third-party integration keys.",
                endpoint=target,
                evidence={"config_found": True}
            )
            return [f.to_dict()]
        return None