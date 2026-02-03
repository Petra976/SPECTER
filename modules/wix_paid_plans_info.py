from core.finding import Finding
from utils.requester import get
import re

class WixPaidPlansExploitScanner:
    name = "wix_paid_plans_info"

    def run(self, target):
        r = get(f"{target}/plans")
        if not r: return None
        
        plan_ids = re.findall(r'"planId":"([a-z0-9\-]{36})"', r.text)
        if plan_ids:
            f = Finding(
                module=self.name,
                title="Wix Paid Plan ID Exposure",
                severity="low",
                description="Subscription plan IDs are exposed. These can be used to manipulate checkout requests.",
                endpoint=target,
                evidence={"plan_ids": plan_ids}
            )
            return [f.to_dict()]
        return None