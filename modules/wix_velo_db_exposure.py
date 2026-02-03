from utils.requester import post
from core.finding import Finding

class WixVeloDatabaseBypassScanner:
    name = "wix_velo_db_exposure"

    def run(self, target):
        # Tenta acessar o endpoint padrão de query do Wix Data
        payload = {"collectionName": "Members", "query": {"filter": {}, "paging": {"limit": 1}}}
        r = post(f"{target}/_api/wix-data/v1/items/query", json=payload)
        
        if r and r.status_code == 200 and "items" in r.text:
            f = Finding(
                module=self.name,
                title="Wix Velo Unrestricted Database Access",
                severity="high",
                description="A Velo database collection is accessible to unauthenticated users via the wix-data API.",
                endpoint=target,
                business_impact="Attackers can dump the entire site database, including private member info or internal records."
            )
            return [f.to_dict()]
        return None