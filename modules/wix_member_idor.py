import re
from core.finding import Finding
from utils.requester import get

class WixMemberIdorScanner:
    name = "wix_member_idor"

    def run(self, target):
        # Tenta acessar o perfil de um usuário "1" ou similar através da API interna
        test_endpoints = ["/_api/members/v1/members/1", "/_api/members/v1/members/00000000-0000-0000-0000-000000000000"]
        
        for url in test_endpoints:
            r = get(target.rstrip('/') + url)
            if r and r.status_code == 200 and ("nickname" in r.text or "emails" in r.text):
                f = Finding(
                    module=self.name,
                    title="IDOR in Wix Members API",
                    severity="critical",
                    description="It is possible to access other members' private data by manipulating the member ID.",
                    endpoint=target + url,
                    evidence=r.text[:200]
                )
                return [f.to_dict()]
        return None