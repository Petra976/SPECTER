from core.finding import Finding
from utils.requester import get
import json

class WixDatabaseExposureScanner:
    name = "wix_database_exposure"

    # Nomes comuns de coleções que desenvolvedores esquecem de proteger
    COMMON_COLLECTIONS = [
        "Members", "Users", "Orders", "Subscribers", 
        "Contacts", "Config", "Settings", "Products"
    ]

    def run(self, target):
        findings = []
        exposed_collections = []

        # Endpoint padrão da API de dados do Wix para consultas
        # Nota: O Wix geralmente requer um App-ID, mas configurações maliciosas
        # ou roteamentos customizados podem expor o _api/wix-data
        base_api = target.rstrip('/') + "/_api/wix-data/v1/items/"

        for collection in self.COMMON_COLLECTIONS:
            url = f"{base_api}{collection}"
            r = get(url)
            
            # Se retornar 200 e tiver cara de JSON de banco de dados
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "items" in data or "results" in data:
                        exposed_collections.append({
                            "collection": collection,
                            "url": url,
                            "sample_count": len(data.get("items", []))
                        })
                except:
                    continue

        if exposed_collections:
            f = Finding(
                module=self.name,
                title="Publicly Accessible Wix Data Collection",
                severity="high",
                description="Database collections were found to be publicly accessible. This occurs when 'Read' permissions are set to 'Anyone' in Wix Velo settings.",
                endpoint=target,
                evidence=exposed_collections
            )
            f.business_impact = "Attackers can dump sensitive user data, orders, or internal configurations, leading to mass data breaches and GDPR violations."
            f.remediation = "Change the Collection Permissions in the Wix Dev Center/Velo Sidebar. Set 'Who can read content from this collection' to 'Admin' or 'Site Member Author'."
            f.exploitability = "high"
            
            findings.append(f.to_dict())
            return findings
        
        return None