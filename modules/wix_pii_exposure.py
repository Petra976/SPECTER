from core.finding import Finding
from utils.requester import get

class WixPiiExposureScanner:
    name = "wix_pii_exposure"

    def run(self, target):
        # Tenta acessar campos comuns de PII em coleções de contatos/leads
        pii_collections = ["Leads", "Newsletter", "ContactForm", "Entries"]
        discovered_pii = []

        for col in pii_collections:
            url = f"{target.rstrip('/')}/_api/wix-data/v1/items/{col}"
            r = get(url)
            if r and r.status_code == 200:
                if any(x in r.text for x in ["@gmail.com", "phone", "address"]):
                    discovered_pii.append(col)

        if discovered_pii:
            f = Finding(
                module=self.name,
                title="PII Data Exposure in Collections",
                severity="critical",
                description=f"Personal information was found in the following public collections: {', '.join(discovered_pii)}",
                endpoint=target,
                evidence=discovered_pii
            )
            return [f.to_dict()]
        return None