from core.finding import Finding
from utils.requester import get

class WixSearchExposureScanner:
    name = "wix_search_exposure"

    def run(self, target):
        # Busca por termos comuns que podem revelar arquivos sensíveis indexados internamente
        search_url = f"{target}/_api/wix-search-v1/v1/search?query=admin"
        r = get(search_url)
        if r and "results" in r.text and len(r.json().get("results", [])) > 0:
            f = Finding(
                module=self.name,
                title="Wix Internal Search Sensitive Results",
                severity="medium",
                description="The internal search API returned results for 'admin', suggesting internal pages are indexed.",
                endpoint=search_url
            )
            return [f.to_dict()]
        return None