from utils.requester import get
from core.finding import Finding

class WixCustomAuthScanner:
    name = "wix_custom_auth_weakness"

    def run(self, target):
        # Verifica se existe o arquivo de rota customizado do Velo para login
        r = get(f"{target}/_functions/login")
        if r and r.status_code != 404:
            f = Finding(
                module=self.name,
                title="Custom Velo Authentication Endpoint Detected",
                severity="info",
                description="The site uses a custom Velo login function. These are often prone to NoSQL injection or weak session management.",
                endpoint=f"{target}/_functions/login"
            )
            return [f.to_dict()]
        return None