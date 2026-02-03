from core.finding import Finding
from utils.requester import get

class WixWebhookInsecureScanner:
    name = "wix_webhook_insecure"

    def run(self, target):
        # Tenta disparar um POST para endpoints comuns de webhook Velo
        # Nota: Este é um scanner passivo/semi-ativo
        r = get(f"{target}/_functions/webhook")
        if r and r.status_code == 200:
             f = Finding(
                module=self.name,
                title="Potential Insecure Wix Velo Webhook",
                severity="medium",
                description="A Velo Webhook endpoint was found. If it doesn't validate 'wix-signature', it can be abused.",
                endpoint=f"{target}/_functions/webhook",
                evidence="Endpoint accessible at /_functions/webhook"
            )
             return [f.to_dict()]
        return None