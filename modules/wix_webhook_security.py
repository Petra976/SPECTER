from core.finding import Finding
from utils.requester import post

class WixWebhookSecurityScanner:
    name = "wix_webhook_security"

    # Endpoints comuns onde desenvolvedores expõem listeners de webhooks
    WEBHOOK_PATHS = [
        "/_functions/webhook", "/_functions/notify", 
        "/_functions/stripe_callback", "/_functions/sync_data"
    ]

    def run(self, target):
        findings = []
        for path in self.WEBHOOK_PATHS:
            url = target.rstrip('/') + path
            # Tenta um POST sem assinatura
            r = post(url, json={"test": "ping"})
            
            # Se o endpoint responder 200 ou 201 sem exigir assinatura/token
            if r and r.status_code in [200, 201]:
                findings.append({
                    "endpoint": url,
                    "vulnerability": "Potential Unauthenticated Webhook Listener"
                })

        if findings:
            f = Finding(
                module=self.name,
                title="Unauthenticated Wix Webhook Listener",
                severity="high",
                description="A custom Wix Function appears to accept POST requests without proper authentication or signature verification.",
                endpoint=target,
                evidence=findings
            )
            f.business_impact = "Attackers can inject malicious data into your CRM, trigger fake orders, or manipulate internal workflows by spoofing webhooks."
            f.remediation = "Always verify the 'wix-signature' header in your Velo functions or use a secret token in the query string to validate the sender."
            f.exploitability = "high"
            return [f.to_dict()]
        return None