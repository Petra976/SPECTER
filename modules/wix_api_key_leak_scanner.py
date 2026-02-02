from core.finding import Finding
from utils.requester import get
from urllib.parse import urljoin
import re
import math

class WixGenericSecretScanner:
    name = "wix_generic_secret_scanner"

    # Nomes de variáveis que indicam alta probabilidade de segredos
    SUSPICIOUS_NAMES = [
        "key", "api", "secret", "token", "auth", "passwd", "password", 
        "bearer", "jwt", "client_secret", "access_key", "credential"
    ]

    # Regex para provedores específicos (Alta Precisão)
    SPECIFIC_RULES = {
        "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
        "Firebase Config": r'apiKey["\']?\s*[:=]\s*["\'](AIza[0-9A-Za-z-_]{35})["\']',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24}',
        "GitHub Personal Access Token": r'ghp_[a-zA-Z0-9]{36}',
        "Generic Secret Pair": r'(?i)(?:key|secret|token|auth|api|pass|pwd)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']'
    }

    # Strings que frequentemente geram falsos positivos em JS
    FALSE_POSITIVES = ["webpack", "anonymous", "internal", "version", "react"]

    def extract_js_urls(self, html, base):
        # Captura tanto <script src> quanto links em blocos de texto/JSON
        urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
        return list(set([urljoin(base, u) for u in urls]))

    def shannon_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log2(p_x)
        return entropy

    def is_valid_secret(self, key, value):
        val_lower = value.lower()
        
        # Ignorar se o valor for um falso positivo conhecido
        if any(fp in val_lower for fp in self.FALSE_POSITIVES):
            return False

        # Ignorar caminhos de arquivos ou URLs
        if "/" in value or "http" in val_lower:
            return False

        entropy = self.shannon_entropy(value)
        
        # Se o nome for suspeito, aceitamos entropia menor
        if any(s in key.lower() for s in self.SUSPICIOUS_NAMES):
            return len(value) >= 16 and entropy > 3.5
        
        # Se for apenas uma string solta, a entropia deve ser muito alta
        return len(value) >= 24 and entropy > 4.5

    def scan_content(self, content):
        findings = []

        # 1. Busca por regras específicas (Provedores conhecidos)
        for name, pattern in self.SPECIFIC_RULES.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                # Se a regex tiver grupos, pega o valor do grupo 1, senão o match inteiro
                val = m.group(1) if len(m.groups()) > 0 else m.group(0)
                findings.append({
                    "type": name,
                    "value_preview": f"{val[:6]}...{val[-4:]}" if len(val) > 10 else val[:5]
                })

        # 2. Busca por Authorization Bearer Tokens (JWT/Tokens longos)
        auth_matches = re.findall(r'Authorization["\']?\s*[:=]\s*["\']Bearer\s+([a-zA-Z0-9\-\._~+/]+=*)', content)
        for token in auth_matches:
            if len(token) > 20:
                findings.append({
                    "type": "Bearer Token/JWT",
                    "value_preview": f"{token[:10]}..."
                })

        return findings

    def run(self, target):
        r = get(target)
        if not r: return None

        js_urls = self.extract_js_urls(r.text, target)
        all_findings = []

        for js in js_urls:
            # Ignorar bibliotecas conhecidas para economizar tempo/recursos
            if any(lib in js for lib in ["jquery", "lodash", "react", "wix-code-sdk"]):
                continue

            js_resp = get(js)
            if not js_resp or len(js_resp.text) > 2_000_000: # 2MB limit
                continue

            secrets = self.scan_content(js_resp.text)
            if secrets:
                all_findings.append({
                    "file": js,
                    "secrets": secrets
                })

        if all_findings:
            f = Finding(
                module=self.name,
                title="Wix Sensitive API Key Leakage",
                severity="high",
                description="Hardcoded API keys, secrets, or authentication tokens were found in client-side JavaScript. This can lead to unauthorized access to external services.",
                endpoint=target,
                evidence=all_findings
            )
            f.business_impact = "Exposure of service credentials can allow attackers to impersonate the application, access databases, or incur costs on the owner's cloud accounts."
            f.remediation = "Move sensitive API keys to the Wix Backend (.jsw files) and use Velo's 'Secrets Manager' to store and access them securely."
            f.exploitability = "high"

            return [f.to_dict()]
        
        return None