from core.finding import Finding
from utils.requester import get
from urllib.parse import urljoin
import re

COMMON_FUNCTIONS = [
    "getUser", "getUsers", "getOrders", "createOrder",
    "deleteUser", "updateProfile", "loginUser",
    "registerUser", "getMembers", "adminPanel"
]

class WixPublicAPIScanner:
    name = "wix_public_api_scanner"
    requires = []

    def extract_functions_from_html(self, html):
        pattern = r"/_functions/([a-zA-Z0-9_\-]+)"
        return set(re.findall(pattern, html))

    def extract_js_urls(self, html, base):
        raw_urls = re.findall(r'<script[^>]+src="([^"]+)"', html)
        return [urljoin(base, u) for u in raw_urls]

    def find_functions_in_js(self, js_content):
        return set(re.findall(r"_functions/([a-zA-Z0-9_\-]+)", js_content))

    def probe_function(self, base_url, func):
        url = f"{base_url.rstrip('/')}/_functions/{func}"
        r = get(url)

        if not r or not hasattr(r, "status_code"):
            return None

        headers = getattr(r, "headers", {}) or {}
        content_type = headers.get("Content-Type", "").lower()

        text = getattr(r, "text", "")
        looks_json = "application/json" in content_type
        looks_structured = text.strip().startswith("{") or text.strip().startswith("[")

        if r.status_code in [200, 400, 401, 403] and (looks_json or looks_structured):
            return {
                "function": func,
                "url": url,
                "status": r.status_code,
                "content_type": content_type,
                "length": len(text)
            }

        return None


    def run(self, target):
        r = get(target)
        if not r or not hasattr(r, "text"):
            return None
        
        found_functions = set()

        found_functions |= self.extract_functions_from_html(r.text)

        js_urls = self.extract_js_urls(r.text, target)
        for js in js_urls:
            js_resp = get(js)
            if js_resp and hasattr(js_resp, "text") and len(js_resp.text) < 2_000_000:
                found_functions |= self.find_functions_in_js(js_resp.text)

        found_functions |= set(COMMON_FUNCTIONS)

        results = []
        for func in found_functions:
            res = self.probe_function(target, func)
            if res:
                results.append(res)

        if results:
            findings = []

            f = Finding(
                module=self.name,
                title="Wix Public API Functions Exposure",
                severity="medium",
                description="Public Wix API functions were discovered.",
                endpoint=target,
                evidence=results
            )

            f.business_impact = (
                "Exposed Wix API functions can provide attackers with insights into the application's backend operations."
            )

            f.remediation = (
                "Review and restrict access to Wix API functions that should not be publicly accessible."
            )

            f.exploitability = "medium"

            findings.append(f.to_dict())

            return findings
        return None
