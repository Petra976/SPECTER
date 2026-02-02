from core.finding import Finding
from utils.requester import post, get
import time
import statistics

class WixRateLimitScanner:
    name = "wix_rate_limit_scanner"
    TEST_ENDPOINTS = [
        "/_api/members/v1/authentication/login",
        "/_api/members/v1/authentication/send-reset-password-email"
    ]
    ATTEMPTS = 12
    requires = ["endpoints"]

    def test_login_rate_limit(self, base_url, endpoint):
        url = base_url.rstrip("/") + endpoint
        times, statuses = [], []
        for i in range(self.ATTEMPTS):
            start = time.time()
            r = post(url, json={"email": f"test{i}@test.com", "password": "WrongPass123"})
            if not r:
                continue
            times.append(time.time() - start)
            statuses.append(r.status_code)
        if len(statuses) < 5 or 429 in statuses or statistics.stdev(times) > 2:
            return None
        return {"endpoint": endpoint, "statuses": statuses[:5], "avg_response_time": round(sum(times)/len(times), 2)}

    def test_api_rate_limit(self, url):
        times, statuses = [], []
        for _ in range(self.ATTEMPTS):
            start = time.time()
            r = get(url)
            if not r:
                continue
            times.append(time.time() - start)
            statuses.append(r.status_code)
        if 429 in statuses or statistics.stdev(times) > 2:
            return None
        return {"endpoint": url, "issue": "No visible rate limiting"}

    def run(self, target, discovered_endpoints):
        findings = []
        # Auth endpoints
        for ep in self.TEST_ENDPOINTS:
            res = self.test_login_rate_limit(target, ep)
            if res:
                findings.append(res)
        # APIs descobertas
        for ep in discovered_endpoints[:5]:
            url = ep["url"] if isinstance(ep, dict) else str(ep)
            res = self.test_api_rate_limit(url)
            if res:
                findings.append(res)
        if not findings:
            return None
        f = Finding(
            module=self.name,
            title="Rate Limiting Issues Detected",
            severity="high",
            description="Rate limiting issues detected on endpoints.",
            endpoint=target,
            evidence=findings
        )
        f.business_impact = (
            "Rate limiting issues can allow abuse of endpoints and potential unauthorized access."
        )
        f.remediation = (
            "Implement proper rate limiting and throttling to protect endpoints."
        )
        f.exploitability = "high"
        return [f.to_dict()]
