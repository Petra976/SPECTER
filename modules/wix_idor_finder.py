from core.finding import Finding
from utils.requester import get
import json
import hashlib
import itertools

class WixIDORDetector:
    name = "wix_idor_detector"
    PARAMS = ["id", "userId", "ownerId", "accountId", "memberId"]
    requires = ["endpoints"]

    @staticmethod
    def extract_keys(obj):
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(k)
                keys.extend(WixIDORDetector.extract_keys(v))
        elif isinstance(obj, list):
            for i in obj:
                keys.extend(WixIDORDetector.extract_keys(i))
        return keys

    @staticmethod
    def hash_json_structure(data):
        try:
            obj = json.loads(data)
            keys = sorted(WixIDORDetector.extract_keys(obj))
            return hashlib.md5(str(keys).encode()).hexdigest()
        except:
            return None

    def test_param_variation(self, base_url, endpoint, param):
        values = ["1", "2", "3"]
        responses = []
        for v in values:
            url = f"{base_url}{endpoint}?{param}={v}"
            r = get(url)
            if not r or "application/json" not in r.headers.get("Content-Type", ""):
                continue
            structure_hash = self.hash_json_structure(r.text)
            responses.append({"value": v, "length": len(r.text), "hash": structure_hash})
        if len(responses) < 2:
            return None
        lengths = set(r["length"] for r in responses)
        structures = set(r["hash"] for r in responses)
        if len(lengths) > 1 or len(structures) > 1:
            return {"endpoint": endpoint, "parameter": param, "responses": responses}
        return None

    def run(self, target, discovered_endpoints):
        interesting = []
        for ep in discovered_endpoints:
            url_path = ep["url"].replace(target, "") if isinstance(ep, dict) else str(ep).replace(target, "")
            for p in self.PARAMS:
                res = self.test_param_variation(target, url_path, p)
                if res:
                    interesting.append(res)
        if not interesting:
            return None
        f = Finding(
            module=self.name,
            title="Wix IDOR Detection",
            severity="high",
            description="Potential IDOR vulnerabilities detected.",
            endpoint=target,
            evidence=interesting
        )
        f.business_impact = (
            "IDOR can allow attackers to access unauthorized data by manipulating request parameters."
        )
        f.remediation = (
            "Implement proper access controls and validate all input parameters server-side."
        )
        f.exploitability = "high"
        return [f.to_dict()]