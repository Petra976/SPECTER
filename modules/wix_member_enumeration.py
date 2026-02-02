from core.finding import Finding
from utils.requester import post
import random
import string
import re

class WixMemberEnumerationScanner:
    name = "wix_member_enumeration"

    MEMBER_ENDPOINTS = [
        "/_api/members/v1/authentication/login",
        "/_api/members/v1/authentication/register",
        "/_api/members/v1/authentication/send-reset-password-email"
    ]

    ENUM_PATTERNS = [
        r"user does not exist",
        r"email not found",
        r"no account",
        r"already exists",
        r"email already in use",
        r"member not found"
    ]

    def random_email(self):
        rand = ''.join(random.choices(string.ascii_lowercase, k=10))
        return f"{rand}@test.com"

    def response_indicates_enum(self, text):
        for p in self.ENUM_PATTERNS:
            if re.search(p, text, re.I):
                return True
        return False

    def run(self, target):
        results = []
        test_email = self.random_email()

        for ep in self.MEMBER_ENDPOINTS:

            data = {
                "email": test_email,
                "password": "Password123"
            }

            r = post(target, data=data)
            if not r:
                continue

            body = r.text.lower()

            # Sinais de enumeração
            if self.response_indicates_enum(body):
                results.append({
                    "endpoint": r,
                    "status": r.status_code,
                    "response_snippet": body[:200]
                })

        if results:
            findings = []

            f = Finding(
                module=self.name,
                title="Wix Member Enumeration Vulnerability",
                severity="medium",
                description="Public Wix API functions were discovered that allow enumeration of member accounts.",
                endpoint=target,
                evidence=results
            )

            f.business_impact = (
                "An attacker could exploit this vulnerability to determine valid user accounts, which may lead to further attacks such as phishing or brute-force password attempts."
            )

            f.remediation = (
                "It is recommended to standardize error messages for authentication endpoints to avoid revealing whether a user account exists. Implement generic responses for login, registration, and password reset requests."
            )

            f.exploitability = "Medium"

            findings.append(f.to_dict())

            return findings
        return None

