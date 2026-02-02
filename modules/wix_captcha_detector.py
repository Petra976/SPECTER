from core.finding import Finding
from utils.requester import get
from bs4 import BeautifulSoup


class WixCaptchaDetector:
    name = "wix_captcha_detector"
    requires = []

    CAPTCHA_TEXT_INDICATORS = [
        "please verify you're a human",
        "verify you are human",
        "complete the captcha",
    ]

    CAPTCHA_SCRIPT_INDICATORS = [
        "recaptcha",
        "hcaptcha",
        "captcha",
        "wix-captcha",
    ]

    def detect_captcha(self, base_url):
        r = get(base_url)
        if not r:
            return None

        indicators_found = []

        if r.status_code in [403, 429]:
            indicators_found.append(f"HTTP block status detected ({r.status_code})")

        html = r.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        page_text = soup.get_text().lower()
        for indicator in self.CAPTCHA_TEXT_INDICATORS:
            if indicator in page_text:
                indicators_found.append(f"Text indicator: {indicator}")

        if "data-sitekey" in html:
            indicators_found.append("reCAPTCHA sitekey detected")

        for script in soup.find_all("script"):
            src = (script.get("src") or "").lower()
            content = (script.string or "").lower()

            for indicator in self.CAPTCHA_SCRIPT_INDICATORS:
                if indicator in src or indicator in content:
                    indicators_found.append(f"Script indicator: {indicator}")

        for iframe in soup.find_all("iframe"):
            src = (iframe.get("src") or "").lower()
            if any(x in src for x in ["recaptcha", "hcaptcha", "captcha"]):
                indicators_found.append(f"Iframe CAPTCHA: {src}")

        return indicators_found if indicators_found else None

    def run(self, base_url):
        detected = self.detect_captcha(base_url)

        if not detected:
            f = Finding(
            module=self.name,
            title="Wix CAPTCHA / Bot Protection Not Detected",
            severity="low",
            description="No Wix CAPTCHA or bot protection mechanisms were detected on the site.",
            endpoint=base_url,
            evidence=detected
            )

            f.business_impact = (
                "The absence of CAPTCHA or bot protection mechanisms may make the site more vulnerable to automated attacks."
            )
            f.remediation = (
                "Consider implementing CAPTCHA or bot protection mechanisms to prevent automated abuse."
            )
            f.exploitability = "Automated bots can easily access and interact with the site without any challenges."

            return [f.to_dict()]
    
