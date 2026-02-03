from utils.requester import get
from core.finding import Finding

class WixInsecureUploadScanner:
    name = "wix_insecure_upload"

    def run(self, target):
        r = get(f"{target}/_api/upload-server-web/v1/generate-upload-url")
        if r and r.status_code == 200:
            f = Finding(
                module=self.name,
                title="Unauthenticated File Upload URL Generation",
                severity="medium",
                description="The site allows generating upload URLs without an active session, potentially allowing unauthorized file hosting.",
                endpoint=target
            )
            return [f.to_dict()]
        return None