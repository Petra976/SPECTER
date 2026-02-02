from core.finding import Finding
from utils.requester import get
import re

class WixMediaMetadataScanner:
    name = "wix_media_metadata_leak"

    def run(self, target):
        r = get(target)
        if not r: return None

        # Extrai URLs de imagens hospedadas no Wix
        images = re.findall(r'https://static\.wixstatic\.com/media/[^"\']+', r.text)
        
        if images:
            # Analisamos apenas a primeira para evitar excesso de requisições (rate limiting)
            sample_img = images[0].split('/v1/')[0] # Limpa a URL
            
            f = Finding(
                module=self.name,
                title="Information Leakage via Media Metadata",
                severity="low",
                description="Images hosted on Wix Static may contain EXIF metadata (GPS, Camera info, Usernames).",
                endpoint=target,
                evidence={"sample_image": sample_img}
            )
            f.business_impact = "Metadata leakage can reveal sensitive information about the site's content creators or internal infrastructure."
            f.remediation = "Sanitize images before uploading or use a backend process to strip EXIF data."
            f.exploitability = "low"
            return [f.to_dict()]
        return None