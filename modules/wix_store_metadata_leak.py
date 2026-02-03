from utils.requester import get
from core.finding import Finding

class WixStoreMetadataScanner:
    name = "wix_store_metadata_leak"

    def run(self, target):
        r = get(f"{target}/_api/wix-ecommerce-renderer-web/v1/products")
        if r and "inventoryItem" in r.text:
            f = Finding(
                module=self.name,
                title="Wix Store Product Metadata Exposure",
                severity="medium",
                description="Sensitive product metadata, potentially including inventory details, was found via an unauthenticated API call.",
                endpoint=target,
                evidence=r.text
            )
            return [f.to_dict()]
        return None