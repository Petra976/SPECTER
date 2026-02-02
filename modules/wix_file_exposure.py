from core.finding import Finding
from utils.requester import get
import re

class WixFileExposureScanner:
    name = "wix_file_exposure"

    def run(self, target):
        # Busca por padrões de URLs de documentos no Wix (wixmp.com ou static.wix)
        r = get(target)
        if not r: return None

        # Procura links para documentos que podem ser sensíveis
        sensitive_docs = re.findall(r'https://[^"\']+\.(?:pdf|docx|zip|xlsx)\b', r.text)
        
        leaked = []
        for doc in set(sensitive_docs):
            if "static.wixstatic.com/ugd/" in doc: # UGD = User Generated Document
                leaked.append(doc)

        if leaked:
            f = Finding(
                module=self.name,
                title="Sensitive Document Exposure",
                severity="low",
                description="Direct links to user-generated documents (PDFs, Docs) were found. If these contain PII, it represents a data leak.",
                endpoint=target,
                evidence=leaked[:5]
            )
            f.business_impact = "Public access to uploaded documents can lead to the exposure of sensitive personal information (PII) or confidential business data."
            f.remediation = "Use Wix Velo to serve files through a backend function that checks for authentication before redirecting to the file URL."
            f.exploitability = "low"
            return [f.to_dict()]
        return None