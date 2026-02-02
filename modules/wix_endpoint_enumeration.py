from core.finding import Finding
from utils.requester import get, post
from urllib.parse import urljoin

class WixEndpointEnumeration:
    name = "wix_endpoint_enumeration"

    # Categorização para facilitar a análise de risco
    ENDPOINTS_MAP = {
        "User & Auth": [
            "/_api/users/current", "/_api/users/login", "/_api/members/v1/members/my",
            "/_api/users/forgotPassword", "/_api/blog-permissions/v3/current-permissions"
        ],
        "Database & Collections": [
            "/_api/wix-data/v1/schema", "/_api/wix-data/v1/items/", 
            "/_api/wix-data/collections", "/_api/wix-data/v1/query"
        ],
        "E-commerce (Stores)": [
            "/_api/stores/products", "/_api/stores/cart", "/_api/stores/orders",
            "/_api/stores/customers", "/_api/stores/discounts"
        ],
        "Content & Blog": [
            "/_api/communities-blog-node-api/v3/posts", 
            "/_api/communities-forum-node-api/v3/threads",
            "/_api/blog-frontend-adapter-public/v2/post-feed-page-metadata"
        ],
        "System & Config": [
            "/_api/tag-manager/api/v1/tags/sites/", "/_api/v1/access-tokens",
            "/api/common/site/settings", "/api/common/user/info"
        ]
    }

    def is_meaningful_response(self, response):
        """Verifica se a resposta contém dados reais e não apenas um HTML de erro ou vazio."""
        if not response or response.status_code != 200:
            return False
        
        content_type = response.headers.get("Content-Type", "").lower()
        # Se for JSON, é um forte indicativo de API ativa
        if "application/json" in content_type:
            try:
                data = response.json()
                # Ignora respostas vazias ou padrões de erro codificados em JSON
                if data == {} or data == [] or "error" in str(data).lower():
                    return False
                return True
            except:
                return False
        
        # Se for texto, checa por palavras-chave de estrutura de dados
        keywords = ["id", "uid", "items", "collectionName", "ownerId", "role"]
        return any(key in response.text for key in keywords)

    def run(self, base_url):
        if not base_url:
            return None

        discovered = {}
        target = base_url.rstrip('/')

        for category, paths in self.ENDPOINTS_MAP.items():
            for path in paths:
                url = target + path
                # Tenta GET e depois POST se necessário
                r = get(url)
                if not self.is_meaningful_response(r):
                    r = post(url, json={}) # Wix APIs preferem JSON vazio a data={}
                
                if self.is_meaningful_response(r):
                    if category not in discovered:
                        discovered[category] = []
                    
                    # Tenta extrair um preview dos dados para a evidência
                    preview = "Data accessible"
                    try:
                        keys = list(r.json().keys())[:3]
                        preview = f"Keys: {', '.join(keys)}"
                    except: pass

                    discovered[category].append({"url": url, "info": preview})

        if discovered:
            all_urls = [item["url"] for cat in discovered.values() for item in cat]
            
            f = Finding(
                module=self.name,
                title="Wix API & Business Logic Enumeration",
                severity="medium", # Aumentado de 'low' para 'medium' pelo potencial de exposição de dados
                description=f"Active Wix internal endpoints were discovered across {len(discovered)} categories.",
                endpoint=target,
                evidence=discovered
            )

            f.business_impact = (
                "The discovery of these endpoints reveals the internal structure of the site's business logic, "
                "including store data, member lists, and database schemas. This facilitates targeted attacks "
                "like Insecure Direct Object References (IDOR) or unauthorized data extraction."
            )
            
            f.remediation = (
                "Implement strict CORS policies and ensure that each endpoint validates the user's "
                "session and permissions server-side. Disable public access to schema and debug endpoints."
            )
            
            f.exploitability = "High - These endpoints are designed to be consumed by the frontend and are easily mapped."

            return [f.to_dict()]
        
        return None