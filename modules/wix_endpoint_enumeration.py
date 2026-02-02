from core.finding import Finding
from utils.requester import get, post

class WixEndpointEnumeration:
    name = "wix_endpoint_enumeration"
    requires = []

    COMMON_ENDPOINTS = [
        "/api/common/user/info",
        "/api/common/site/info",
        "/api/common/site/settings",
        "/api/common/memberships/list",
        "/api/common/files/list",
        "/api/common/blog/posts",
        "/api/common/shop/products",
        "/api/common/events/list",
        "/_api/users/current",
        "/_api/users/login",
        "/_api/users/logout",
        "/_api/users/register",
        "/_api/common/files/list",
        "/_api/common/blog/posts",
        "/_api/common/shop/products",
        "/_api/common/events/list",
        "/_api/communities-blog-node-api/v3/posts",
        "/_api/communities-forum-node-api/v3/threads",
        "/_api/communities-blog-node-api/v3/posts/query",
        "/_api/blog-permissions/v3/current-permissions",
        "/_api/members/v1/members",
        "/_api/users/forgotPassword",
        "/_api/users/changePassword",
        "/_api/wix-data/collections/",
        "/_api/wix-data/collections/a/count",
        "/_api/wix-data/collections/a/query",
        "/_api/stores/products",
        "/_api/stores/cart",
        "/_api/stores/checkout",
        "/_api/stores/orders",
        "/_api/stores/customers",
        "/_api/stores/discounts",
        "/_api/v1/access-tokens",
        "/_api/blog-frontend-adapter-public/v2/post-feed-page-metadata",
        "/_api/members/v1/members/my",
        "/_api/tag-manager/api/v1/tags/sites/"
        "/_api/blog-frontend-adapter-public/v2/post-page/"
        "/_api/communities-blog-node-api/v3/categories"
    ]

    def enumerate_endpoints(self, base_url):
        discovered_endpoints = []

        for endpoint in self.COMMON_ENDPOINTS:
            r = get(base_url + endpoint)
            if r and r.status_code == 200:
                discovered_endpoints.append(base_url + endpoint)
            else:
                r = post(base_url + endpoint, data={})
                if r and r.status_code == 200:
                    discovered_endpoints.append(base_url + endpoint)

        return discovered_endpoints

    def run(self, base_url):
        if not base_url:
            return None

        endpoints = self.enumerate_endpoints(base_url)
        if not endpoints:
            return None

        f = Finding(
            module=self.name,
            title="Wix Endpoint Enumeration",
            severity="low",
            description="The following Wix endpoints were discovered: " + ", ".join(endpoints),
            endpoint=base_url,
            evidence=endpoints
        )

        f.business_impact = (
            "Knowledge of available endpoints can aid attackers in further reconnaissance and exploitation."
        )
        f.remediation = (
            "Review and restrict access to sensitive endpoints as necessary."
        )
        f.exploitability = "These endpoints are publicly accessible and can be enumerated by anyone."

        return [f.to_dict()]