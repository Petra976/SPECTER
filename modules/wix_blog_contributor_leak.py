import re
from core.finding import Finding
from utils.requester import get

class WixBlogContributorScanner:
    name = "wix_blog_contributor_leak"

    def run(self, target):
        r = get(f"{target}/blog")
        if not r: return None
        
        author_ids = re.findall(r'"authorId":"([a-z0-9\-]{36})"', r.text)
        if author_ids:
            f = Finding(
                module=self.name,
                title="Wix Blog Contributor ID Exposure",
                severity="low",
                description="Internal Author UUIDs were found in the blog source code.",
                endpoint=target,
                evidence={"ids": list(set(author_ids))}
            )
            return [f.to_dict()]
        return None