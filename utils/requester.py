import requests
import urllib3

urllib3.disable_warnings()

session = requests.Session()
session.headers.update({
    "User-Agent": "S.P.E.C.T.E.R Scanner",
    "Accept": "*/*",
})

def get(url, headers=session.headers):
    try:
        return session.get(url, timeout=8, verify=False, headers=headers)
    except:
        return None

def post(url, json=None, data=None):
    try:
        return session.post(url, json=json, data=data, timeout=8, verify=False)
    except:
        return None
    
def request_raw(method, url, timeout=8):
    try:
        return requests.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=False,
            verify=False
        )
    except:
        return None