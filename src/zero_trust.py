import requests

ZTNA_API = "https://secure-gateway.openziti.io/authenticate"

def verify_user(identity: str, token: str) -> bool:
    """Verify identity via Zero Trust API Gateway."""
    payload = {"identity": identity, "token": token}
    response = requests.post(ZTNA_API, json=payload)
    
    if response.status_code == 200 and response.json().get("verified"):
        return True
    return False
