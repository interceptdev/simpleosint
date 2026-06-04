import requests
from typing import Any, Dict

APIKEY = "YOUR_HIBP_API_KEY"

def search_breaches(query: str) -> Dict[str, Any]:
    """
    Queries Have I Been Pwned API for data breaches associated with an email address.
    """
    Email = query.strip()
    
    Headers = {
        "hibp-api-key": APIKEY,
        "User-Agent": "OSINT-Tool"
    }
    
    Url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{Email}"
    
    try:
        Response = requests.get(Url, headers=Headers, params={"truncateResponse": "false"}, timeout=10)
        
        if Response.status_code == 200:
            Breaches = Response.json()
            Count = len(Breaches)
            TypesSet = set()
            
            LogDetails = f"[!] WARNING: {Count} DATA BREACHES FOUND FOR {Email}\n"
            LogDetails += "=" * 60 + "\n"
            
            for Idx, Breach in enumerate(Breaches, 1):
                Name = Breach.get("Name", "Unknown")
                Domain = Breach.get("Domain", "N/A")
                Date = Breach.get("BreachDate", "Unknown")
                DataClasses = ", ".join(Breach.get("DataClasses", []))
                
                TypesSet.update(Breach.get("DataClasses", []))
                
                LogDetails += f"{Idx}. {Name} ({Domain})\n"
                LogDetails += f"   • Date of Breach: {Date}\n"
                LogDetails += f"   • Compromised Data: {DataClasses}\n\n"
            
            return {
                "count": Count,
                "types": ", ".join(TypesSet),
                "details": LogDetails
            }
            
        elif Response.status_code == 404:
            return {
                "count": 0,
                "types": "None",
                "details": f"[✔] Clean record. No breaches found for {Email} in HaveIBeenPwned database."
            }
            
        elif Response.status_code == 401:
            return {
                "count": 0,
                "types": "Error",
                "details": "[Error] Invalid HIBP API Key. Please verify your credentials."
            }
            
        elif Response.status_code == 429:
            return {
                "count": 0,
                "types": "Error",
                "details": "[Error] Rate limited by HaveIBeenPwned. Try again in a few seconds."
            }
            
        else:
            return {
                "count": 0,
                "types": "Error",
                "details": f"[Error] HIBP API returned status code {Response.status_code}"
            }
            
    except requests.exceptions.RequestException as E:
        return {
            "count": 0,
            "types": "Error",
            "details": f"[Error] Connection failed: {str(E)}"
        }
