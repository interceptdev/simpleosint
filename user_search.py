import hashlib
import requests
from typing import Any, Dict

def search_target(query: str) -> Dict[str, Any]:
    QueryClean = query.strip()
    
    IsEmail = "@" in QueryClean
    UserName = QueryClean.split("@")[0] if IsEmail else QueryClean
    
    ProfilesFound = 0
    LogDetails = f"Target Handle: {UserName}\n"
    
    if IsEmail:
        Domain = QueryClean.split("@")[1]
        DohUrl = f"https://cloudflare-dns.com/dns-query?name={Domain}&type=MX"
        DohHeaders = {"accept": "application/dns-json"}
        try:
            DohResponse = requests.get(DohUrl, headers=DohHeaders, timeout=5)
            if DohResponse.status_code == 200:
                DohData = DohResponse.json()
                if "Answer" in DohData:
                    LogDetails += f"Email Domain {Domain} has valid MX records\n"
                else:
                    LogDetails += f"Email Domain {Domain} has no MX records\n"
        except Exception:
            LogDetails += f"Failed DNS check for domain {Domain}\n"

    MailHash = hashlib.md5(QueryClean.lower().encode("utf-8")).hexdigest()
    GravatarUrl = f"https://en.gravatar.com/{MailHash}.json"
    Headers = {"User-Agent": "Mozilla/5.0"}
    try:
        GravatarResponse = requests.get(GravatarUrl, headers=Headers, timeout=5)
        if GravatarResponse.status_code == 200:
            GravatarData = GravatarResponse.json()
            if "entry" in GravatarData and len(GravatarData["entry"]) > 0:
                Entry = GravatarData["entry"][0]
                DisplayName = Entry.get("displayName", "N/A")
                About = Entry.get("aboutMe", "N/A")
                Location = Entry.get("currentLocation", "N/A")
                LogDetails += f"Gravatar profile found for {QueryClean}\n"
                LogDetails += f"Name: {DisplayName}\n"
                LogDetails += f"Location: {Location}\n"
                LogDetails += f"About: {About}\n"
        else:
            LogDetails += "No Gravatar profile found\n"
    except Exception:
        LogDetails += "Failed to lookup Gravatar profile\n"

    Platforms = {
        "GitHub": f"https://github.com/{UserName}",
        "Linktree": f"https://linktree.com/{UserName}",
        "Reddit": f"https://www.reddit.com/user/{UserName}",
        "Pinterest": f"https://www.pinterest.com/{UserName}/",
        "Chess": f"https://api.chess.com/pub/player/{UserName}"
    }

    for Name, Url in Platforms.items():
        try:
            Response = requests.get(Url, headers=Headers, timeout=5)
            if Response.status_code == 200:
                ProfilesFound += 1
                LogDetails += f"Found profile on {Name}: {Url}\n"
            else:
                LogDetails += f"No profile found on {Name}\n"
        except Exception:
            LogDetails += f"Failed check for {Name}\n"

    DuolingoUrl = f"https://www.duolingo.com/2017-06-30/users?username={UserName}"
    try:
        DuoResponse = requests.get(DuolingoUrl, headers=Headers, timeout=5)
        if DuoResponse.status_code == 200:
            DuoData = DuoResponse.json()
            if "users" in DuoData and len(DuoData["users"]) > 0:
                ProfilesFound += 1
                LogDetails += f"Found profile on Duolingo: https://www.duolingo.com/profile/{UserName}\n"
            else:
                LogDetails += "No profile found on Duolingo\n"
        else:
            LogDetails += "No profile found on Duolingo\n"
    except Exception:
        LogDetails += "Failed check for Duolingo\n"

    RiskLevel = "Low"
    if ProfilesFound > 3:
        RiskLevel = "High"
    elif ProfilesFound > 0:
        RiskLevel = "Medium"

    return {
        "handle": UserName,
        "profiles": ProfilesFound,
        "risk": RiskLevel,
        "details": LogDetails
    }
