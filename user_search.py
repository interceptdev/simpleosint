# Connected Discord-GitHub
# Roblox: llntercept
# Discord: @intrcept

import hashlib
import requests
from typing import Any, Dict

def search_target(query: str) -> Dict[str, Any]:
    # We clean up input handle spaces
    QueryClean = query.strip()
    
    # Split query logic if email is inputted to scan both domain and username
    IsEmail = "@" in QueryClean
    UserName = QueryClean.split("@")[0] if IsEmail else QueryClean
    
    ProfilesFound = 0
    LogDetails = f"Target Handle: {UserName}\n"
    
    # Only run DNS checks if query is an email address
    if IsEmail:
        Domain = QueryClean.split("@")[1]
        # Using Cloudflare DNS-over-HTTPS API to check MX records since socket lacks native MX resolution
        DohUrl = f"https://cloudflare-dns.com/dns-query?name={Domain}&type=MX"
        DohHeaders = {"accept": "application/dns-json"}
        try:
            # Query Cloudflare DNS API for MX response
            DohResponse = requests.get(DohUrl, headers=DohHeaders, timeout=5)
            if DohResponse.status_code == 200:
                DohData = DohResponse.json()
                # If Answer key is in response, domain can receive emails
                if "Answer" in DohData:
                    LogDetails += f"Email Domain {Domain} has valid MX records\n"
                else:
                    LogDetails += f"Email Domain {Domain} has no MX records\n"
        except Exception:
            LogDetails += f"Failed DNS check for domain {Domain}\n"

    # Hashing the query to query Gravatar API which stores records under MD5 email hashes
    MailHash = hashlib.md5(QueryClean.lower().encode("utf-8")).hexdigest()
    GravatarUrl = f"https://en.gravatar.com/{MailHash}.json"
    Headers = {"User-Agent": "Mozilla/5.0"}
    try:
        # Requesting Gravatar profile payload
        GravatarResponse = requests.get(GravatarUrl, headers=Headers, timeout=5)
        if GravatarResponse.status_code == 200:
            GravatarData = GravatarResponse.json()
            # If entry array is returned, parse user details
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

    # Social platforms list to check handle availability using HTTP responses
    Platforms = {
        "GitHub": f"https://github.com/{UserName}",
        "Linktree": f"https://linktree.com/{UserName}",
        "Reddit": f"https://www.reddit.com/user/{UserName}",
        "Pinterest": f"https://www.pinterest.com/{UserName}/",
        "Chess": f"https://api.chess.com/pub/player/{UserName}"
    }

    # Loop to request each platform url
    for Name, Url in Platforms.items():
        try:
            # We request the profile URL and check if response is 200 OK
            Response = requests.get(Url, headers=Headers, timeout=5)
            if Response.status_code == 200:
                ProfilesFound += 1
                LogDetails += f"Found profile on {Name}: {Url}\n"
            else:
                LogDetails += f"No profile found on {Name}\n"
        except Exception:
            LogDetails += f"Failed check for {Name}\n"

    # Duolingo check uses custom API URL structure
    DuolingoUrl = f"https://www.duolingo.com/2017-06-30/users?username={UserName}"
    try:
        # Requesting Duolingo search endpoint
        DuoResponse = requests.get(DuolingoUrl, headers=Headers, timeout=5)
        if DuoResponse.status_code == 200:
            DuoData = DuoResponse.json()
            # Parsing array to check if a user with this handle matches
            if "users" in DuoData and len(DuoData["users"]) > 0:
                ProfilesFound += 1
                LogDetails += f"Found profile on Duolingo: https://www.duolingo.com/profile/{UserName}\n"
            else:
                LogDetails += "No profile found on Duolingo\n"
        else:
            LogDetails += "No profile found on Duolingo\n"
    except Exception:
        LogDetails += "Failed check for Duolingo\n"

    # Returning final dictionary object to CLI
    return {
        "handle": UserName,
        "profiles": ProfilesFound,
        "risk": "N/A",
        "details": LogDetails
    }

# Entrypoint for running the file directly from CLI
if __name__ == "__main__":
    import sys
    # Checks if user passed a search target query
    if len(sys.argv) < 2:
        print("Usage: python target_search.py <query>")
        sys.exit(1)
    TargetQuery = sys.argv[1]
    ResultVal = search_target(TargetQuery)
    print(ResultVal["details"])
