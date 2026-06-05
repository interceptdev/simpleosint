import requests
from typing import Any, Dict

def search_breaches(query: str) -> Dict[str, Any]:
    # We clean up the user input to avoid sending trailing spaces to the API
    Email = query.strip()
    # Building the request URL for XposedOrNot because it is free and does not require an API key
    Url = f"https://api.xposedornot.com/v1/check-email/{Email}"
    
    try:
        # We wrap the API call in try-except to handle network timeouts and keep the tool from crashing
        Response = requests.get(Url, timeout=10)
        
        # Successful request means the email is pwned and we need to parse the JSON payload
        if Response.status_code == 200:
            Data = Response.json()
            # Grabbing the list of breaches to count how many times this email has been leaked
            BreachesList = Data.get("breaches", [])
            # XposedOrNot returns breaches in a nested list format: [["Breach1", "Breach2", ...]]
            if len(BreachesList) == 1 and isinstance(BreachesList[0], list):
                BreachesList = BreachesList[0]
            Count = len(BreachesList)
            
            # Parsing SearchPassDetails to summarize what type of data was leaked like passwords or IPs
            ExposedData = ""
            PassDetails = Data.get("SearchPassDetails", {})
            if isinstance(PassDetails, dict):
                ExposedData = PassDetails.get("exposed_data", "")
            
            # Creating a simple, human-readable text log of the breaches to show in CLI
            LogDetails = f"Breaches found for {Email}: {Count}\n"
            if ExposedData:
                LogDetails += f"Exposed Data: {ExposedData}\n"
            
            # Formatting the list by looping over the breaches to print them one by one
            for Idx, Breach in enumerate(BreachesList, 1):
                if isinstance(Breach, dict):
                    Name = Breach.get("breach", "Unknown")
                    LogDetails += f"{Idx}. {Name}\n"
                elif isinstance(Breach, list) and len(Breach) > 0:
                    LogDetails += f"{Idx}. {', '.join(map(str, Breach))}\n"
                else:
                    LogDetails += f"{Idx}. {str(Breach)}\n"
            
            ResultTypes = ExposedData if ExposedData else "Exposed Accounts"
            
            # Returning a standard dict so that the CLI printing block can display it easily
            return {
                "count": Count,
                "types": ResultTypes,
                "details": LogDetails
            }
            
        # API returns 404 if the email is clean, which is a success for the user
        elif Response.status_code == 404:
            return {
                "count": 0,
                "types": "None",
                "details": f"No breaches found for {Email}"
            }
            
        # Catching other status codes (e.g. 500 server error) to show the API failed
        else:
            return {
                "count": 0,
                "types": "Error",
                "details": f"Error: API status code {Response.status_code}"
            }
            
    # Catching connection/timeout errors if the user has no internet access
    except requests.exceptions.RequestException as E:
        return {
            "count": 0,
            "types": "Error",
            "details": f"Error: Connection failed: {str(E)}"
        }

# Entrypoint for running the file directly from CLI
if __name__ == "__main__":
    import sys
    # Checks if user provided the email argument, otherwise exits with usage info
    if len(sys.argv) < 2:
        print("Usage: python breach_search.py <email>")
        sys.exit(1)
    TargetEmail = sys.argv[1]
    ResultVal = search_breaches(TargetEmail)
    print(ResultVal["details"])
