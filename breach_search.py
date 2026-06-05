import requests
from typing import Any, Dict

def search_breaches(query: str) -> Dict[str, Any]:
    Email = query.strip()
    # Building API URL 
    Url = f"https://api.xposedornot.com/v1/check-email/{Email}"
    
    try:
        # Calling the api
        Response = requests.get(Url, timeout=10)
        
        if Response.status_code == 200: # Successful response - databreaches were found
            Data = Response.json()
            BreachesList = Data.get("breaches", [])
            Count = len(BreachesList)
            
            # Prasing details about the leaked data
            ExposedData = ""
            PassDetails = Data.get("SearchPassDetails", {})
            if isinstance(PassDetails, dict):
                ExposedData = PassDetails.get("exposed_data", "")
            
            # Building the log to be able to provide it to the user
            LogDetails = f"Breaches found for {Email}: {Count}\n"
            if ExposedData:
                LogDetails += f"Exposed Data: {ExposedData}\n"
            
            # Formatting the list
            for Idx, Breach in enumerate(BreachesList, 1):
                if isinstance(Breach, dict):
                    Name = Breach.get("breach", "Unknown")
                    LogDetails += f"{Idx}. {Name}\n"
                elif isinstance(Breach, list) and len(Breach) > 0:
                    LogDetails += f"{Idx}. {Breach[0]}\n"
                else:
                    LogDetails += f"{Idx}. {str(Breach)}\n"
            
            ResultTypes = ExposedData if ExposedData else "Exposed Accounts"
            
            # Return results
            return {
                "count": Count,
                "types": ResultTypes,
                "details": LogDetails
            }
            
        elif Response.status_code == 404: # Email is clean, no databreaches
            return {
                "count": 0,
                "types": "None",
                "details": f"No breaches found for {Email}"
            }
            
        else: # An API status code that we didn't account for 
            return {
                "count": 0,
                "types": "Error",
                "details": f"Error: API status code {Response.status_code}"
            }
            
    except requests.exceptions.RequestException as E: # Handle connection errors
        return {
            "count": 0,
            "types": "Error",
            "details": f"Error: Connection failed: {str(E)}"
        }

# Script is ran in the CLI
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2: # User forgot to enter the email
        print("Usage: python breach_search.py <email>")
        sys.exit(1)
    TargetEmail = sys.argv[1]
    ResultVal = search_breaches(TargetEmail)
    print(ResultVal["details"])
