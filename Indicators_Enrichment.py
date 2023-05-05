import base64
import requests
import csv
import json
import colorama
from colorama import Fore

######################################################### APIs ##############################################################################

CS_api_key = ""             ## Insert CrowdStrike Client ID Here.
CS_api_secret = ""          ## Insert CrowdStrike Secret Key Here.
Mandiant_api_key = ""       ## Insert Mandiant Public Key ID Here.
Mandiant_api_secret = ""    ## Insert Mandiant Secret Key Here.

########################################## CrowdStrike Auth Generate Bearer Token Script ####################################################

CS_auth_url = "https://api.crowdstrike.com/oauth2/token"
CS_auth_token_bytes = f"{CS_api_key}:{CS_api_secret}".encode("ascii")
CS_base64_auth_token_bytes = base64.b64encode(CS_auth_token_bytes)
CS_base64_auth_token = CS_base64_auth_token_bytes.decode("ascii")

CS_auth_headers = {

    "Authorization": f"Basic {CS_base64_auth_token}",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    "X-App-Name": "insert app name",
}

CS_auth_params = {

    "grant_type": "client_credentials", 
    "scope": ""
}

CS_access_token = requests.post(url=CS_auth_url, headers=CS_auth_headers, data=CS_auth_params)
#print(CS_access_token)
CS_token = CS_access_token.json()
#print(CS_token)
CS_token_type = CS_token.get("token_type")
#print (CS_access_token.json().get("token_type"))
CS_token_key = CS_token.get("access_token")
#print(CS_access_token.json().get("access_token"))
CS_access = CS_token_type + " " + CS_token_key       # Bearer Token
#print(CS_access)
if CS_access_token.status_code == 201:
    print(Fore.GREEN + "CrowdStrike Access Token Generated Successfully !!!")
else:
    print (Fore.RED + f"RROR While Generating CrowdStrike Access Token !!! \n Response Code = {CS_access_token.status_code}")

########################################################## END Of CrowdStrike Auth Script ################################################

########################################## Mandiant Auth Generate Bearer Token Script ####################################################

Mandiant_auth_url = "https://api.intelligence.mandiant.com/token"
Mandiant_auth_token_bytes = f"{Mandiant_api_key}:{Mandiant_api_secret}".encode("ascii")
Mandiant_base64_auth_token_bytes = base64.b64encode(Mandiant_auth_token_bytes)
Mandiant_base64_auth_token = Mandiant_base64_auth_token_bytes.decode("ascii")

Mandiant_auth_headers = {

    "Authorization": f"Basic {Mandiant_base64_auth_token}",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    "X-App-Name": "insert app name",
}

Mandiant_auth_params = {

    "grant_type": "client_credentials", 
    "scope": ""
}

Mandiant_access_token = requests.post(url=Mandiant_auth_url, headers=Mandiant_auth_headers, data=Mandiant_auth_params)
Mandiant_token = Mandiant_access_token.json()
# print(cs_token)
Mandiant_token_type = Mandiant_token.get("token_type")
# print (access_token.json().get("token_type"))
Mandiant_token_key = Mandiant_token.get("access_token")
# print(access_token.json().get("access_token"))
Mandiant_access = Mandiant_token_type + " " + Mandiant_token_key       # Bearer Token
#print(Mandiant_access)
if Mandiant_access_token.status_code == 200:
    print(Fore.GREEN + "Mandiant Access Token Generated Successfully !!!")
else:
    print (Fore.RED + f"RROR While Generating Mandiant Access Token !!! \n Response Code = {Mandiant_access_token.status_code}")

########################################################## END Of Mandiant Auth Script #################################################


########################################################## CrowdStrike Enrichment Script ###############################################

CS_enrich_url = "https://api.crowdstrike.com/intel/combined/indicators/v1"

CS_enrich_headers = {

    "Authorization": f"{CS_access}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

####################################################### End Of CrowdStrike Enrichment Script #############################################

########################################################## Mandiant Enrichment Script ####################################################

Mandiant_enrich_url = "https://api.intelligence.mandiant.com/v4/indicator"

Mandiant_enrich_headers = {
 #"Authorization": "Bearer 6157d26949ef3f8d2e889fe0f9f9ed362aae5bae2ef1efaa016159bf6fe50f29",
 "Authorization": f"{Mandiant_access}",
 "Accept": "application/json",
 "X-App-Name": "Python",
 "Content-Type": "application/json"
}

########################################################## End Of Mandiant Enrichment Script ###############################################

######################################################### Common Variables & Functions #####################################################

# Define Input & Output files for Enrichment.
output_file = "Enriched_IOCs.csv"
input_file = "IOCs_List.csv"

# Create Output CSV File with defined coloums.
with open(output_file, "a", newline="") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(
        [
            "Source",
            "Indicator",
            "Type",
            "Malicious_Confidence",
            "Actors",
            "Kill_Chains",
            "Threat_Types",
        ]
    )

# Read IOCs From Input File to Enrich it.
with open(input_file, mode="r") as csvfile:
    query_reader = csv.reader(csvfile)
    next(query_reader)       # skip Header row
    ioc_list = [row[0] for row in query_reader]
    enrich_size = 100        # Insert Number Of Indicators to Enrich in Each query.
    for i in range(0, len(ioc_list), enrich_size):
        batch = ioc_list[i : i + enrich_size]
        q = ", ".join(batch) # combine batch of indicators with comma separeted and space
        print(Fore.YELLOW + f"Enriching indicators for query: {q}")

        CS_enrich_params = {

            "limit": "10000", 
            "q": f"{q}"
        }

        Mandiant_post_body = {
        "requests": [
         {
         "values": batch
         }
         ]
        }

        CS_enrich = requests.get(url=CS_enrich_url, headers=CS_enrich_headers, params=CS_enrich_params)  # Get Request for CrowdStrike Enrichment.
        CS_enrich_data = CS_enrich.json()
        print(Fore.BLUE + f"{CS_enrich_data}")
        Mandiant_enrich = requests.post(url=Mandiant_enrich_url, headers=Mandiant_enrich_headers, data=json.dumps(Mandiant_post_body)) # Post Request for Mandiant Enrichment.
        Mandiant_enrich_data = Mandiant_enrich.json()
        print (Fore.MAGENTA + f"{Mandiant_enrich_data}")
        with open(output_file, "a", newline="") as outfile:
            writer = csv.writer(outfile)
            for resource in CS_enrich_data["resources"]:
                row = [
                    "CrowdStrike",
                    resource.get("indicator", ""),
                    resource.get("type", ""),
                    resource.get("malicious_confidence", ""),
                    "|".join(resource.get("actors", [])),
                    "|".join(kc for kc in resource.get("kill_chains", [])),
                    "|".join(tt for tt in resource.get("threat_types", [])),
                ]
                writer.writerow(row)

            for resource in Mandiant_enrich_data["indicators"]:
                row = [
                    "Mandiant",
                    resource.get("value", ""),
                    resource.get("type", ""),
                    resource.get("mscore", ""),
                ]
                writer.writerow(row)
                
print(Fore.GREEN + "Enrichment Completed Successfully !! \n You Can Find The Output in Enriched_IOCs.csv")
print(Fore.RED + "By: Hassan Nasr !!")