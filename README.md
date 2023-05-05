# Indicators-Enrichment

 Enrich List Of Indicators (IOCs) Using Commercial Threat Intelligence (Mandiant, CrowdStrike).

# How To Use !!!
 1- Run CMD with ---> "pip install -r requirements.txt".
 
 2- Insert Your API Keys for Mandiant & CrowdStrike in the begining of Script.
 
 3- Insert your Indicators (IPs, Domains and URLs) that you want to enrich it in "IOCs_List.csv".
 
 4- Run the Script "Python Indicators_Enrichment.py".
 
 5- Find the enriched IOCs in "Enriched_IOCs.csv" file.

# You Can Set a Limit for Each Query from the below Variable:

  enrich_size = XX        # Insert Number Of Indicators to Enrich in Each query.

  The Maximum Size is 1000 IOC to enrich per Query.
  
  the defult in script is set to 100 IOC per Query.

# APIs
 Insert Your API Keys to Mandiant & CrowdStrike In Script:
 
 CS_api_key = ""            		   ## Insert CrowdStrike Client ID Here. 
 
 CS_api_secret = ""          		   ## Insert CrowdStrike Secret Key Here.
 
 Mandiant_api_key = ""       		  ## Insert Mandiant Public Key ID Here.
 
 Mandiant_api_secret = ""    		  ## Insert Mandiant Secret Key Here.
