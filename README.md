# Indicator Enrichment Script

This is a Python script that performs enrichment of indicators of compromise (IOCs) by querying various commercial threat intelligence feeds like (Mandiant & CrowdStrike). The script takes a list of IOCs in a CSV file as input, and outputs an enriched CSV file that includes additional information about the IOCs.

# Installation

To use the Indicator Enrichment Script, you need to have Python 3.6 or later installed on your system. You can install the required dependencies by running the following command:

 ~~~ 
   pip install -r requirements.txt 
 ~~~

This will install all the required packages including pandas, requests, and Json.

# Usage

To run the Indicator Enrichment Script, you need to provide the script with a CSV file with name (IOCs_List.csv) containing a list of IOCs. The file must have the following column:

    indicator: The IOC itself (e.g., IP address, domain name, URL, etc.).
  

The script also requires an API key for each of the threat intelligence feeds that it queries. You can obtain API keys for the various feeds by following the instructions provided on their respective websites.

# API Keys

#### Insert your API Keys in the first begining of the script as follows:

~~~
   CS_api_key = ""             ## Insert CrowdStrike Client ID Here.
   CS_api_secret = ""          ## Insert CrowdStrike Secret Key Here.
   Mandiant_api_key = ""       ## Insert Mandiant Public Key ID Here.
   Mandiant_api_secret = ""    ## Insert Mandiant Secret Key Here.
~~~

# Query Limit

#### You can set the number of enriched indicators per query from the below variable in the script:

~~~
enrich_size = X        # Insert Number Of Indicators to Enrich in Each query.
~~~
Replace 'X' with a value between (1 - 1000) as a number for inreched indicators per query. (The default value is set to 100). 

#### To run the script, use the following command:

~~~
python Indicators_Enrichment.py
~~~

#### The script will output a CSV file (Enriched_IOCs.csv) with the following columns:

    * Source: The name of the threat intelligence feed that provided the information.
    * Indicator: The IOC itself.
    * Indicator_type: The type of the IOC (e.g., IP address, domain name, URL, etc.).
    * Malicious_Confidence: The Malicious Score of this Indicator.
    * Actors: Related Actor of this Indicator (From CrowdStrike Only!).
    * Kill_Chains: The Kill Chain of this Actor (From CrowdStrike Only!).

# Contributing

If you find any issues with the Indicator Enrichment Script, please report them on the GitHub Issues page. Contributions are also welcome in the form of pull requests.



