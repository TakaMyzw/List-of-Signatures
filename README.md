List-of-Signatures
==================

Listing all of threat signatures for PANW Firewall as TSV(Tab Separated Value) format.

This script obtains vulnerability/phonehome signatures from PANW Firewall and stores with TSV format.

Requirements:
PAN-OS version: 5.0 or later with Threat Prevention subscription license
PANW Firewall appliance: all, including VM series

How to use this script:
1. connect to a PANW firwall from a host run this script
2. modify credential in "params_keygen" parameter of the script
3. run this script

Output format(vulnerability):
************ begin **********
Content Version : xxx-xxxx
Release Date : YYYY/MM/DD  HH:MM:SS
Total number of signatures : XXXX
-----
id	name	severity	category	default-action	affected-host	cve#	vendorID	description
30003	Microsoft Windows DCOM RPC Interface Buffer Overrun Vulnerability........
.......
..
************  end  **********

Note:
- This script may take more than 10 minute as it obtains all of descriptions which can only be gotten by "operational" command of API.
