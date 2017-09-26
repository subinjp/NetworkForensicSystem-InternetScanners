# NetworkForensicSystem-InternetScanners
## Getting Started
This project focuses on implementing a network forensic system for the analysis, manipulation and visualisation of the packets captured from the two above mentioned setups.
It then checks, if it is feasible to identify a pattern depending on the behavior of port scanners and transport layer protocols used to send the packets. Moreover, it is also important to compare the obtained results of the initial configuration with the latter
structure and check if the behavior has been changed. Analysis was achieved by selecting correct suitable metrics that were used to extract information from captured traffic.
Through correct visualisation, we could infer the relevant information from obtained
results of the analysis for further research.


Our Objectives are:

 - Analyse the packets captured using very small network telescope and
find pattern depending on behavior of port scanners

 - Compare the results from the packets captured using two different
configurations of network telescope

 - Find pattern depending on transport layer protocols used to send port scans

## Deployment
To capture packets from the network telescope:- ./packt_capt 

To detect the port scans from the captured packet:- python portscan_isp.py capture.pcap

Then run different python scripts in evalaution_visualization folder for evaluating the port scan packets detected in the previous stage.

## Additional Information
Please look at the project report or presentation to get more idea about this work. 
