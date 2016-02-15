			Cisco Firewall Risk Score Calculator Readme
				Yang Li, June 2012




What's this program for? 
"risk_calc.pl" is a program originally developed for a client during a large firewall assessment project. The tool is used to 
quantify the risk of the firewall Access Control Lists (ACLs). The calculation is based on the formula in the section below.
Specifically, it could be used to calculate the risk score of every implemented ACL in the firewall. If the score meet the 
risk threshold, the ACL entry will be flagged and printed out. 


Limitation?
Currently version (1.0) only supports Cisco firewall format: ASA,FWSM,PIX. I may add support of other type of firewalls if
needed down the road.


Why is this program? 
The program provides a mean of objective assessment of the firewall ACLs using a quantitative approach. For instance,
this tool help BT evaluate over 140,000 lines of ACLs from 271 firewalls during the short period of the engagement. This is a 
human impossible task considering the complexity and sheer amount of the calculations.


What computer language is used in the program?
PERL is used for this job, as it provides the rapid code prototyping, and a relative simple and compact function sets. 


Environment Setup?
a) You need a PERL environment. Traditionally it means a Unix/Linux box. You can also use Cygwin in Windows box. In fact, 
this program was developed in the Cygwin environment.
Before using the program, please make sure you have PERL version 5.8 and above available. You'll also need 
to download and install an important Perl module/library from CPAN "Net::CIDR". It's a core library used
by this program to perform complex network block calculation. To install this module, you need the 'root'
Privilege in the box. You could follow the instructions on the package to install it. One easy way that I use
to install it is like this:
			# perl -MCPAN -eshell
			eshell> install Net::CIDR
			...
			eshell> exit

How do I run the program?
a) You need to collect the full path of the Cisco firewall configuration files and put them in a txt file:	
	For example: 
			$ echo "/home/yang/fwa/runningAdmin.txt" > fws.txt
			$ echo "/home/yang/fwb/runningAdmin.txt" >> fws.txt
		or      $ find /home/yang -name "runningAdmin.txt" > fws.txt
b) Now unzip and set the executable bit of this program. 
			$ unzip risk_calc.pl.zip
			$ chmod +x risk_calc.pl
c) Adjust the configuration file "risk_calc.conf" for your site specific information: trusted network blocks, risky ports etc..
			$ vi ./risk_calc.conf
d) Run the program against the list of firewall configurations:
			$ ./risk_calc.pl -list ./fws.txt
e) For help:
			$ ./risk_calc.pl -help 


How do I modify the program's parameters?
For example, you can add 'ldap' as a risky service into the program by changing the program configuration file:
Use a txt editor such as 'vi' under Unix or 'wordpad' under Windows. Open the default configuration file "risk_calc.conf". 
Locate the proper field. Follow the file format to modify then save it. 


What's the risk calculation formula?
The firewall rule risk score is calculated as the total of: source address risk score + destination address risk score + 
destination port risk score. 
The following tables show the risk score penalty:
a) Source and Destination Addresses Risk Score
Description 		Source IP Risk		Destination IP Risk
Non-trusted Addresses 	Trusted Addresses 
Single Host (/32) 	0			0
/24 or higher 		15			30
/20 or higher 		25			50
/16 or higher 		35			70
"Any" 			40			80
b) Destination Port Risk Score
Description 					Destination Port Risk 
Single Port / Limited Ports 			0
Risky Ports (e.g., NetBIOS,database) 		20
Excessive Port Ranges (e.g, 1024 - 65535) 	20
All TCP or All UDP 				30
All IP 						50


Additional Features?
a) Since version 0.8, the program can also generate the Firewall ACL Consolidation Level 1-3 report, for better performance 
and risk evaluation. The consolidation could take advantage of the Cisco "object-group" feature, in order to bundle 
related ACL rules together. This feature could reduce the number of firewall ACL entries in the firewall. Thus it increases 
the manageability, performance, and the ultimate security of the firewall: 
	Level 1 - Consolidation Based On Services, by using command switch option '-consolidate 1'
	Level 2 - Consolidation Based On Source IPs, by using command switch option '-consolidate 2'
	Level 3 - Consolidation Based on Destination IPs, by using command switch option '-consolidate 3' 

b) Since version 0.9, the program can also generate the Firewall ACL loose rule report, with the following criteria:
	Loose Rule by Source - The ACL entry's source IP is unlimited 'any', by using command switch option '-loose source'                                                  
	Loose Rule by Destination - The ACL entry's destination IP is unlimited 'any', by using command switch option '-loose destination'
	Loose Rule by Service - The ACL entry's destination service port is unlimited 'any', by using command switch option '-loose service'

c) Since version 1.0, the program can also generate the unused oject report:
	Unused access-group (ACLs) in the firewall, by using command switch option '-clean access-group'                                                
	Unused object-group in the firewall, by using command switch option '-clean object-group'


How do I report the bugs?  
Contact the author at 'Yang.Li@owasp.org' 





Disclaimer:
The program is covered by Apache v2.0 license: http://www.apache.org/licenses/LICENSE-2.0




  
