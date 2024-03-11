# Prerequisites

Oracle Linux 8

Python 3.9

bs4 (BeautifulSoup4)



# oscaptool.py 

This tool facilitates scanning a system with open-scap 
scanner STIG profile and shows the results in a minimalistic
format.
For Oracle Linux 8 only.

You can use this tool as follows:

oscaptool.py -s, --scan
Scans the system for rule compliance according to the openscap 
stig profile, then prints results in a minimalistic format.

oscaptool.py -l, --list
Lists previous scan reports by date.

oscaptool.py -p, --print
Lists previous scan reports by date and asks for the user to 
enter the index of one of them to print the report results.

oscaptool.py -c, --compare 
Lists previous scan reports by date and asks for the user to 
enter the index of two of them to compare the report results.

[optional -v, --verbose]
Activates verbose mode and prints logging messages into the 
console stdout.

[optional --logfile ]
Specify a file for logging



# Additional information

Log gets stored in '/usr/oscaptool/oscaptool.log'
Html reports get stored '/usr/oscaptool/html'



# Command help

usage: oscaptool.py [-h] (-s | -l | -p | -c) [-v] [--logfile LOGFILE]

Open scap operations tool. (HTML reports dir is '/usr/oscaptool/html/')

options:
  -h, --help         show this help message and exit
  -s, --scan         Execute scan and print scan report. Option '-s | --scan' no argument required.
  -l, --list         List history of executed scans. Option '-l | --list' no argument required.
  -p, --print        Print scan report list and select which report to print.Option '-p | --print' no argument
                     required.
  -c, --compare      Compare two scan reports available from the history by scan names. Option '-c | --compare' no
                     argument required.
  -v, --verbose      Print verbose output.
  --logfile LOGFILE  Specify file for logging.
