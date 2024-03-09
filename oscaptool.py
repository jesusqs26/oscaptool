#!/usr/bin/python3
#
#   Open scap tool
#   by: jesusq
#
# 02/28/24 jqs Create script
# 03/05/24 jqs Make the code OOP
# 03/07/24 jqs Add logging to the script
import os
from pathlib import Path
import sys
import subprocess
import argparse
import datetime
import logging
from bs4 import BeautifulSoup


# Declare global variables
VERBOSE = False


# Class for accesing to the available reports information
class OscapReport:
    '''
    Scans the system with the open scap CLI tool with a STIG profile and extracts the reports information
    '''
    def __init__(self, file_path: str=""):
        '''
        Class constructor
        Args:
            -file_path(optional): If html report already exists, specify its path
        '''
        self.summary = {}
        self.rule_results = []
        self.date = str(datetime.datetime.now())
        self.date = self.date.replace(" ","_")
        self.file_path = ""
        if file_path:
            self.file_path = file_path
        else:
            self.create_scan_report() # Creates a report html file and sets it as self.file_path
        self.get_scan_results() # Populates self.summary dict and self.rule_results



    def create_scan_report(self):
        '''
        Scans the system with open-scap STIG profile. This generates an html report.
        '''

        file_name = "scan{0}".format(self.date)
        
        xml_file = "/tmp/oscap-results/{0}.xml".format(file_name)
        html_file = "/tmp/oscap-results/html/{0}.html".format(file_name)
        self.file_path = html_file
        if(os.path.isfile(xml_file) or os.path.isfile(html_file)):
            log("There is already a scan report with the same name. \
                Try again with a different name.")
            sys.exit(rc)
        
        print("Executing open-scap security scan with stig profile...")
        rc, out, err = run_cmd(f"oscap xccdf eval  --profile xccdf_org.ssgproject.content_profile_stig \
                                --fetch-remote-resources \
                                --results {xml_file} \
                                --report {html_file} \
                                --cpe /usr/share/xml/scap/ssg/content/ssg-ol8-cpe-dictionary.xml \
                                /usr/share/xml/scap/ssg/content/ssg-ol8-xccdf.xml")
        # Specifically 1 because 2 means scan went well but there is lack of compliance
        if rc == 1:
            log("Something went wrong while executing open-scap. Aborting...",'ERROR')
            sys.exit(rc)


    def get_scan_results(self):
        '''
        Get scan results from the existing report (self.summary and self.rule_results)
        '''
        html = open(self.file_path,'r')
        soup = BeautifulSoup(html, 'html.parser')
        summary = soup.find_all('div', attrs={'class':"progress-bar"})


        # Parses de html, get the required values and clean them
        self.summary = {
            "date":self.date,
            "passed":clean_numbers(summary[0].text),
            "failed":clean_numbers(summary[1].text),
            "other":clean_numbers(summary[2].text),
            "sev_high":clean_numbers(summary[6].text),
            "sev_medium":clean_numbers(summary[5].text),
            "sev_low":clean_numbers(summary[4].text),
            "sev_other":clean_numbers(summary[3].text),
            "score":clean_numbers(summary[8].text,'float')
        }
        rule_results_soup = soup.findAll('tr',attrs={'class':"rule-overview-leaf"})
        rule_results = list()
        for e in rule_results_soup:
            rule = e.td.a.text
            severity = e.find('td',attrs={'class':"rule-severity"}).text
            result = e.find('td',attrs={'class':"rule-result"}).text
            rule_results.append({'Rule':rule,'Severity':severity,'Result':result})
        self.rule_results = rule_results
        
    def print_report(self):
        '''
        Prints the report results to the screen output
        '''    
        summary_format = """
        ===========================================================
                Open-scap scan results with stig profile
        ===========================================================

        Date: {date}

        Rule Results:

                Passed   Failed   Other
                {passed}        {failed}        {other} 
        Severity of failed rules ----------------------------------

        High    {sev_high}
        Medium  {sev_medium}
        Low     {sev_low}
        Other   {sev_other}


        Score           {score}%

        ------------------------------------------------------------
        """.format(date=self.summary['date'],passed=self.summary['passed'], failed=self.summary['failed'], other=self.summary['other'],
        sev_high=self.summary['sev_high'],sev_medium=self.summary['sev_medium'],sev_low=self.summary['sev_low'],sev_other=self.summary['sev_other'],score=self.summary['score'])
        print(summary_format)
        for e in self.rule_results:
            print(f"Rule: {e['Rule']}")
            print(f"Severity: {e['Severity']}")
            print(f"Result: {e['Result']}")
            print("""
            ------------------------------------------------------------
            """)


    def print_report_compare(self, report2):
        '''
        Compares its OscapReport instance to a different report results and prints comparation results to the screen output
        Args:
            - report2(OscapReport object): Report to compare with 
        '''
        diff_msgs = dict()
        passed_dif = self.summary['passed'] - report2.summary['passed']
        if passed_dif > 0:
            diff_msgs['passed'] = "Second results show {0} less passed rules than the first one.".format(abs(passed_dif))
        elif passed_dif < 0:
            diff_msgs['passed'] = "Second results show {0} more passed rules than the first one.".format(abs(passed_dif))
        else:
            diff_msgs['passed'] = "Both results show same number of passed rules."

        failed_dif = self.summary['failed'] - report2.summary['failed']
        if failed_dif > 0:
            diff_msgs['failed'] = "Second results show {0} less failed rules than the first one.".format(abs(failed_dif))
        elif failed_dif < 0:
            diff_msgs['failed'] = "Second results show {0} more failed rules than the first one.".format(abs(failed_dif))
        else:
            diff_msgs['failed'] = "Both results show same number of failed rules."

        other_dif = self.summary['other'] - report2.summary['other']
        if other_dif > 0:
            diff_msgs['other'] = "Second results show {0} less rules in the other category than the first one.".format(abs(other_dif))
        elif other_dif < 0:
            diff_msgs['other'] = "Second results show {0} more rules in the other category than the first one.".format(abs(other_dif))
        else:
            diff_msgs['other'] = "Both results show same number of rules in the other category."

        sev_other_dif = self.summary['sev_other'] - report2.summary['sev_other']
        if sev_other_dif > 0:
            diff_msgs['sev_other'] = "Second results show {0} less rules with severity 'other' than the first one.".format(abs(other_dif))
        elif sev_other_dif < 0:
            diff_msgs['sev_other'] = "Second results show {0} more rules with severity 'other' than the first one.".format(abs(other_dif))
        else:
            diff_msgs['sev_other'] = "Both results show same number of rules with severity 'other'."

        sev_high_dif = self.summary['sev_high'] - report2.summary['sev_high']
        if sev_high_dif > 0:
            diff_msgs['sev_high'] = "Second results show {0} less rules with severity 'high' than the first one.".format(abs(other_dif))
        elif sev_high_dif < 0:
            diff_msgs['sev_high'] = "Second results show {0} more rules with severity 'high' than the first one.".format(abs(other_dif))
        else:
            diff_msgs['sev_high'] = "Both results show same number of rules with severity 'high'."

        sev_medium_dif = self.summary['sev_medium'] - report2.summary['sev_medium']
        if sev_medium_dif > 0:
            diff_msgs['sev_medium'] = "Second results show {0} less rules with severity 'medium' than the first one.".format(abs(other_dif))
        elif sev_medium_dif < 0:
            diff_msgs['sev_medium'] = "Second results show {0} more rules with severity 'medium' than the first one.".format(abs(other_dif))
        else:
            diff_msgs['sev_medium'] = "Both results show same number of rules with severity 'medium'."

        sev_low_dif = self.summary['sev_low'] - report2.summary['sev_low']
        if sev_low_dif > 0:
            diff_msgs['sev_low'] = "Second results show {0} less rules with severity 'low' than the first one.".format(abs(other_dif))
        elif sev_low_dif < 0:
            diff_msgs['sev_low'] = "Second results show {0} more rules with severity 'low' than the first one.".format(abs(other_dif))
        else:
            diff_msgs['sev_low'] = "Both results show same number of rules with severity 'low'."

        score_dif = self.summary['score'] - report2.summary['score']
        if score_dif > 0:
            diff_msgs['score'] = "Second results show {0} worse score percentage.".format(abs(other_dif))
        elif score_dif < 0:
            diff_msgs['score'] = "Second results show {0} better score percentage.".format(abs(other_dif))
        else:
            diff_msgs['score'] = "Both results show same score percentage."
        
        out = """
    ===========================================================
            Open-scap scan results differences
    ===========================================================

                Report 1[{date1}]    Report 2[{date2}]
    Rule Results:
                
    Passed          {passed1}                       {passed2}
    *{diff_msg_passed}*
    Failed          {failed1}                       {failed2}
    *{diff_msg_failed}*
    Other           {other1}                        {other2}
    *{diff_msg_other}*

    Severity of failed rules ----------------------------------

    High            {sev_high1}                     {sev_high2}
    *{diff_msg_sev_high}*
    Medium          {sev_medium1}                   {sev_medium2}
    *{diff_msg_sev_medium}*
    Low             {sev_low1}                      {sev_low1}
    *{diff_msg_sev_low}*
    Other           {sev_other1}                    {sev_other1}
    *{diff_msg_sev_other}*

    
    Score           {score1}%                       {score2}%
    *{diff_msg_score}*

    ------------------------------------------------------------
    """.format(date1=self.summary['date'],passed1=self.summary['passed'], failed1=self.summary['failed'], 
               other1=self.summary['other'],sev_high1=self.summary['sev_high'],sev_medium1=self.summary['sev_medium']
               ,sev_low1=self.summary['sev_low'],sev_other1=self.summary['sev_other'],score1=self.summary['score'],
               date2=report2.summary['date'],passed2=report2.summary['passed'], failed2=report2.summary['failed'], 
               other2=report2.summary['other'],sev_high2=report2.summary['sev_high'],sev_medium2=report2.summary['sev_medium'],
               sev_low2=report2.summary['sev_low'],sev_other2=report2.summary['sev_other'],score2=report2.summary['score'],
               diff_msg_passed=diff_msgs['passed'],diff_msg_failed=diff_msgs['failed'],diff_msg_other=diff_msgs['other'],
               diff_msg_sev_high=diff_msgs['sev_high'],diff_msg_sev_medium=diff_msgs['sev_medium'],diff_msg_sev_low=diff_msgs['sev_low'],
               diff_msg_sev_other=diff_msgs['sev_other'],diff_msg_score=diff_msgs['score'])
        print("""
    ------------------------------------------------------------
    Rule differences (from passed to failed)         
    ------------------------------------------------------------  
            """)
        
        for e in range(0,len(self.rule_results)):
            if self.rule_results[e]['Result'] == 'fail':
                if report2.rule_results[e]['Result'] == 'pass':
                    print(f"Rule: {self.rule_results[e]['Rule']}")
                    print(f"Severity: {self.rule_results[e]['Severity']}")
                    print("*First report failed the rule but second report passed it*") 
        
        print("""
    ------------------------------------------------------------
    Rule differences (from failed to passed)         
    ------------------------------------------------------------  
            """)
        for e in range(0,len(self.rule_results)):
            if self.rule_results[e]['Result'] == 'pass':
                if report2.rule_results[e]['Result'] == 'fail':
                    print(f"Rule: {self.rule_results[e]['Rule']}")
                    print(f"Severity: {self.rule_results[e]['Severity']}")
                    print("*First report passed the rule but second report failed it*")

def list_previous_reports():
    rc, out, err = run_cmd("ls /usr/oscaptool/html/")
    return out

# Function for cleaning everything that is not a number from a string
def clean_numbers(string,type="int"):
    if type == "int":
        num_string = (''.join(char for char in string if char.isdigit()))
        numbers = int(num_string)
    elif type == "float":
        num_string = (''.join(char for char in string if char.isdigit()))
        numbers = float(num_string)

    return numbers


# Run system commands and get output and err
def run_cmd(cmd: str):
    cmd_out, cmd_err = "", ""

    # Create subprocess, Run command, get out and err
    cmd_p = subprocess.Popen(cmd, executable='/bin/bash', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd_out, cmd_err = cmd_p.communicate() 
    cmd_rc = cmd_p.returncode

    out = cmd_out.decode('utf-8')

    return cmd_rc, out, cmd_err

# Configure the log for the tool
def config_log(logfile: str):
    if VERBOSE:
        logger = logging.getLogger("verbose")
        logger.setLevel("DEBUG")
    else:
        logger = logging.getLogger(__name__)
        logger.setLevel("WARNING")

    # Handling the file
    handler = logging.FileHandler(logfile)
    logger.addHandler(handler)

    logger.info(" ### Starting {0} execution - {1} ###".format(Path(__file__),datetime.datetime.now()))

    formater = logging.Formatter("%(asctime)s - %(levelname)s : %(message)s")
    handler.setFormatter(formater)

    
# Log a message, type is INFO by default
def log(msg: str, type="INFO"):
    if VERBOSE:
        logger = logging.getLogger("verbose")
        logger.setLevel("DEBUG")
    else:
        logger = logging.getLogger(__name__)
        logger.setLevel("WARNING")
    
    # # Handling the file
    # handler = logging.FileHandler(logfile)
    # # Formatter for file handler input
    # formatter = logging.Formatter("%(asctime)s - %(levelname)s : %(message)s")
    # handler.setFormatter(formatter)
    # logger.addHandler(handler)
    if type == "DEBUG":
        logger.debug(msg)
    elif type == "INFO":
        logger.info(msg)
    elif type == "WARNING":
        logger.warning(msg)
    elif type == "ERROR":
        logger.error(msg)
    elif type == "CRITICAL":
        logger.critical(msg)

# Gets command arguments
def get_args():
    # Initialize parser
    parser = argparse.ArgumentParser(description="Open scap operations tool. (HTML reports dir is '/usr/oscaptool/html/')")
    
    # Adding arguments
    parser.add_argument("-s", "--scan", action='store_true',help = "Execute scan and print scan report.")
    parser.add_argument("-l", "--list", action='store_true', help = "List history of executed scans.")
    parser.add_argument("-p", "--print", action='store_true',help = "Print scan report list and select which report to print.")
    parser.add_argument("-c", "--compare", action='store_true',help = "Compare two scan reports available from the history by scan names.")
    parser.add_argument("-v", "--verbose", action='store_true',help="Print verbose output.")
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(0)
    # Read arguments from command line
    args = parser.parse_args()

    return args
 
def op_scan():
    '''
    Function for the scan operation of the script
    '''
    report = OscapReport()
    report.print_report()
    print("CHECKPOINT")
    return 0
    

def op_list():
    '''
    Function for printing history of scan reports
    '''
    print("List of scan reports by date:")
    reports = list_previous_reports()
    if reports:
        for report in reports:
            print(report[:-5])
    else:
        print("There is no previous scan reports at the moment. To start a scan report use 'oscaptool.py -s'.")
        sys.exit(1)
    
    

def op_print():
    '''
    Function for printing a specific scan report
    '''
    print("List of scan reports by date:")
    reports = list_previous_reports()
    if reports:
        for i in range(0,len(reports)):
            print("{0}:         {1}".format(i,reports[i][:-5]))
    else:
        print("There is no previous scan reports at the moment. To start a scan report use 'oscaptool.py -s'. Aborting...")
        sys.exit(1)
    
    print("Enter the number that contains the date of the report you want to print:")
    number = input()
    while not isinstance(number,int):
        print("You entered something different than a number. Please enter a number from above:")
        number = input()
    file_path = "/usr/oscaptool/html/{0}".format(reports[number])
    result = OscapReport(file_path)
    result.print_report
    return 0

def op_compare():
    '''
    Function for printing the differences between two scan reports
    '''
    print("List of scan reports by date:")
    reports = list_previous_reports()
    if reports:
        for i in range(0,len(reports)):
            print("{0}:         {1}".format(i,reports[i][:-5]))
    else:
        print("There is no previous scan reports at the moment. To start a scan report use 'oscaptool.py -s'. Aborting...")
        sys.exit(1)
    
    print("Enter the number that contains the date of the first report you want to compare:")
    number = input()
    while not isinstance(number,int):
        print("You entered something different than a number. Please enter a number from above:")
        number = input()
    file_path = "/usr/oscaptool/html/{0}".format(reports[number])
    result1 = OscapReport(file_path)

    print("Enter the number that contains the date of the second report you want to compare:")
    number = input()
    while not isinstance(number,int):
        print("You entered something different than a number. Please enter a number from above:")
        number = input()
    file_path = "/usr/oscaptool/html/{0}".format(reports[number])
    result2 = OscapReport(file_path)

    result1.print_report_compare(result2)
    
    return 0

# Main function
def main():
    args = get_args()
    if(not os.path.isdir("/usr/oscaptool/html/")):
        run_cmd("mkdir -p /usr/oscaptool/html/")
    
    # Configure log
    logfile="/usr/oscaptool/oscaptool.log"
    config_log(logfile)

    if args.verbose:
        VERBOSE == True

    if args.scan:
        rc = op_scan()
    if args.list:
        rc = op_list()
    if args.print:
        rc = op_print()
    if args.compare:
        rc = op_compare()

    sys.exit(rc)

#### MAIN ####
if __name__ == '__main__':
    main()