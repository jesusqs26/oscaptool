#!/usr/bin/python3
'''

   = Open scap tool =
   This tool facilitates scanning a system with open-scap 
   scanner STIG profile and shows the results in a minimalistic
   format.
   For Oracle Linux 8 only.
   
   by: jesusq

 02/28/24 jqs Create script
 03/05/24 jqs Make the code OOP
 03/09/24 jqs Add logging to the script
 03/10/24 jqs Add required mutually exclusive group to arguments
 03/10/24 jqs Add function to clean xml file after scan
 03/10/24 jqs Make functions more single pourpoused by creating
                a new function for populating the difference msgs
'''
import os
import sys
import subprocess
import argparse
import datetime
import logging
from bs4 import BeautifulSoup


# Declare global variables
# Configure log
LOGFILE = "/usr/oscaptool/oscaptool.log"


# Class for accesing to the available reports information
class OscapReport:
    '''
    Scans the system with the open scap CLI tool 
    with a STIG profile and extracts the reports 
    information
    '''

    def __init__(self, file_path=None):
        '''
        Class constructor
        Args:
            -file_path(optional): If html report already exists, specify its path
        '''
        logger.debug("Initializing OscapReport object with args 'file_path=%s'",file_path)
        self.summary = {}
        self.rule_results = []
        self.date = str(datetime.datetime.now())
        self.date = self.date.replace(" ", "_")

        if file_path is None:
            self.create_scan_report()
            self.clean_extra_files()
        else:
            self.file_path = file_path  # Creates a report html file and sets it as self.file_path
        self.get_scan_results()  # Populates self.summary dict and self.rule_results

    def create_scan_report(self):
        '''
        Scans the system with open-scap STIG profile. This generates an html report.
        '''
        logger.debug("Starting function: 'create_scan_report()' from OscapReport")
        file_name = str(self.date)

        xml_file = f"/usr/oscaptool/{file_name}.xml"
        html_file = f"/usr/oscaptool/html/{file_name}.html"
        self.xml_file = xml_file
        self.file_path = html_file
        if os.path.isfile(xml_file) or os.path.isfile(html_file):
            logger.error("There is already a scan report with the same name. \
                Try again with a different name.")
            return 1
        print("Executing open-scap security scan with stig profile...")
        logger.info("Executing open-scap security scan with stig profile...")
        cmd_res = run_cmd(f"oscap xccdf eval \
                                --profile xccdf_org.ssgproject.content_profile_stig \
                                --fetch-remote-resources \
                                --results {xml_file} \
                                --report {html_file} \
                                --cpe /usr/share/xml/scap/ssg/content/ssg-ol8-cpe-dictionary.xml \
                                /usr/share/xml/scap/ssg/content/ssg-ol8-xccdf.xml")
        # Specifically 1 because 2 means scan went well but there is lack of compliance
        # This is the return code
        cmd_rc = cmd_res
        if cmd_rc == 1:
            logger.error("Something went wrong while executing open-scap. Aborting...")
            return cmd_rc
        logger.debug("Ending function: 'create_scan_report()' from OscapReport")
        return 0

    def get_scan_results(self):
        '''
        Get scan results from the existing report (self.summary and self.rule_results)
        '''
        logger.debug("Starting function: 'get_scan_results()' from OscapReport")

        logger.info("Opening '%s' file...",self.file_path)
        if not os.path.isfile(self.file_path):
            logger.error("There was a problem, the specified file wasn't found.")
            return 1
        print("Loading information from report...")
        html = open(file=self.file_path, mode='r', encoding='utf-8')
        soup = BeautifulSoup(html, 'html.parser')
        summary = soup.find_all('div', attrs={'class': "progress-bar"})

        logger.info("Finding summary of results in the html file...")

        # Parses de html, get the required values and clean them
        self.summary = {
            "date": self.date,
            "passed": clean_numbers(summary[0].text),
            "failed": clean_numbers(summary[1].text),
            "other": clean_numbers(summary[2].text),
            "sev_high": clean_numbers(summary[6].text),
            "sev_medium": clean_numbers(summary[5].text),
            "sev_low": clean_numbers(summary[4].text),
            "sev_other": clean_numbers(summary[3].text),
            "score": clean_numbers(summary[8].text, 'float')
        }

        logger.debug("self.summary=")
        logger.debug(self.summary)

        rule_results_soup = soup.findAll(
            'tr', attrs={'class': "rule-overview-leaf"})
        rule_results = []
        for e in rule_results_soup:
            rule = e.td.a.text
            severity = e.find('td', attrs={'class': "rule-severity"}).text
            result = e.find('td', attrs={'class': "rule-result"}).text
            rule_results.append(
                {'Rule': rule, 'Severity': severity, 'Result': result})
        self.rule_results = rule_results
        logger.debug("self.rule_results=")
        logger.debug(self.rule_results)
        logger.debug("Ending function: 'get_scan_results()' from OscapReport")
        return 0

    def clean_extra_files(self):
        '''
        Cleans not needed files generated by open scap scans
        '''
        logger.debug("Starting function: 'clean_extra_files()' from OscapReport")
        logger.info("Removing '%s'.",self.xml_file)
        os.remove(self.xml_file)
        logger.debug("Ending function: 'clean_extra_files()' from OscapReport")
        return 0

    def print_report(self):
        '''
        Prints the report results to the screen output
        '''
        logger.debug("Starting function: 'print_report()' from OscapReport")
        logger.info("Printing report information...")
        summary_format = f"""
        ===========================================================
                Open-scap scan results with stig profile
        ===========================================================

        Date: {self.summary['date']}

        Rule Results:

                Passed   Failed   Other
                {self.summary['passed']}        {self.summary['failed']}        {self.summary['other']} 
        Severity of failed rules ----------------------------------

        High    {self.summary['sev_high']}
        Medium  {self.summary['sev_medium']}
        Low     {self.summary['sev_low']}
        Other   {self.summary['other']}


        Score           {self.summary['score']}%

        ------------------------------------------------------------
        """
        print(summary_format)
        for e in self.rule_results:
            print(f"Rule: {e['Rule']}")
            print(f"Severity: {e['Severity']}")
            print(f"Result: {e['Result']}")
            print("""
            ------------------------------------------------------------
            """)
        logger.debug("Ending function: 'print_report()' from OscapReport")
        return 0

    def populate_report_diff_msgs(self,report2):
        '''
        Populates msgs explaining differences between two report
        results
        Args:
            -report2: Second report (compares to self)
        '''
        logger.debug("Starting function: 'populate_report_diff_msgs()' from OscapReport")
        logger.debug("Setting difference comparation messages based \
            on scan report results.")
        diff_msgs = {}
        passed_dif = self.summary['passed'] - report2.summary['passed']
        if passed_dif > 0:
            diff_msgs['passed'] = f"Second results show {abs(passed_dif)} less \
                passed rules than the first one."
        elif passed_dif < 0:
            diff_msgs['passed'] = f"Second results show {abs(passed_dif)} more \
                passed rules than the first one."
        else:
            diff_msgs['passed'] = "Both results show same number of passed rules."

        failed_dif = self.summary['failed'] - report2.summary['failed']
        if failed_dif > 0:
            diff_msgs['failed'] = f"Second results show {abs(failed_dif)} less \
                failed rules than the first one."
        elif failed_dif < 0:
            diff_msgs['failed'] = f"Second results show {abs(failed_dif)} more \
                failed rules than the first one."
        else:
            diff_msgs['failed'] = "Both results show same number of failed rules."

        other_dif = self.summary['other'] - report2.summary['other']
        if other_dif > 0:
            diff_msgs['other'] = f"Second results show {abs(other_dif)} less rules \
                in the other category than the first one."
        elif other_dif < 0:
            diff_msgs['other'] = f"Second results show {abs(other_dif)} more rules \
                in the other category than the first one."
        else:
            diff_msgs['other'] = "Both results show same number of rules in the other category."

        sev_other_dif = self.summary['sev_other'] - \
            report2.summary['sev_other']
        if sev_other_dif > 0:
            diff_msgs['sev_other'] = f"Second results show {abs(sev_other_dif)} less \
                rules with severity 'other' than the first one."
        elif sev_other_dif < 0:
            diff_msgs['sev_other'] = f"Second results show {abs(sev_other_dif)} more \
                rules with severity 'other' than the first one."
        else:
            diff_msgs['sev_other'] = "Both results show same number of rules with severity 'other'."

        sev_high_dif = self.summary['sev_high'] - report2.summary['sev_high']
        if sev_high_dif > 0:
            diff_msgs['sev_high'] = f"Second results show {abs(sev_high_dif)} less \
                rules with severity 'high' than the first one."
        elif sev_high_dif < 0:
            diff_msgs['sev_high'] = f"Second results show {abs(sev_high_dif)} more \
                rules with severity 'high' than the first one."
        else:
            diff_msgs['sev_high'] = "Both results show same number of rules with severity 'high'."

        sev_medium_dif = self.summary['sev_medium'] - \
            report2.summary['sev_medium']
        if sev_medium_dif > 0:
            diff_msgs['sev_medium'] = f"Second results show {abs(sev_medium_dif)} less \
                rules with severity 'medium' than the first one."
        elif sev_medium_dif < 0:
            diff_msgs['sev_medium'] = f"Second results show {abs(sev_medium_dif)} more \
                rules with severity 'medium' than the first one."
        else:
            diff_msgs['sev_medium'] = "Both results show same number of rules \
                with severity 'medium'."

        sev_low_dif = self.summary['sev_low'] - report2.summary['sev_low']
        if sev_low_dif > 0:
            diff_msgs['sev_low'] = f"Second results show {abs(sev_low_dif)} less \
            rules with severity 'low' than the first one."
        elif sev_low_dif < 0:
            diff_msgs['sev_low'] = f"Second results show {abs(sev_low_dif)} more \
            rules with severity 'low' than the first one."
        else:
            diff_msgs['sev_low'] = "Both results show same number of rules with severity 'low'."

        score_dif = self.summary['score'] - report2.summary['score']
        if score_dif > 0:
            diff_msgs['score'] = f"Second results show {abs(score_dif)} worse \
                score percentage."
        elif score_dif < 0:
            diff_msgs['score'] = f"Second results show {abs(score_dif)} better \
                score percentage."
        else:
            diff_msgs['score'] = "Both results show same score percentage."


        logger.debug("diff_msgs=")
        logger.debug(diff_msgs)

        logger.info("Ending function: 'populate_report_diff_msgs()' from OscapReport")
        return diff_msgs

    def print_report_compare(self, report2):
        '''
        Compares its OscapReport instance to a different 
        report results and prints comparation results to 
        the screen output
        Args:
            - report2(OscapReport object): Report to compare with 
        '''
        logger.debug("Starting function: 'print_report_compare()' from OscapReport")

        diff_msgs = self.populate_report_diff_msgs(report2=report2)

        out = f"""
    ===========================================================
            Open-scap scan results differences
    ===========================================================

        Report 1[{self.summary['date']}]    Report 2[{report2.summary['date']}]
        
    Rule Results:
                
    Passed          {self.summary['passed']}                       {report2.summary['passed']}
    *{diff_msgs['passed']}*
    Failed          {self.summary['failed']}                       {report2.summary['failed']}
    *{diff_msgs['failed']}*
    Other           {self.summary['other']}                        {report2.summary['other']}
    *{diff_msgs['other']}*

    Severity of failed rules ----------------------------------

    High            {self.summary['sev_high']}                     {report2.summary['sev_high']}
    *{diff_msgs['sev_high']}*
    Medium          {self.summary['sev_medium']}                   {report2.summary['sev_medium']}
    *{diff_msgs['sev_medium']}*
    Low             {self.summary['sev_low']}                      {report2.summary['sev_low']}
    *{diff_msgs['sev_low']}*
    Other           {self.summary['sev_other']}                    {report2.summary['sev_other']}
    *{diff_msgs['sev_other']}*

    
    Score           {self.summary['score']}%                       {report2.summary['score']}%
    *{diff_msgs['score']}*

    ------------------------------------------------------------
    """
        print(out)
        print("""
    ------------------------------------------------------------
    Rule differences (from passed to failed)         
    ------------------------------------------------------------  
            """)

        for e, rule in enumerate(self.rule_results):
            if rule['Result'] == 'fail':
                if report2.rule_results[e]['Result'] == 'pass':
                    print(f"Rule: {rule['Rule']}")
                    print(f"Severity: {rule['Severity']}")
                    print("*First report failed the rule but second report passed it*")

        print("""
    ------------------------------------------------------------
    Rule differences (from failed to passed)         
    ------------------------------------------------------------  
            """)
        for e, rule in enumerate(self.rule_results):
            if rule['Result'] == 'pass':
                if report2.rule_results[e]['Result'] == 'fail':
                    print(f"Rule: {rule['Rule']}")
                    print(f"Severity: {rule['Severity']}")
                    print("*First report passed the rule but second report failed it*")
        logger.debug("Ending function: 'print_report_compare()' from OscapReport")
        return 0

class Customlogger(logging.Logger):
    '''
    Logger for the script
    '''
    def __init__(self, name, verbose=False, log_path=None):
        '''
        Cosntructor class
        Args:
            -name: logger name
            -verbose: Verbose Mode(True/False) 
            -log_dir: Log file path
        '''
        super().__init__(name)
        self.verbose = verbose
        self.log_path = log_path
        self.stdout_handler = None
        self.file_handler = None
        self.set_up_handlers()

    def set_up_handlers(self):
        '''
        Set up the stdout handler
        '''
        self.stdout_handler = logging.StreamHandler(sys.stdout)
        self.stdout_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.stdout_handler.setFormatter(formatter)
        self.addHandler(self.stdout_handler)

        # Set up the file handler
        self.file_handler = logging.FileHandler(self.log_path)
        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(formatter)
        self.addHandler(self.file_handler)

    def disable_file_output(self):
        '''
        Disables file output
        '''
        if self.file_handler:
            self.removeHandler(self.file_handler)
            self.file_handler = None

    def enable_file_output(self):
        '''
        Enables file output
        '''
        if not self.file_handler and self.log_path:
            log_file = os.path.join(self.log_path, f'{self.name}.log')
            self.file_handler = logging.FileHandler(log_file)
            self.file_handler.setLevel(logging.INFO)
            self.addHandler(self.file_handler)

    def info(self, msg, *log_args, **log_kwargs):
        '''
        Logs info msg as info
        Args:
            -msg: Message to log
        '''
        if self.verbose:
            super().info(msg, *log_args, **log_kwargs)
        else:
            if self.file_handler:
                self.file_handler.emit(logging.LogRecord(self.name, logging.INFO,
                                                        None, None, msg, log_args, log_kwargs))

    def debug(self, msg, *log_args, **log_kwargs):
        '''
        Logs info msg as debug
        Args:
            -msg: Message to log
        '''
        if self.verbose:
            super().debug(msg, *log_args, **log_kwargs)
        else:
            if self.file_handler:
                self.file_handler.emit(logging.LogRecord(self.name, logging.INFO,
                                                        None, None, msg, log_args, log_kwargs))

    def error(self, msg, *log_args, **log_kwargs):
        '''
        Logs info msg as error
        Args:
            -msg: Message to log
        '''
        if self.verbose:
            super().error(msg, *log_args, **log_kwargs)
        else:
            if self.file_handler:
                self.file_handler.emit(logging.LogRecord(self.name, logging.INFO,
                                                        None, None, msg, log_args, log_kwargs))

    def warning(self, msg, *log_args, **log_kwargs):
        '''
        Logs info msg as warning
        Args:
            -msg: Message to log
        '''
        if self.verbose:
            super().warning(msg, *log_args, **log_kwargs)
        else:
            if self.file_handler:
                self.file_handler.emit(logging.LogRecord(self.name, logging.INFO,
                                                         None, None, msg, log_args, log_kwargs))


def list_previous_reports():
    '''
    List previous scan reports
    '''
    logger.debug("Checking reports dir '/usr/oscaptool/html/'")
    cmd_res = run_cmd("ls /usr/oscaptool/html/")
    cmd_out = str(cmd_res[1]).split()

    return cmd_out


def clean_numbers(string, num_type="int"):
    '''
    Cleans strings leaving only numbers.
    Args:
        -string: string to clean
        -type: 'float' or 'int' 
    '''
    logger.debug("Starting function: 'clean_numbers()'")
    if num_type == "int":
        num_string = (''.join(char for char in string if char.isdigit()))
        numbers = int(num_string)
    elif num_type == "float":
        num_string = (''.join(char for char in string if char.isdigit() or char == '.'))
        numbers = float(num_string)

    return numbers


def run_cmd(cmd: str):
    '''
    Runs a system command
    Returns:
        -rc: return code,
        -out: stdout
        -err: stderr
    '''
    logger.debug("Starting function: 'run_cmd() with args [{%s}]'",cmd)

    cmd_out, cmd_err = "", ""

    # Create subprocess, Run command, get out and err
    # with subprocess.Popen(cmd, executable='/bin/bash',
    #                          shell=True, stdout=subprocess.PIPE,
    #                          stderr=subprocess.PIPE) as process:
    cmd_p = subprocess.Popen(cmd, executable='/bin/bash',
                             shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    raw_out, raw_err = cmd_p.communicate()
    cmd_rc = cmd_p.returncode

    cmd_err = raw_err.decode('utf-8')
    cmd_out = raw_out.decode('utf-8')
    logger.debug("rc = [%i]",cmd_rc)

    return cmd_rc, cmd_out, cmd_err


def get_args():
    '''
    Gets command arguments
    '''
    # Initialize parser
    parser = argparse.ArgumentParser(
        description="Open scap operations tool. (HTML reports dir is '/usr/oscaptool/html/')")
    # Adding required, mutually exclusive group
    required_args = parser.add_mutually_exclusive_group(required=True)
    # Adding arguments
    required_args.add_argument("-s", "--scan", action='store_true',
                        help="Execute scan and print scan report. Option '-s \
                            | --scan' no argument required.")
    required_args.add_argument("-l", "--list", action='store_true',
                        help="List history of executed scans. Option '-l | \
                            --list' no argument required.")
    required_args.add_argument("-p", "--print", action='store_true',
                        help="Print scan report list and select which report \
                            to print.Option '-p | --print' no argument required.")
    required_args.add_argument("-c", "--compare", action='store_true',
                        help="Compare two scan reports available from the \
                            history by scan names. Option '-c | --compare' \
                            no argument required.")
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="Print verbose output.")
    parser.add_argument("--logfile",
                        help="Specify file for logging.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    # Read arguments from command line
    arguments = parser.parse_args()


    return arguments


def op_scan():
    '''
    Function for the scan operation of the script
    '''
    logger.debug("Starting function: 'op_scan()'")
    report = OscapReport(None)
    rc = report.print_report()
    return rc


def op_list():
    '''
    Function for printing history of scan reports
    '''
    logger.debug("Starting function: 'op_list()'")
    print("List of scan reports by date:")
    reports = list_previous_reports()
    logger.debug("reports=")
    logger.debug(reports)
    if reports:
        for report in reports:
            print(str(report)[:-5])
        return 0
    logger.warning("There were no previous scan reports found.")
    print("There is no previous scan reports at the moment. \
        To start a scan report use 'oscaptool.py -s'.")
    return 1


def op_print():
    '''
    Function for printing a specific scan report
    '''
    logger.debug("Starting function: 'op_print()'")
    print("List of scan reports by date:")
    reports = list_previous_reports()
    logger.debug("reports=")
    logger.debug(reports)
    if reports:
        for i, report in enumerate(reports):
            print(f"{i}:         {report[:-5]}")
    else:
        logger.warning("There is no previous scan reports at the moment. \
              To start a scan report use 'oscaptool.py -s'. Aborting...")
        return 1

    print("Enter the number that contains the date of the report you want to print:")
    number = input()
    while not number.isdigit():
        print("You entered something different than a number. \
            Please enter a number from above:")
        logger.error("You entered something different than a number. \
            Please enter a number from above:")
        number = input()

    try:
        file_path = f"/usr/oscaptool/html/{reports[int(number)]}"
        result = OscapReport(file_path)
        result.print_report()
    except IndexError:
        logger.error("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        print("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        return 1

    return 0


def op_compare():
    '''
    Function for printing the differences between two scan reports
    '''
    logger.debug("Starting function: 'op_compare()'")
    print("List of scan reports by date:")
    reports = list_previous_reports()
    logger.debug("reports=")
    logger.debug(reports)
    if reports:
        for i, report in enumerate(reports):
            print(f"{i}:         {report[:-5]}")
    else:
        print("There is no previous scan reports at the moment. \
              To start a scan report use 'oscaptool.py -s'. Aborting...")
        logger.error("There is no previous scan reports at the moment. \
              To start a scan report use 'oscaptool.py -s'. Aborting...")
        return 1

    print("Enter the number that contains the date of the first report you want to compare:")
    number = input()
    while not number.isdigit():
        print("You entered something different than a number. \
            Please enter a number from above:")
        logger.error("You entered something different than a number. \
            Please enter a number from above:")
        number = input()
    try:
        file_path = f"/usr/oscaptool/html/{reports[int(number)]}"
        result1 = OscapReport(file_path)
    except IndexError:
        logger.error("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        print("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        return 1

    print("Enter the number that contains the date of the second report you want to compare:")
    number = input()
    while not number.isdigit():
        print("You entered something different than a number. \
            Please enter a number from above:")
        logger.error("You entered something different than a number. \
            Please enter a number from above:")
        number = input()

    try:
        file_path = f"/usr/oscaptool/html/{reports[int(number)]}"
        result2 = OscapReport(file_path)
    except IndexError:
        logger.error("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        print("The number entered doesn't match with any \
            previous scan report. Try the command again and enter \
            a number from the list.")
        return 1

    result1.print_report_compare(result2)

    return 0


def main():
    '''
    Main function
    '''
    logger.info("Verifying required directories exist...")
    if not os.path.isdir("/usr/oscaptool/html/"):
        run_cmd("mkdir -p /usr/oscaptool/html/")

    if args.scan:
        op_rc = op_scan()
    if args.list:
        op_rc = op_list()
    if args.print:
        op_rc = op_print()
    if args.compare:
        op_rc = op_compare()

    return op_rc

# Variable declaration
args = get_args()

if args.logfile:
    logger = Customlogger(name=__name__,verbose=args.verbose,
                      log_path=args.logfile)
else:
    logger = Customlogger(name=__name__,verbose=args.verbose,
                      log_path=LOGFILE)

#### MAIN ####
if __name__ == '__main__':
    logger.info("##### Starting script with args: [%s] #####",sys.argv)
    RC = main()
    logger.info("##### Ending script execution with rc: [%i] #####",RC)
    sys.exit(RC)
