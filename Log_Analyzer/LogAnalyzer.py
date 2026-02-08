#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# LogAnalyzer, this class reads and analyses log files, returnin an anal
#############################################################################################
from datetime import datetime
from termcolor import colored
import re
import geoip2.database
GEOIP_DB = "GeoLite2-City.mmdb"
####################################################################
# Log Analyzer Method
# @args: file, service
#
###################################################################

def log_analyzer(file, service):
    print(colored("---------- Log Analyzer ----------","green"))
    results = []
    # Open file
    try:
        with open(file, "r") as f:
            lines = f.readlines()
            for line in lines:
                datetime = get_datetime(line)
                if service == "HTTP":
                    src_ip_format = re.search(r'\bSRC=(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    dest_ip_format = re.search(r'\bDST=(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    src_country = get_country_from_ip(src_ip_format)
                    dest_country = get_country_from_ip(dest_ip_format)
                    src_city = get_city_from_ip(src_ip_format)
                    dest_city = get_city_from_ip(dest_ip_format)

                    if "[UFW BLOCK]" in line:
                        status = "Blocked"
                    elif "[UFW ALLOW]" in line:
                        status = "Allowed"
                    else:
                        status = "Unknown"
                    results.append(
                        f"SRC_IP: {src_ip_format} | SRC Country: {src_country} | SRC City: {src_city} | "
                        f"DST_IP {dest_ip_format} | DST Country: {dest_country} | DST City: {dest_city} | "
                        f"Status: {status} | Log: {line.strip()} | Date: {datetime}")

                if service == "SSH":
                    ip_format = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    ip = ip_format.group()
                    country = get_country_from_ip(ip)
                    city = get_city_from_ip(ip)
                    if "Accepted" in line:
                        status = "Acepted"
                    elif "Failed password" in line or "Invalid user" in line:
                        status = "Failed"
                    else:
                        status = "Unknown"
                    results.append(
                            f"IP: {ip} | Country: {country} | City: {city} | Status: {status} | Log: {line.strip()} | Date: {datetime}")

        print("Results:")
        for result in results:
            print(result)

    except Exception as e:
        print(colored(f"Error on Log Analyzer execution: {e}", "red"))


####################################################################
# Get City From IP Method
# @args: file, service
# ip = ip collected from file
# return -> city name, or Unknown
###################################################################
def get_city_from_ip(ip):

    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            city_result = reader.city(ip)
            return city_result.city.name
    except Exception as e:
        return "Unknown"
####################################################################
# Get Country From IP Method
# @args: ip
# return -> city name, or Unknown
###################################################################
def get_country_from_ip(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            country_result = reader.city(ip)
            return country_result.country.name
    except Exception as e:
        return "Unknown"

####################################################################
# Get time from line
# @args: line
# return -> date & time
###################################################################

def get_datetime(line):
    datetime = re.search(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b', line)
    return datetime

    '''

    results=[]
    pattern_str= r'^\d{2}-\d{2}$'
    format_date = "%m-%d"
    is_OK = False
    while not is_OK:
        start_date = input("Insert Starting Date (mm-dd):")
        if re.match(pattern_str, start_date):

            is_OK = True
        else:
            print(colored(f"Date format does not match the requested format.", "red"))

    is_OK = False

    while not is_OK:
        end_date = input("Insert Starting Date (mm-dd):")
        if re.match(pattern_str, end_date):

            is_OK = True

        else:
            print(colored(f"Date format does not match the requested format.", "red"))



    try:
        with open(file, "r") as f:
            lines = f.readlines()
            for line in lines:

                date = line[:6]
                date = date.replace(' ', '-')
                parsed_date = datetime.strptime(date, format_date)

                ip = None
                src_IP =None
                dest_ip=None

                if(service == "HTTP"):

                    src_IP = re.findall(r"SRC=[0-9]+(?:\.[0-9]+){3}", line)
                    dest_ip = re.findall(r"DST=[0-9]+(?:\.[0-9]+){3}", line)
                    print(colored(f"Dest ip = {dest_ip}, src ip= {src_IP}","green"))
                print(colored(f"Date: {parsed_date}", "green"))
                print(line)
    except Exception as e:
        print(colored(f"Error on Log Analyzer execution: {e}", "red"))
    '''