#############################################################################################
# @Author: José Manuel Batista Galanducho
# @Número de Aluno: 13651
# LogAnalyzer, this class reads and analyses log files, returnin an anal
#############################################################################################
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from termcolor import colored
from Helper_Classes.ArgumentMaker import progress_print
import re
import geoip2.database
####################################################################
# Log Analyzer Method
# @args: file, service
#
###################################################################

def log_analyzer(file, service, output):
    print(colored("---------- Log Analyzer ----------","green"))
    results = []

    # Open file
    try:
        fase = 1
        index = 0
        with open(file, "r") as f:
            print(colored("Testing file...","green"))
            lines = f.readlines()
            total_lines = len(lines)
            for line in lines:
                if fase == 4:
                    fase = 1
                index += 1
                percentage = round(100 * (index / total_lines), 1)
                print(colored(f"\rReading {progress_print(fase)} | {percentage}% ", "green"),
                      end="")
                fase += 1
                if output != 'CSV' and output != 'PDF' and output != "CONSOLE":
                    results.append("The output value was not accepted, the output will be console by default.")
                ip_format = None
                src_ip_format = None
                dest_ip_format = None
                datetime = get_datetime(line)
                if service == "HTTP":
                    src_ip_format = re.search(r'\bSRC=(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    dest_ip_format = re.search(r'\bDST=(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)

                    if src_ip_format and dest_ip_format:
                        src_ip = src_ip_format.group().replace("SRC=", '')
                        dest_ip = dest_ip_format.group().replace("DST=", '')
                        src_country = get_country_from_ip(src_ip)
                        dest_country = get_country_from_ip(dest_ip)
                        src_city = get_city_from_ip(src_ip)
                        dest_city = get_city_from_ip(dest_ip)

                        if "[UFW BLOCK]" in line:
                            status = "Blocked"
                        elif "[UFW ALLOW]" in line:
                            status = "Allowed"
                        else:
                            status = "Unknown"
                        if output != 'CSV':
                            results.append(
                        f"SRC_IP: {src_ip_format} | SRC Country: {src_country} | SRC City: {src_city} | "
                        f"DST_IP {dest_ip_format} | DST Country: {dest_country} | DST City: {dest_city} | "
                        f"Status: {status} | Log: {line.strip()} | Date: {datetime}\n")
                        else:
                            results.append(f"{src_ip},{src_country},{src_city},{dest_ip},{dest_country},{dest_city},{status},{line.strip()},{datetime}")


                if service == "SSH":
                    ip_format = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_format:
                        ip = ip_format.group()
                        country = get_country_from_ip(ip)
                        city = get_city_from_ip(ip)
                        if "Accepted" in line:
                            status = "Acepted"
                        elif "Failed password" in line or "Invalid user" in line:
                            status = "Failed"
                        else:
                            status = "Unknown"
                        if output != 'CSV':
                            results.append(
                            f"IP: {ip} | Country: {country} | City: {city} | Status: {status} | Log: {line.strip()} | Date: {datetime}\n")
                        else:
                            results.append(f"{ip},{country},{city},{status},{line.strip()},{datetime}")

            if output == 'CSV':
                save_file_csv(results, service)
            elif output == 'PDF':
                save_file_pdf(results, service)
            else:
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
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
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
        with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
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

####################################################################
# Save Results to CSV
# @args: results, report
# return -> Operation results, success or failure
###################################################################

def save_file_csv(results, report):
    now = datetime.now()
    fase = 1
    index = 0
    total_results = len(results)
    date_time = now.strftime("%d-%m-%Y-%H-%M-%S")
    output_file = f"{report}_{date_time}.csv"
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("IP,Country,City,Status,Log,Date\n")
        print(colored("\nSaving file...", "green"))
        for result in results:
            if fase == 4:
                fase = 1
            index += 1
            percentage = round(100 * (index / total_results), 1)
            print(colored(f"\rRecording {progress_print(fase)} | {percentage}% ", "green"),
                  end="")
            fase += 1
            file.write(result + "\n")
    print(colored(f"\nResults saved to {output_file}", "green"))

####################################################################
# Save Results to PDF
# @args: results, report
# return -> Operation results, success or failure
###################################################################

def save_file_pdf(results, report):
    LINE_WIDTH= 80
    fase = 1
    index = 0
    total_results = len(results)
    now = datetime.now()
    date_time = now.strftime("%d-%m-%Y-%H-%M-%S")
    output_file = f"{report}_{date_time}.pdf"
    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter
    c.setFont("Times-Roman", 18)
    c.drawCentredString(width / 2.0, height - 40, f"Log Analysis for {report}")
    c.drawCentredString(width / 2.0, height - 40, f"")
    c.setFont("Times-Roman", 12)
    y_position = height - 60
    print(colored("\nSaving file...","green"))
    for result in results:
        if fase == 4:
            fase = 1
        index += 1
        percentage = round(100 * (index / total_results), 1)
        print(colored(f"\rRecording {progress_print(fase)} | {percentage}% ", "green"),
              end="")
        fase += 1
        if y_position < 60:
            c.showPage()
            c.setFont("Times-Roman", 12)
            y_position = height - 60
        for line in result.split(" | "):
            if y_position < 60:
                c.showPage()
                c.setFont("Helvetica", 12)
                y_position = height - 30
            # wrap text if too long
            if len(line) > LINE_WIDTH:
                # split long lines into multiple lines of width PDF_LINE_WIDTH
                for i in range(0, len(line), LINE_WIDTH):
                    c.drawString(30, y_position, line[i:i + LINE_WIDTH])
                    if line[i + LINE_WIDTH:]:
                        y_position -= 15
            else:
                c.drawString(30, y_position, line)
            # move to next line
            y_position -= 15

            # move to next line
        y_position -= 15

    c.save()
    print(colored(f"\nResults saved to {output_file}", "green"))

