import subprocess
import requests
from requests.exceptions import ConnectionError, RequestException
from bs4 import BeautifulSoup
import time
import sys


def welcome():
    print('''
   ___    __      ______            ________       _____
   __ |  / /___  ____  /______      ___  __ \_________(_)__   ______________
   __ | / /_  / / /_  /__  __ \     __  / / /_  ___/_  /__ | / /  _ \_  ___/
   __ |/ / / /_/ /_  / _  / / /     _  /_/ /_  /   _  / __ |/ //  __/  /
   _____/  \__,_/ /_/  /_/ /_/      /_____/ /_/    /_/  _____/ \___//_/
  --------------------------------------------------------------------------
''')

def web_scrape_and_process(url, class_to_scrape):
    extracted_data = []
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_with_class = soup.find_all(class_= class_to_scrape)
        for element in elements_with_class:
            extracted_data.append(element.text)

    return extracted_data


def web_scrape_xml_and_process(url, element_id):
    extracted_data = []
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_with_class = soup.find_all(class_= element_id)
        for element in elements_with_class:
            extracted_data.append(element.text)

        return extracted_data

def scraped_vulnerable_driver_parser(data):
    driver_list =  []
    for line in data:
        drivers = line.split()
        for driver in drivers:
            if driver.endswith('.sys'):
                driver_list.append(driver [:-4])
    return driver_list

def microsoft_driver_parser(data):
    element_list = []
    for line in data:
        element_names = line.split()
        for element_name in element_names:
            if 'FileName' in element_name:
                element_list.append(element_name[10:])
        final_element_list = []
        for element_name in element_list:
                if '.'  or '\"'in element_name:
                    index = element_name.find('.')
                    final_element_list.append(element_name[:index])
                else:
                    final_element_list.append(element_name)
    return final_element_list[2:]

def query_and_parse_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        leftmost_words =  [line.split() [0] for line in output_lines if line.strip()]  # Extract leftmost word of non-empty lines
        return leftmost_words [2:]
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def find_matching_drivers(driver_list_1, driver_list_2):
    set1 = set(driver_list_1)
    set2 = set(driver_list_2)

    matching_drivers = list(set1.intersection(set2))
    return matching_drivers

def main():
    welcome()
    time.sleep(1)

    try:
        host_drivers = query_and_parse_host_drivers('driverquery')
        sorted_host_drivers = sorted(host_drivers)

        print(f'  [+] Querying host drivers')
        time.sleep(1)

        print(f'  [+] Web scraping updated vulnerable driver list from https://www.loldrivers.io')
        time.sleep(2)

        raw_scraped_lol_driver_data = web_scrape_and_process('https://www.loldrivers.io','row')
        scraped_and_parsed_lol_driver_data = scraped_vulnerable_driver_parser(raw_scraped_lol_driver_data)

        matching_lol_drivers = find_matching_drivers(scraped_and_parsed_lol_driver_data, sorted_host_drivers)


        data = web_scrape_xml_and_process('https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules','lang-xml')
        parsed_windows_driver_data = microsoft_driver_parser(data)
        sorted_parsed_windows_driver_data = sorted(parsed_windows_driver_data)

        print(f'  [+] Web scraping updated vulnerable driver list from https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules')
        time.sleep(2)

        matching_windows_drivers = find_matching_drivers(sorted_parsed_windows_driver_data, sorted_host_drivers)

        matching_drivers = []

        if len(matching_lol_drivers):
            matching_drivers.append(matching_lol_drivers)
        if len(matching_windows_drivers):
            matching_drivers.append(matching_windows_drivers)

    except (ConnectionError, RequestException) as e:
        time.sleep(1)

        print(f'  [-] An error occurred while trying to establish a secure connection. Please check your internet connection and try again later.\n')
        sys.exit(1)

    except Exception as e:
        print(str(e))
        sys.exit(1)

    if len(matching_drivers):
        print(f'  [!] VULNERABLE DRIVERS DETECTED')
        time.sleep(2)

        for match in matching_drivers:
            print(f'  [-] Vulnerable Driver: {match}')
            time.sleep(2)

        time.sleep(2)
        print(f'  [*] Drivers can be stopped by using the \"sc stop <driver>\" command when executed with administrative privileges')

        time.sleep(2)
        print(f'  [*] Drivers can be deleted by using the \"sc delete <driver>\" command when executed with administrative privileges')

        time.sleep(2)
        print(f'  [*] Check for false positives by verifying the version of the vulnerable driver')

        time.sleep(2)
        print(f'  [*] Run this powershell command to check all driver versions')

        time.sleep(2)
        print('  [*] Get-WmiObject Win32_PnPSignedDriver | Select-Object -Property DeviceName, DriverVersion ; Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like "PCI\VEN_*" } | Select-Object -Property Name, DriverVersion\n')

        time.sleep(2)
    else:
        print(f'  [+] No vulnerable drivers detected on your machine\n')

if __name__ == "__main__":
    main()
