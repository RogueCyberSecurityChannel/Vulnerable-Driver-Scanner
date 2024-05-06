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

def scrape_and_process():
    extracted_data = []
    url = 'https://www.loldrivers.io'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_with_class = soup.find_all(class_='row')
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

def find_matching_drivers(driver_list_1, driver_list_2):

    set1 = set(driver_list_1)
    set2 = set(driver_list_2)

    matching_drivers = list(set1.intersection(set2))
    return matching_drivers

def query_and_parse_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        leftmost_words =  [line.split() [0] for line in output_lines if line.strip()]  # Extract leftmost word of non-empty lines
        return leftmost_words [2:]
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def main():
    welcome()
    time.sleep(1)

    try:
        host_drivers = query_and_parse_host_drivers('driverquery')
        print(f'  [+] Querying host drivers')
        time.sleep(1)

        print(f'  [+] Web scraping updated vulnerable driver list from https://www.loldrivers.io')
        time.sleep(2)

        raw_scraped_driver_data = scrape_and_process()
        scraped__and_parsed_driver_data = scraped_vulnerable_driver_parser(raw_scraped_driver_data)

        matching_drivers = find_matching_drivers(scraped__and_parsed_driver_data, host_drivers)

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
        print(f'  [*] Drivers can be deleted by using the \"sc delete <driver>\" command when executed with administrative privileges\n')

        time.sleep(2)
    else:

        time.sleep(2)
        print(f'  [+] No vulnerable drivers detected on your machine\n')

if __name__ == "__main__":
    main()
