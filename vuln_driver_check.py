import subprocess
import requests
from requests.exceptions import ConnectionError, RequestException
from bs4 import BeautifulSoup
import time
import sys
import re

def welcome():
    print('''
  ___    __      ______            ________       _____                        ______________            ______
  __ |  / /___  ____  /______      ___  __ \_________(_)__   ______________    __  ____/__  /_______________  /__
  __ | / /_  / / /_  /__  __ \     __  / / /_  ___/_  /__ | / /  _ \_  ___/    _  /    __  __ \  _ \  ___/_  //_/
  __ |/ / / /_/ /_  / _  / / /     _  /_/ /_  /   _  / __ |/ //  __/  /        / /___  _  / / /  __/ /__ _  ,<
  _____/  \__,_/ /_/  /_/ /_/      /_____/ /_/    /_/  _____/ \___//_/         \____/  /_/ /_/\___/\___/ /_/|_|
  -------------------------------------------------------------------------------------------------------------
                           {GitHub:https://github.com/RogueCyberSecurityChannel}''')

def web_scrape_and_process(url, class_to_scrape):
    extracted_data = []
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        elements_with_class = soup.find_all(class_= class_to_scrape)
        for element in elements_with_class:
            extracted_data.append(element.text)
    return extracted_data

def lol_vulnerable_driver_parser(data):
    driver_list =  []
    for line in data:
        drivers = line.split()
        for driver in drivers:
            if driver.endswith('.sys'):
                driver_list.append(driver [:-4])
    return driver_list

def lol_hash_parser(data):
    hash_list =  []
    pattern = r'[a-fA-F0-9]{64}'
    for line in data:
        raw_hash = re.findall(pattern, line)
        hash = ''.join(raw_hash)
        if len(hash):
            hash_list.append(hash)
    return hash_list

def microsoft_driver_parser(data):
    driver_list = []
    for line in data:
        drivers = line.split()
        for driver in drivers:
            if 'FileName' in driver:
                driver_list.append(driver[10:])
        final_driver_list = []
        for driver in driver_list:
                if '.'  or '\"'in driver:
                    index = driver.find('.')
                    final_driver_list.append(driver[:index])
                else:
                    final_driver_list.append(driver)
    return final_driver_list[2:]

def windows_hash_parser(data):
    hash_list = []
    for line in data:
        hashes = line.split()
        for hash in hashes:
            if 'Hash' in hash:
                hash_list.append(hash[6:])
    for hash in hash_list:
        if len(hash) == 0:
            hash_list.remove(hash)
    hash_list_2 = []
    for hash in hash_list:
        if '\"' in hash:
            index = hash.find("\"")
            hash_list_2.append(hash[:index])
        else:
            hash_list_2.append(hash)
    lower_case_hashes = [hash.lower() for hash in hash_list_2]
    hash_list = lower_case_hashes
    return hash_list

def query_and_parse_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        driver_names =  [line.split() [0] for line in output_lines if line.strip()]
        return driver_names [2:]
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def lists_to_dict(keys, values):
    return dict(zip(keys, values))

def driver_path_finder(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        paths = []
        for i, s in enumerate(output_lines):
            for index in range(len(s) - len('C:') + 1):
                if s[index:index + len('C:')] == 'C:':
                    path = output_lines[i][index:]
                    paths.append(path)
        return paths
    except subprocess.CalledProcessError as e:
        print(f"  [-] Error executing driverquery command: {e}")
        return ""

def hash_host_drivers(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        driver_hash = output_lines[1]
        return driver_hash
    except subprocess.CalledProcessError:
        pass

def find_matches(driver_list_1, driver_list_2):
    set1 = set(driver_list_1)
    set2 = set(driver_list_2)
    matches = list(set1.intersection(set2))
    return matches

def display(matching_drivers):

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
        print('  [*] Get-WmiObject Win32_PnPSignedDriver | Select-Object -Property DeviceName, DriverVersion ; Get-WmiObject Win32_PnPEntity | Where-Object { $_.DeviceID -like "PCI\VEN_*" } | Select-Object -Property Name, DriverVersion')

        time.sleep(2)
        print(f'  [*] Use a 3rd party to verify host driver hash and act accordingly')

        time.sleep(2)
    else:
        print(f'  [+] No vulnerable drivers detected on your machine')

def main():
    welcome()
    time.sleep(1)

    try:
        print(f'  \n  [+] Querying host drivers')
        time.sleep(2)

        host_drivers = query_and_parse_host_drivers('driverquery /v')

        print(f'  [+] Hashing all local system drivers')
        time.sleep(2)

        host_driver_paths = driver_path_finder('driverquery /FO list /v')
        host_driver_hashes = []

        for path in host_driver_paths:
            driver_hash = hash_host_drivers( f'certutil -hashfile {path} SHA256')
            host_driver_hashes.append(driver_hash)

        hash_dictionary = lists_to_dict(host_driver_hashes, host_drivers)

        print(f'  [+] Web scraping updated vulnerable driver list & corresponding SHA 256 hashes from https://www.loldrivers.io')
        time.sleep(2)

        data = web_scrape_and_process('https://www.loldrivers.io','row')
        lol_vuln_driver_list = lol_vulnerable_driver_parser(data)
        lol_driver_hashes = lol_hash_parser(data)

        print(f'  [+] Web scraping updated vulnerable driver list & corresponding SHA 256 hashes from https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules')
        time.sleep(2)

        data = web_scrape_and_process('https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules','lang-xml')
        windows_vuln_driver_list = microsoft_driver_parser(data)
        windows_hashes = windows_hash_parser(data)

        print(f'  [*] Checking vulnerable drivers through name matching & hash based detection')
        time.sleep(2)

        matching_lol_drivers = find_matches(lol_vuln_driver_list, host_drivers)
        matching_lol_hashes = find_matches(lol_driver_hashes, host_driver_hashes)

        matching_windows_drivers = find_matches(windows_vuln_driver_list, host_drivers)
        matching_windows_hashes = find_matches(windows_hashes, host_driver_hashes)

        matching_drivers = []

        if len(matching_lol_drivers):
            for driver in matching_lol_drivers:
                matching_drivers.append(driver)
        if len(matching_windows_drivers):
            for driver in matching_windows_drivers:
                matching_drivers.append(driver)
        if len(matching_lol_hashes):
            print(f'  [!] HASH BASED DETECTION')
            time.sleep(2)
            for hash in matching_lol_hashes:
                driver = hash_dictionary[hash]
                matching_drivers.append(driver)
        if len(matching_windows_hashes):
            print(f'  [!] HASH BASED DETECTION')
            time.sleep(2)
            for hash in matching_windows_hashes:
                driver = hash_dictionary[hash]
                matching_drivers.append(driver)

    except (ConnectionError, RequestException) as e:
        time.sleep(1)
        print(f'  [-] An error occurred while trying to establish a secure connection. Please check your internet connection and try again later.\n')
        sys.exit(1)

    except Exception as e:
        print(str(e))
        sys.exit(1)

    display(matching_drivers)

if __name__ == "__main__":
    main()
