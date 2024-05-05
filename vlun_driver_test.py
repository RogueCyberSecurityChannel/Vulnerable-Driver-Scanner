import os
import subprocess
import requests
from bs4 import BeautifulSoup

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

def lol_driver_grabber(data):
    driver_list = []
    for line in data:
        drivers = line.split()
        for driver in drivers:
            if driver.endswith('.sys'):
                driver_list.append(driver[:-4])
    return driver_list


def find_matches(list1, list2):
    # Convert lists to sets for faster lookup
    set1 = set(list1)
    set2 = set(list2)

    # Find the intersection of the two sets
    matches = list(set1.intersection(set2))

    return matches

def drive_grabber(input_file):
    input_file = os.path.join(os.getcwd(), input_file)
    driver_list = []
    with open(input_file, 'r') as file:
        for line in file:
            drivers = line.split()
            for driver in drivers:
                if driver.endswith('.sys'):
                    driver_list.append(driver[:-4])
    return driver_list

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        leftmost_words = [line.split()[0] for line in output_lines if line.strip()]  # Extract leftmost word of non-empty lines
        return leftmost_words[2:]
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return ""
        
if __name__ == "__main__":
    #  drivers = drive_grabber('vulndrivers.txt')
    host_drivers = execute_command('driverquery')

    driver_data = scrape_and_process()
    scraped_driver_data = lol_driver_grabber(driver_data)
    for driver in scraped_driver_data:
        print(driver)

    matches = find_matches(scraped_driver_data, host_drivers)
    for match in matches:
        print(match)

    #  sc stop <driver>
    #  sc delete <driver>
