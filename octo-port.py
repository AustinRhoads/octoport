#!/usr/bin/env python3
import pyfiglet
import subprocess
from termcolor import colored
import nmap
import ipaddress
import re
from datetime import datetime

#to update in bin file run from home directory:
#sudo cp ~/executable-bash/octoport/octo-port.py /usr/bin/octo-port
# OR RUN:
# update-home-tools
subprocess.call("clear", shell=True)

fig = pyfiglet.Figlet()
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535


#print("\n" + colored(pyfiglet.figlet_format("OCTOPORT", font="computer", width=120), 'magenta'))
#print("\n" + colored(pyfiglet.figlet_format("OCTOPORT", font="isometric1", width=120), 'magenta'))
print("\n" + colored(pyfiglet.figlet_format("OCTOPORT", font="poison", width=120), 'magenta'))
print("\n****************************************************************")
print("*                                                              *")
print("* Copyright of " + colored("Austin Rhoads", "green") + ", 2022                             *")
print("*                                                              *")
print("* https://www.austinrhoads-code.com                            *")
print("****************************************************************")

while True:
    ip_add_submitted = input("\nPlease enter the ip address that you wish to scan: ")

    try:
        ip_address_obj = ipaddress.ip_address(ip_add_submitted)

        print(colored("You have submitted a valid IP address.", "green"))
        break
    except:
        print("You entered an "+colored("invalid", "red")+" IP address.")

while True:
    print("Please enter the range of ports you wish to scan in the following format: <int>-<int> (example would be  20-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid: 
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

print (colored("Scanning "+ ip_add_submitted + " on ports " + port_range + " .......", "green"))

nm = nmap.PortScanner()
t1 = datetime.now()
#           |  6   |   8    |   9     |         24             |    9    |          24            | 

format_str_lengths = {
    "port": 6,
    "status": 8,
    "tcp_name": 24,
    "product": 24,
    "version": 9,
    "extra_info": 24,
    "cpe": 40
}

#127.0.0.1
print ("     _____________________________________________________________________________________________________________________________________________")
print ("    | PORT | STATUS |         SERVICE        |      PRODUCT NAME      | VERSION |       EXTRA INFO       |                   CPE                  |")
print ("    |______|________|________________________|________________________|_________|________________________|________________________________________|")

def format_port_info(info):
    full_str = "    "
    
    for attribute in info:
        att = str(info[attribute])
        info_length = len(att)
        total_length = format_str_lengths[attribute]
        front = True
        while info_length < total_length:
            
            if front:
                att = " " + att
                info_length = info_length + 1
                front = not front
            else:
                att = att + " "
                info_length = info_length + 1
                front = not front



        full_str = full_str + "|" + att
    
    return full_str + "|"



for port in range(port_min, port_max + 1):
   
    try:
        result = nm.scan(ip_add_submitted, str(port))
        #print (result)
        port_info = {
            "port": port,
            "status": (result['scan'][ip_add_submitted]['tcp'][port]['state']),
            "tcp_name": (result['scan'][ip_add_submitted]['tcp'][port]['name']),
            "product": (result['scan'][ip_add_submitted]['tcp'][port]['product']),
            "version": (result['scan'][ip_add_submitted]['tcp'][port]['version']),
            "extra_info": (result['scan'][ip_add_submitted]['tcp'][port]['extrainfo']),
            "cpe": (result['scan'][ip_add_submitted]['tcp'][port]['cpe'])
        }
        

        if port_info["status"] == "open":
            formatted_port_str = format_port_info(port_info)
            print(formatted_port_str)
            print ("    |______|________|________________________|________________________|_________|________________________|________________________________________|")
           
           
        #else:
        #    print(f"Port {port} is {port_status}")
    except:
        print (f"Cannot scan port {port}.")

t2 = datetime.now()




def get_completion_time(t1, t2):
    totaltime = t2 - t1
    timeseparater = re.compile("([0-9]+):([0-9]+):(\d+(?:\.\d+)?)")
    time_obj = timeseparater.search(str(totaltime))
    total_time = {
        "hours": time_obj.group(1),
        "minutes": time_obj.group(2),
        "seconds": time_obj.group(3)
    }

    formatted_time = ""

    for time in total_time:
        if  formatted_time != "" and time == "seconds" and float(total_time[time]) != 0:
            formatted_time = f"{formatted_time} and {total_time[time]} {time}"
        elif float(total_time[time]) != 0:
            formatted_time = f"{formatted_time} {total_time[time]} {time}"

    #print (totaltime)
    #total = re.sub('(0:0)(0:)', "", str(totaltime))
    print(colored(f"Scan completed in{formatted_time}.", "green"))

get_completion_time(t1, t2)



