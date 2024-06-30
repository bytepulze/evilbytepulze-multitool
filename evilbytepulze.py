import os
import nmap
import json
import socket
import requests
import subprocess
from pystyle import *
from colorama import *

e = f"    {Fore.LIGHTBLACK_EX}[{Fore.MAGENTA}-{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
s = f"    {Fore.LIGHTBLACK_EX}[{Fore.MAGENTA}+{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
q = f"    {Fore.LIGHTBLACK_EX}[{Fore.MAGENTA}?{Fore.LIGHTBLACK_EX}]{Fore.RESET}"

## Daddy BytePulze

pid = os.getpid()
login = os.getlogin()

def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024')
        port_data = {}
        for proto in nm[ip].all_protocols():
            port_data[proto] = nm[ip][proto]
        return port_data
    except Exception as e:
        return {"error": str(e)}

def ip_lookup(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def simple_ping(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "4", ip])
        return output.decode()
    except Exception as e:
        return {"error": str(e)}

def tcp_ping(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {"status": "open" if result == 0 else "closed"}
    except Exception as e:
        return {"error": str(e)}

def traffic_check(ip):
    try:
        response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_API_KEY&ip={ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def multi_ping(ips):
    results = {}
    for ip in ips:
        results[ip] = simple_ping(ip)
    return results

def ip3(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return {"hostname": hostname[0]}
    except Exception as e:
        return {"error": str(e)}

def ip4(ip):
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def ip5(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def ip6(ip):
    try:
        response = requests.get(f"https://freegeoip.app/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def ip7(ip):
    try:
        response = requests.get(f"http://ipwhois.app/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def ip8(ip):
    try:
        output = subprocess.check_output(["traceroute", ip])
        return output.decode()
    except Exception as e:
        return {"error": str(e)}

def ip9(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={ip}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def ip10(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/mtr/?q={ip}")
        return response.text
    except Exception as e:
        return {"error": str(e)}

def ip11(ip):
    try:
        output = subprocess.check_output(["nslookup", ip])
        return output.decode()
    except Exception as e:
        return {"error": str(e)}

def ip12(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/reversedns/?q={ip}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def ip13(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/pagelinks/?q={ip}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def ip14(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/dnslookup/?q={ip}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def ip15(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/geoip/?q={ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def json_formatter(data):
    try:
        parsed = json.loads(data)
        formatted = json.dumps(parsed, indent=4)
        return formatted
    except Exception as e:
        return {"error": str(e)}

def json_validator(data):
    try:
        json.loads(data)
        return {"status": "valid"}
    except json.JSONDecodeError as e:
        return {"status": "invalid", "error": str(e)}

def json_minifier(data):
    try:
        parsed = json.loads(data)
        minified = json.dumps(parsed, separators=(',', ':'))
        return minified
    except Exception as e:
        return {"error": str(e)}

def json_prettify(data):
    try:
        parsed = json.loads(data)
        prettified = json.dumps(parsed, indent=2)
        return prettified
    except Exception as e:
        return {"error": str(e)}

def discord_invite_info(invite_code):
    try:
        response = requests.get(f"https://discord.com/api/v9/invites/{invite_code}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_user_info(user_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/users/{user_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_channel_info(channel_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/channels/{channel_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_guild_info(guild_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_webhook_info(webhook_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/webhooks/{webhook_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_message_info(channel_id, message_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def discord_role_info(guild_id, role_id):
    try:
        response = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/roles/{role_id}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def osint_email(email):
    try:
        response = requests.get(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=YOUR_API_KEY")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def osint_phone(phone):
    try:
        response = requests.get(f"https://api.apilayer.com/number_verification/validate?number={phone}&apikey=YOUR_API_KEY")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def osint_username(username):
    try:
        response = requests.get(f"https://api.sherlock.staging.sud0u53r.dev/api/{username}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def osint_domain(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def osint_ip(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/geoip/?q={ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def osint_breach(email):
    try:
        response = requests.get(f"https://haveibeenpwned.com/api/v2/breachedaccount/{email}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def lookup_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def lookup_domain(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        return response.text.split('\n')
    except Exception as e:
        return {"error": str(e)}

def main():
    while True:
        menu = f"""
           ____     _ _____       __      ___       __       
          / __/  __(_) / _ )__ __/ /____ / _ \__ __/ /__ ___   [ PID : {pid} ]
         / _/| |/ / / / _  / // / __/ -_) ___/ // / /_ // -_)  [ USER : {login} ]
        /___/|___/_/_/____/\_, /\__/\__/_/   \_,_/_//__/\__/ 
                          /___/                              

    [  IP_TOOLS  ]                  [  JSON_TOOLS  ]
    IP01 - PortScan                 JSON01 - JSON Formatter
    IP02 - IP Lookup                JSON02 - JSON Validator
    IP03 - Hostname Lookup          JSON03 - JSON Minifier
    IP04 - IPInfo                   JSON04 - JSON Prettify
    IP05 - IPAPI
    IP06 - GeoIP
    IP07 - IPWhois

    [  DISCORD_TOOLS  ]              [  OSINT_TOOLS  ]
    DISC01 - Discord Invite Info     OSINT01 - OSINT Email
    DISC02 - Discord User Info       OSINT02 - OSINT Phone
    DISC03 - Discord Channel Info    OSINT03 - OSINT Username
    DISC04 - Discord Guild Info      OSINT04 - OSINT Domain
    DISC05 - Discord Webhook Info    OSINT05 - OSINT IP
    DISC06 - Discord Message Info    OSINT06 - OSINT Breach Check
    DISC07 - Discord Role Info

    [  LOOKUP_TOOLS  ]               [  EXIT  ]
    LOOKUP01 - Lookup IP             EX01 - Exit
    LOOKUP02 - Lookup Domain

    [>]"""

        x = input(Colorate.Vertical(Colors.blue_to_purple, menu))
        if x.upper().startswith("IP"):
            ip = input(f"{q} Enter IP: {Fore.BLUE}")
            if x.upper() == "IP01":
                data = scan_ports(ip)
            elif x.upper() == "IP02":
                data = ip_lookup(ip)
            elif x.upper() == "IP03":
                data = ip3(ip)
            elif x.upper() == "IP04":
                data = ip4(ip)
            elif x.upper() == "IP05":
                data = ip5(ip)
            elif x.upper() == "IP06":
                data = ip6(ip)
            elif x.upper() == "IP07":
                data = ip7(ip)
            elif x.upper() == "IP08":
                data = ip8(ip)
            elif x.upper() == "IP09":
                data = ip9(ip)
            elif x.upper() == "IP10":
                data = ip10(ip)
            elif x.upper() == "IP11":
                data = ip11(ip)
            elif x.upper() == "IP12":
                data = ip12(ip)
            elif x.upper() == "IP13":
                data = ip13(ip)
            elif x.upper() == "IP14":
                data = ip14(ip)
            elif x.upper() == "IP15":
                data = ip15(ip)
            else:
                print(f"{e} Invalid Option. Please choose a valid option.")
                continue

        elif x.upper().startswith("JSON"):
            data = input(f"{q} Enter JSON Data: {Fore.BLUE}")
            if x.upper() == "JSON01":
                result = json_formatter(data)
            elif x.upper() == "JSON02":
                result = json_validator(data)
            elif x.upper() == "JSON03":
                result = json_minifier(data)
            elif x.upper() == "JSON04":
                result = json_prettify(data)
            else:
                print(f"{e} Invalid Option. Please choose a valid option.")
                continue
            print(f"{s} Operation completed successfully.")
            print(result)
            continue

        elif x.upper().startswith("DISC"):
            discord_id = input(f"{q} Enter Discord ID: {Fore.BLUE}")
            if x.upper() == "DISC01":
                data = discord_invite_info(discord_id)
            elif x.upper() == "DISC02":
                data = discord_user_info(discord_id)
            elif x.upper() == "DISC03":
                data = discord_channel_info(discord_id)
            elif x.upper() == "DISC04":
                data = discord_guild_info(discord_id)
            elif x.upper() == "DISC05":
                data = discord_webhook_info(discord_id)
            elif x.upper() == "DISC06":
                message_id = input(f"{q} Enter Message ID: {Fore.BLUE}")
                data = discord_message_info(discord_id, message_id)
            elif x.upper() == "DISC07":
                role_id = input(f"{q} Enter Role ID: {Fore.BLUE}")
                data = discord_role_info(discord_id, role_id)
            else:
                print(f"{e} Invalid Option. Please choose a valid option.")
                continue

        elif x.upper().startswith("OSINT"):
            data_input = input(f"{q} Enter OSINT Input: {Fore.BLUE}")
            if x.upper() == "OSINT01":
                data = osint_email(data_input)
            elif x.upper() == "OSINT02":
                data = osint_phone(data_input)
            elif x.upper() == "OSINT03":
                data = osint_username(data_input)
            elif x.upper() == "OSINT04":
                data = osint_domain(data_input)
            elif x.upper() == "OSINT05":
                data = osint_ip(data_input)
            elif x.upper() == "OSINT06":
                data = osint_breach(data_input)
            else:
                print(f"{e} Invalid Option. Please choose a valid option.")
                continue

        elif x.upper().startswith("LOOKUP"):
            data_input = input(f"{q} Enter Lookup Input: {Fore.BLUE}")
            if x.upper() == "LOOKUP01":
                data = lookup_ip(data_input)
            elif x.upper() == "LOOKUP02":
                data = lookup_domain(data_input)
            else:
                print(f"{e} Invalid Option. Please choose a valid option.")
                continue

        elif x.upper() == "EXIT":
            print(f"Exiting the script...")
            break

        else:
            print(f"{e} Invalid Option. Please choose a valid option.")
            continue

        if isinstance(data, dict):
            with open(f"{x.lower()}.json", "w") as f:
                json.dump(data, f, indent=4)
            print(f"{s} Operation completed successfully.")
        elif isinstance(data, list):
            with open(f"{x.lower()}.txt", "w") as f:
                f.write("\n".join(data))
            print(f"{s} Operation completed successfully.")
        else:
            print(f"{e} Error occurred: {data}")

main()
