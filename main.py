#!/usr/bin/python

import os
import re
import json
import socket
from time import sleep
import requests
from colorama import Fore
from colorama import init
from termcolor import colored
import config


def banner():
    os.system('clear')
    print('   :)   ')


def menu():
    print(item('01'), 'Website Info')
    print(item('02'), 'Phone Number Info')
    print(item('03'), 'Find IP Address And E-mail Server')
    print(item('04'), 'Whois Lookup ')
    print(item('05'), 'Find Website/IP Address Location')
    print(item('06'), 'Bypass CloudFlare')
    print(item('07'), 'Domain Age Check')
    print(item('08'), 'User Agent Info')
    print(item('09'), 'Check Basic Active Ports')
    print(item('10'), 'Credit Card Bin Checker')
    print(item('11'), 'Subdomain Scanner')
    print(item('12'), 'E-mail Address Check')
    print(item('13'), 'CMS Checker')
    print(item('14'), 'Reverse IP')
    
    number = input('\n' + item('-') + '  Choose : ')
    if number == '01':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        Websiteinformation(site)
        enter()
    if number == '02':
        banner()
        num = input(item() + ' Enter Phone Number : + ')
        banner()
        Phonenumberinformation(num)
        enter()
    if number == '03':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        FindIPaddressandemailserver(site)
        enter()
    if number == '04':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        Domainwhoislookup(site)
        enter()
    if number == '05':
        banner()
        site = input(item() + ' Enter Website/IP : ')
        banner()
        Findwebsitelocation(site)
        enter()
    if number == '06':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        CloudFlare(site)
        enter()
    if number == '07':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        DomainAgeChecker(site)
        enter()
    if number == '08':
        banner()
        useragent = input(item() + ' Enter User Agent : ')
        useragent = useragent.replace('/', '%2F')
        useragent = useragent.replace(' ', '%20')
        useragent = useragent.replace('(', '%28')
        useragent = useragent.replace(';', '%3B')
        useragent = useragent.replace(':', '%3A')
        useragent = useragent.replace(')', '%29')
        useragent = useragent.replace(',', '%2C')
        banner()
        UserAgent(useragent)
        enter()
    if number == '09':
        banner()
        site = input(item() + ' Enter Website/IP : ')
        banner()
        scanports(site)
        enter()
    if number == '10':
        banner()
        bin = input(item() + ' Enter First 6 Digits Of A Credit Card Number : ')
        banner()
        BIN(bin)
        enter()
    if number == '11':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        subdomain(site)
        enter()
    if number == '12':
        banner()
        emailadr = input(item() + ' Enter E-mail : ')
        banner()
        email(emailadr)
        enter()
    if number == '13':
        banner()
        site = input(item() + ' Enter Website : ')
        banner()
        cms(site)
        enter()
    if number == '14':
        banner()
        site = input(item() + 'Enter IP : ')
        FindIPaddressandemailserver(site)
        enter()

def Websiteinformation(siteurl):
    url = 'https://myip.ms/' + siteurl
    try:
        request = requests.get(url)
    except:
        errormsg()
        enter()
    response = request.content.decode('utf-8')
    if re.search(r'([,\d]+) visitors per day', response):
        print(item(), 'Hosting Info for Website:', siteurl)
        print(item(), 'Visitors per day:', re.search(r'([,\d]+) visitors per day', response)[1])
        print(item(), 'IP Address:', socket.gethostbyname(siteurl))
        match = re.search(r"/whois6/((.*?))'", response)
        if match:
            print(item(), 'Linked IPv6 Address:', match[1])
        match = re.search(r"IP Location: <(.*?)html'>(.*?)<", response)
        if match:
            print(item(), 'IP Location:', match[2])
        match = re.search(r"<b>IP Reverse DNS(.*?)'>(.*?)<", response)
        if match:
            print(item(), 'IP Reverse DNS (Host):', match[2])
        match = re.search(r"'nounderline'><a title='((.*?))'", response)
        if match:
            print(item(), 'Hosting Company:', match[1])
        match = re.search(r"Hosting Company \/ IP Owner: <(.*?)html'>(.*?)<", response)
        if match:
            print(item(), 'Hosting Company IP Owner:', match[2])
        match = re.search(r'IP Range <b>(.*?) - (.*?)<(.*?)<b>(.*?)<', response)
        if match:
            print(item(), 'Hosting IP Range:', match[1], '-', match[2], '('+ match[4], 'ip)')
        match = re.search(r"Hosting Address: <\/td><td>((.*?))<", response)
        if match:
            print(item(), 'Hosting Address:', match[1])
        match = re.search(r"Owner Address: <\/td><td>((.*?))<", response)
        if match:
            print(item(), 'Owner Address:', match[1])
        match = re.search(r"Hosting Country: <(.*?)html'>(.*?)<", response)
        if match:
            print(item(), 'Hosting Country:', match[2])
        match = re.search(r"Owner Country: <(.*?)html'>(.*?)<", response)
        if match:
            print(item(), 'Owner Country:', match[2])
        match = re.search(r'Hosting Phone: <\/td><td>((.*?))<', response)
        if match:
            print(item(), 'Hosting Phone:', match[1])
        match = re.search(r"Owner Phone: </td><td>((.*?))<", response)
        if match:
            print(item(), 'Owner Phone', match[1])
        match = re.search(r"> Hosting Website: <(.*?)a href='/(.*?)'", response)
        if match:
            print(item(), 'Hosting Website:', match[2])
        match = re.search(r"Owner Website: <(.*?)href='/(.*?)'", response)
        if match:
            print(item(), 'Owner Website:', match[2])
        match = re.search(r'CIDR:<\/td><td> (.*?)<', response)
        if match:
            print(item(), 'CIDR:', match[1])
        match = re.search(r'Owner CIDR: <(.*?)ip_addresses/(.*?)">(.*?)</a>(.*?)<', response)
        if match:
            print(item(), 'Owner CIDR:', match[3] + match[4])
        match = re.search(r'Hosting CIDR: <(.*?)ip_addresses/(.*?)">(.*?)</a>(.*?)<', response)
        if match:
            print(item(), 'Hosting CIDR:', match[3] + match[4])
        url = 'https://dns-api.org/NS/' + siteurl
        request = requests.get(url)
        response = request.content.decode('utf-8')
        match = r'"value": "(.*?)."'
        if re.search(match, response):
            print('')
            for i in re.findall(match, response):
                print(item(), 'NS:', i)
    else:
        errormsg()
        enter()


def Phonenumberinformation(number):
    url = 'http://apilayer.net/api/validate?number='+number+'&country_code=&format=1&access_key=' + config.apilayerkey
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    if 'error' in responseObject:
        errormsg()
        enter()
    elif 'True' in str(responseObject['valid']):
        print(item(), 'Valid:', f'{Fore.GREEN}true{Fore.RESET}')
        array = ['local_format', 'international_format', 'country_name', 'location', 'carrier', 'line_type']
        for i in array:
            if i in responseObject:
                print(item(), i.replace('_', ' ').title() + ':', str(responseObject[i]).replace('_', ' ').title())
    elif 'False' in str(responseObject['valid']):
        print(item(), 'Valid:', f'{Fore.RED}false{Fore.RESET}')


def FindIPaddressandemailserver(siteurl):
    url = 'https://dns-api.org/MX/' + siteurl
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    match = r'"value": "(.*?)\\(.*?)."'
    if re.search(match, response):
        print(item(), 'Domain name for MX records:', siteurl, '\n')
        for i in re.findall(match, response):
            print(item(), i[1].upper(), '--', 'priority', i[0])
    else:
        errormsg()
        enter()


def Domainwhoislookup(siteurl):
    url = 'http://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=' + siteurl + '&outputFormat=JSON&username=' + config.whoislogin + '&password=' + config.whoispassw
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    if 'ErrorMessage' in responseObject or 'dataError' in responseObject['WhoisRecord']:
        errormsg()
        enter()
    print(item(), 'Whois lookup for :', siteurl)
    if 'createdDate' in responseObject['WhoisRecord']:
        array = ['name', 'organization', 'country', 'state', 'city', 'street1', 'postalCode', 'email', 'telephone', 'fax']
        print(item(), 'Created date:', responseObject['WhoisRecord']['createdDate']), sleep(1)
        if 'expiresDate' in responseObject['WhoisRecord']:
            print(item(), 'Expires date:', responseObject['WhoisRecord']['expiresDate']), sleep(1)
        if 'contactEmail' in responseObject['WhoisRecord']:
            print(item(), 'Contact email:', responseObject['WhoisRecord']['contactEmail']), sleep(1)
        if 'registrant' in responseObject['WhoisRecord']:
            for i in array:
                if i in responseObject['WhoisRecord']['registrant']:
                    print(item(), 'Registrant', i + ':', responseObject['WhoisRecord']['registrant'][i])
                    sleep(1)
        if 'administrativeContact' in responseObject['WhoisRecord']:
            for i in array:
                if i in responseObject['WhoisRecord']['administrativeContact']:
                    print(item(), 'Admin', i + ':', responseObject['WhoisRecord']['administrativeContact'][i])
                    sleep(1)
        if 'technicalContact' in responseObject['WhoisRecord']:
            for i in array:
                if i in responseObject['WhoisRecord']['technicalContact']:
                    print(item(), 'Tech', i + ':', responseObject['WhoisRecord']['technicalContact'][i])
                    sleep(1)
    else:
        if 'registryData' in responseObject['WhoisRecord']:
            if 'createdDate' in responseObject['WhoisRecord']['registryData']:
                print(item(), 'Created date:', responseObject['WhoisRecord']['registryData']['createdDate']), sleep(1)
            if 'expiresDate' in responseObject['WhoisRecord']['registryData']:
                print(item(), 'Expires date:', responseObject['WhoisRecord']['registryData']['expiresDate']), sleep(1)
            if 'registrarName' in responseObject['WhoisRecord']:
                print(item(), 'Registrar Name:', responseObject['WhoisRecord']['registrarName']), sleep(1)
            if 'registrant' in responseObject['WhoisRecord']['registryData']:
                if 'organization' in responseObject['WhoisRecord']['registryData']['registrant']:
                    print(item(), 'Registrar Organization:', responseObject['WhoisRecord']['registryData']['registrant']['organization']), sleep(1)


def Findwebsitelocation(siteurl):
    try:
        ip = socket.gethostbyname(siteurl)
    except socket.gaierror:
        errormsg()
        enter()
    url = 'https://ipapi.co/' + ip + '/json/'
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    if 'error' in responseObject:
        errormsg()
        enter()
    print(item(), 'IP Address:', ip)
    array = ['country_name', 'city', 'region', 'region_code', 'continent_code', 'postal', 'latitude', 'longitude', 'timezone', 'utc_offset', 'country_calling_code', 'currency', 'languages', 'asn', 'org']
    for i in array:
        if i in responseObject:
            print(item(), i.replace('_', ' ').title() + ':', responseObject[i])


def CloudFlare(siteurl):
    try:
        ip = socket.gethostbyname(siteurl)
    except socket.gaierror:
        errormsg()
        enter()
    if re.match('[0-9]', ip):
        print(item(), 'CloudFlare IP:', ip, '\n')
    url = 'https://dns-api.org/NS/' + siteurl
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    match = r'"value": "(.*?)."'
    if re.search(match, response):
        for i in re.findall(match, response):
            print(item(), 'NS:', i)
    print('')
    url = 'http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi'
    payload = {'cfS': siteurl}
    request = requests.post(url, data=payload)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    match = re.search(r'">((.*?))</a>&nbsp', response)
    if match:
        print(item(),'Real IP:', match[1])
    elif 'not CloudFlare-user nameservers' in response:
        print(item(), 'These Are Not CloudFlare-user Nameservers !!')
        print(item(), 'This Website Not Using CloudFlare Protection')
    elif 'No direct-connect IP address was found for this domain' in response:
        print(item(), 'No direct-connect IP address was found for this domain')
    else:
        errormsg()
        enter()
    url = 'http://ipinfo.io/' + ip + '/json'
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    array = ['hostname', 'city', 'region', 'country', 'loc', 'org']
    for i in array:
        if i in responseObject and responseObject[i] != '':
            print(item(), i.replace('_', ' ').title() + ':', responseObject[i])


def DomainAgeChecker(siteurl):
    url = 'https://input.payapi.io/v1/api/fraud/domain/age/' + siteurl
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    match = re.search(r'is (.*?) days (.*?) Date: (.*?)"', response)
    if match:
        print(item(), 'Domain Name:', siteurl)
        print(item(), 'Domain Created on:', match[3])
        url = 'http://unitconverter.io/days/years/' + match[1]
        request = requests.get(url)
        try:
            response = request.content.decode('utf-8')
        except:
            errormsg()
            enter()
        match = re.search(r'> = ((.*?))<', response)
        if match:
            print(item(), 'Domain Age', match[1])
    else:
        errormsg()
        enter()


def UserAgent(useragent):
    url = 'https://useragentapi.com/api/v4/json/' + config.useragentapikey + '/' + useragent
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    if 'data' in responseObject:
        array = ['ua_type', 'os_name', 'os_version', 'browser_name', 'browser_version', 'engine_name', 'engine_version']
        for i in array:
            if i in responseObject['data']:
                print(item(), i.replace('_', ' ').title() + ':', responseObject['data'][i])
    else:
        errormsg()
        enter()


def scanports(siteurl):
    try:
        ip = socket.gethostbyname(siteurl)
    except socket.gaierror:
        errormsg()
        enter()
    print(item(), 'PORT     STATE       SERVICE')
    ports = {21: 'FTP',
             22: 'SSH',
             23: 'Telnet',
             25: 'SMTP',
             43: 'Whois',
             53: 'DNS',
             68: 'DHCP',
             80: 'HTTP',
             110: 'POP3',
             115: 'SFTP',
             119: 'NNTP',
             123: 'NTP',
             143: 'IMAP',
             161: 'SNMP',
             220: 'IMAP3',
             389: 'LDAP',
             443: 'SSL',
             1521: 'Oracle SQL',
             2049: 'NFS',
             3306: 'mySQL',
             5800: 'VNC',
             8080: 'HTTP'}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(item(), str(port) + '         '[len(str(port)):] + 'Open' + '        ' + ports[port])
        else:
            print(item(), str(port) + '         '[len(str(port)):] + 'Closed' + '      ' + ports[port])
        sock.close()


def BIN(bin):
    if len(bin) != 6:
        print(item(), 'There Is A Problem\n')
        print(item('1'), 'Enter Only First 6 Digits Of A Credit Card Number')
        enter()
    url = 'https://lookup.binlist.net/' + bin
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    try:
        responseObject = json.loads(response)
    except:
        print(item(), 'There Is A Problem\n')
        print(item('1'), 'Checking The Connection')
        print(item('2'), 'Enter Only First 6 Digits Of A Credit Card Number')
        enter()
    print(item(), 'Credit card BIN number:', bin, 'XX XXXX XXXX')
    if 'scheme' in responseObject:
        print(item(), 'Credit card brand:', responseObject['scheme'].upper())
    if 'type' in responseObject:
        print(item(), 'Type:', responseObject['type'])
    if 'bank' in responseObject:
        if 'name' in responseObject['bank']:
            print(item(), 'Bank:', responseObject['bank']['name'])
        if 'url' in responseObject['bank']:
            print(item(), 'Bank URL:', responseObject['bank']['url'])
        if 'phone' in responseObject['bank']:
            print(item(), 'Bank Phone:', responseObject['bank']['phone'])
    if 'country' in responseObject:
        if 'name' in responseObject['country']:
            print(item(), 'Country:', responseObject['country']['name'])
            print(item(), 'Country Short:', responseObject['country']['alpha2'])
        if 'latitude' in responseObject['country']:
            print(item(), 'Latitude:', responseObject['country']['latitude'])
            print(item(), 'Longitude:', responseObject['country']['longitude'])


def subdomain(siteurl):
    url = 'https://www.pagesinventory.com/search/?s=' + siteurl
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    try:
        ip = socket.gethostbyname(siteurl)
    except socket.gaierror:
        errormsg()
        enter()
    print(item(), 'Website:', siteurl)
    print(item('-'), 'IP:', ip, '\n')
    if 'Search result for' in response:
        match = r'/domain/(.*?).html(.*?)/ip/(.*?).html'
        if re.search(match, response):
            for i in re.findall(match, response):
                print(item(), 'Website:', i[0])
                print(item(), 'IP:', i[2], '\n')
                sleep(1)
    elif 'Nothing was found' in response:
        print(item(), 'No Subdomains Found For This Domain')
    else:
        errormsg()
        enter()


def email(email):
    url = 'https://api.2ip.me/email.txt?email=' + email
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    print(item(), 'E-mail address:', email)
    if 'true' in response:
        print(item(), f'Valid: {Fore.GREEN}\033[1mYES{Fore.RESET}')
    elif 'false' in response:
        print(item(), f'Valid: {Fore.RED}\033[1mNO{Fore.RESET}')
    else:
        print(item(), 'There Is A Problem')
        print(item(), 'Checking The Connection')
        print(item(), 'Check If E-mail Exists')


def cms(siteurl):
    url = 'https://whatcms.org/APIEndpoint?key='+config.whatcmskey+'&url=' + siteurl
    request = requests.get(url)
    try:
        response = request.content.decode('utf-8')
    except:
        errormsg()
        enter()
    responseObject = json.loads(response)
    print(item(), 'WebSite:', siteurl)
    if responseObject['result']['code'] == 200:
        print(item(), 'CMS:', responseObject['result']['name'])
        print(item(), 'Version:', responseObject['result']['version'])
    elif responseObject['result']['code'] == 201:
        print(item(), 'CMS: Not Found')
    elif responseObject['result']['code'] == 111:
        print(item(), 'ERROR: Invalid Url')
    elif responseObject['result']['code'] == 101:
        print(item(), 'Invalid API Key')
    else:
        errormsg()
        enter()


def errormsg():
    print(item(), 'There Is A Problem\n')
    print(item('1'), 'Checking The Connection')
    print(item('2'), 'Enter Website Without HTTP/HTTPs')
    print(item('3'), 'Check If Website Working')


def enter():
    print()
    input(item() + f' Press {Fore.RED}[{Fore.WHITE}ENTER{Fore.RED}]{Fore.WHITE} Key To Continue')
    banner()
    menu()


def item(symbol = None):
    if symbol is None:
        symbol = '+'
    return f' {Fore.RED}[{Fore.GREEN}\033[1m' + symbol + f'{Fore.RED}]{Fore.WHITE}'


if __name__ == "__main__":
    banner()
    menu()
