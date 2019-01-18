'''
KeePass Leak Detector

This script searches your KeePass-Database for passwords
that were known to be leaked. API of haveibeenpwned.com is
used to check if a password was leaked. The script will not 
send any passwords in plaintext to the server. A k-Anonymity 
model is used to send a fraction of the hash of every password
to the server and analyses the response to check if a password
is known to be compromitted.

Usage: Export KeePass-Database as Format KeePass XML 2.x and
drop .xml file onto this script (kpld.py). Delete exported database
file after check!

Created on 18.01.2019

@version: 1.0
@author: Javanaut
@license: "THE BEER-WARE LICENSE" (Revision 42):
<javanaut2018@gmail.com> wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
'''

import sys, os, hashlib, requests, threading, time, xml.etree.ElementTree as ET

BASE_URL = "https://api.pwnedpasswords.com/range/"
MAX_NUMBER_OF_THREADS = 10
DONT_CHECK_PASSWORDS_SHORTER_THAN = 4
EXCLUDE_TAN_ENTRIES = True

def checkLeak(title,password):
    global group
    if title == None or password == None:
        return 
    if EXCLUDE_TAN_ENTRIES == True:
        if title.upper().find("TAN") != -1 or group.upper().find("TAN") != -1:
            return
    if len(password) <= DONT_CHECK_PASSWORDS_SHORTER_THAN:
        return
    
    #hashing password
    hashvalue = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    #using only the  first 5 chars of hash
    clue = hashvalue[:5]
    
    #sending out only the first 5 chars of the hash. It is impossible to guess
    #the password from that 5 chars.
    result = requests.get(BASE_URL+clue).content.decode("utf-8").upper()
    
    findings = result.splitlines()
    for found in findings:
        if clue+found.split(":")[0] == hashvalue:
            print("Password for entry " + group + "/" + title + " is compromitted!")

def checkEntry(entry):
    title = ""
    password = ""
    for row in entry:
        if row.tag == "String":   
            if row.find("Key").text == "Title":
                title = row.find("Value").text
            if row.find("Key").text == "Password":
                password = row.find("Value").text
    if threading.active_count() >= MAX_NUMBER_OF_THREADS:
        time.sleep(0.2)
    threading.Thread(target=checkLeak, args=(title,password,)).start()

def parseBranch(branch):
    global group
    for elem in branch:
        if elem.tag == "Group":
            group = elem.find("Name").text
            parseBranch(elem)
        else:
            if elem.tag == "Entry":
                checkEntry(elem) 


if len(sys.argv) != 2:
    exit()
    
filename = sys.argv[1]
    
if os.path.isfile(filename) == False:
    exit()

print("parsing...", end="", flush=True)
try:
    tree = ET.parse(filename)
except:
    print("error")
    exit()
print("done")
    
root = tree.getroot()
content = root.find("Root")

print("checking for leaks...")
parseBranch(content)
if threading.active_count() > 0:
    time.sleep(0.2)
print("done")
z = input()