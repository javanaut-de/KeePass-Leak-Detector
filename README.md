# README #

### What is this repository for? ###

KeePass Leak Detector

Version 1.0

Created on 18.01.2019 by Javanaut

This script searches your KeePass-Database for passwords
that were known to be leaked. API of haveibeenpwned.com is
used to check if a password was leaked. The script will not 
send any passwords in plaintext to the server. The k-Anonymity 
mechanism of the haveibeenpwned.com is used to send a fraction
of the hash of every password to the server and analyses the 
response to check if a password is known to be compromitted.

### Plugin ###

There is also a plug-in for KeePass 2.x integrating check for
compromitted passwords that is not from me. It can be found here: 

https://github.com/andrew-schofield/keepass2-haveibeenpwned

### Licence ###

"THE BEER-WARE LICENSE" (Revision 42):
<javanaut2018@gmail.com> wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.

### How do I get set up? ###

Export KeePass-Database as Format KeePass XML 2.x and
drop .xml file onto this script (kpld.py). Delete exported database
file after check!
