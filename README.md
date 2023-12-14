# CCOM 4205 - Project 3 - Final project - Packet-Sniffer
## Eduardo Santín 

### This project is packet sniffer script that detects the following protocols:
    
    - ARP
    - IP
    - TCP
    - UDP
    - ICMP
    - HTTP
    - HTTPS
    - DNS
    - SMTP
    - Other

### Requirements:
- python 3

### How to run:
  1. Open a terminal and navigate to the directory where the files are located.

  2. Run the command: `sudo `

  3. The program will run in the background and it will run until the user presses Ctrl+C to stop it. The output will be displayed in the terminal once the user stops the program.


### Comments:
- SMTP on private networks were not able to be detected. On a public network, like the campus network, it was able to detect SMTP.
- Split http and https into two different protocols. They are differentiated in the output print.

### Sites used for reference and help:
 - https://wiki.wireshark.org/Ethernet
 - https://support.huawei.com/enterprise/fr/doc/EDOC1100112351/dd76ea1f/ipv4-packet-format
 - https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml



