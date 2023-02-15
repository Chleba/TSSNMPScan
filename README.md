# TSSNMPScan
Scanner of SNMP agents from CIDR range of IP addresses written in Typescript. Outputs IP address and it's Interfaces. 

#
## Usage
- `nmp install`
- `npm start`
- wait for prompt: `Please enter CIDR you want to scan:``
- enter CIDR range of IP addresses, for example: `192.168.0.0/24`

## Output
Program will output it's progress and after the whole range is scanned program will wrote into a console all IP addresses that answer on SNMP with the list of it's interfaces.

Enjoy