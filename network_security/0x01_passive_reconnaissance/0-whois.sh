#!/bin/bash
whois $1 | grep -E "^Registrant|^Admin|^Tech" | awk -F': ' '/Street/{print $1","$2" "; next} /Ext/{print $1":"","$2; next} {print $1","$2}' > $1.csv
