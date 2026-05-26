#!/bin/bash
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -m --state ESTABLISHED,RELATED -j ACCEPT && sudo iptables -A INPUT -j DROP
