#!/bin/bash
sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT
sudo iptables -A INPUT -m --state ESTABLISHED,RELATED -j ACCEPT && sudo iptables -A INPUT -j DROP
