#!/bin/bash
hashcat -m 0 -a 1 "$1" wordlist1.txt wordlist2.txt --show --outfile=9-password.txt --outfile-format=2
