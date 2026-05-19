#!/bin/bash
hashcat --potfile-path=/tmp/9-potfile -m 0 -a 1 "$1" wordlist1.txt wordlist2.txt --outfile=9-password.txt --outfile-format=2
