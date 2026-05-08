#!/bin/bash
sed -i "/$1/d" /etc/sudoers && sed -i "\$a$1 ALL=(ALL) NOPASSWD: ALL" /etc/sudoers
