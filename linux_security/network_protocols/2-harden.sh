#!/bin/bash
find / -type d -perm -o+w 2>/dev/null | tee /dev/stderr | xargs -I {} sudo chmod o-w {}
