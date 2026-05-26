#!/bin/bash
find / -xdev -type d -perm -0002 2>/dev/null | tee /dev/stderr | xargs -I {} sudo chmod o-w {}
