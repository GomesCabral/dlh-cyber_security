#!/bin/bash
grep "^NAME=" /etc/os-release | cut -d '"' -f2 | cut -d ' ' -f1

