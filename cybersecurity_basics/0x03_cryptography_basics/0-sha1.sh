#!/bin/bash
echo -n "$1" | sha1sum | cut -d " " -f 1
