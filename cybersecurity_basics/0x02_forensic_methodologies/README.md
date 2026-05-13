# Forensic Ethics & Methodologies - The Case of the Mysterious Image

## Objective
Analyze an image using exiftool to identify metadata

## I used exiftool to inspect the image

```bash
exiftool Y8CYJ34I9W2GTE9T.png
exiftool Y8CYJ34I9W2GTE9T.png | grep "Author"
```bash

# Finding - Sherlock_Holbies

# Geolocation

## Extract GPS coordinates from image metadata and identify the real-world location.

```bash
exiftool -gpsposition 9ACK7LD8EFPNI6EB.png
```bash

# Finding - 37 deg 46' 53.82" N, 122 deg 24' 29.84" W
# Result: San Francisco, California 
