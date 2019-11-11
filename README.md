# SBFS
Secure Basic File Sharer (SBFS) is a CLI app that allows to easily get/send encrypted files, using AES-256 and RSA-2048 to respectively cipher the file and secret key, from/to a host

# HOW TO USE SBFS ?
```shell script
Usage: sbfs [-h] -f=<file> MODE HOST
      MODE            The mode in which the program will operate (send/get).
      HOST            IP Address from the host
  -f, --file=<file>   Name of the file to download (extension included) / Path
                        to the file to send
  -h, --help          Display this help and exit
```
Copyright (c) 2019 Sébastien Maes
