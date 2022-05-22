#!/usr/bin/env python3
"""
Python script to retrieve your public IP address.

Requires the `requests` and `pyperclip` libraries to be installed.

To install the libraries type the command below:

python -m pip install requests pyperclip
"""

__author__ = "Daniel Davidson"
__version__ = "0.1.0"
__license__ = "MIT"

from requests import get
import pyperclip

# Obtain Public IP
ip = get('https://api.ipify.org').text
print(f'[~] Public IP address: {ip}')

# Copy to Clipboard
print('[+] Copied to clipboard')
pyperclip.copy(ip)
