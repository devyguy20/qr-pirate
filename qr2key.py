#!/usr/bin/env python3

# Copyright (c) 2018 Marco Zollinger
# Licensed under MIT, the license file shall be included in all copies

from PIL import Image
import requests
import zbarlight
import glob
import re
from eth_utils import to_checksum_address
from eth_account import Account

counter_images = 0
counter_qrcodes = 0
counter_privkeys = 0
etherscan_api_key = 'Your_API_Key_Here'  # Replace with your Etherscan API key

with open('./keylist.txt', 'a') as key_list:
    print("scanning images for QR codes with Ethereum private keys...")
    for image_path in glob.glob('./qrbooty/*.*'):
        with open(image_path, 'rb') as image_file:
            counter_images += 1
            try:
                image = Image.open(image_file).convert('RGBA')
                image.load()
            except (OSError, IOError, ValueError, AttributeError) as e:
                print("Invalid image: {}".format(e))
                continue
            try:
                codes = zbarlight.scan_codes('qrcode', image)
            except SyntaxError as e:
                print("Could not decode: {}".format(e))
                continue
            for code in (codes or []):
                code = code.decode('ascii', errors='replace')
                counter_qrcodes += 1
                if re.match(r'^0x[0-9a-fA-F]{64}$', code):  # match Ethereum private key with length 64 (excluding "0x")
                    counter_privkeys += 1
                    try:
                        account = Account.from_key(code)
                        address = to_checksum_address(account.address)
                        req = requests.get('https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest&apikey={}'.format(address, etherscan_api_key))
                        balance = int(req.json()['result']) / 10 ** 18
                        key_list.write(code + '\n')
                        print("booty found!: {} Ether contained in key {}".format(balance, code))
                    except (AssertionError, AttributeError, IndexError, ValueError) as e:
                        print("Address lookup error: {}".format(e))
    print("qr2key done. scanned {} images, with {} QR codes containing {} Ethereum private keys".format(counter_images, counter_qrcodes, counter_privkeys))
    print("saved private keys to keylist.txt")
