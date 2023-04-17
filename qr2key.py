#!/usr/bin/env python3

# Copyright (c) 2018 Marco Zollinger
# Licensed under MIT, the license file shall be included in all copies

from PIL import Image
from pycoin.symbols.btc import network as btc_network
from pycoin.symbols.bch import network as bch_network
from eth_utils import keccak
import requests
import zbarlight
import glob
import re

counter_images = 0
counter_qrcodes = 0
counter_privkeys = 0

def get_eth_address(priv_key):
    pub_key = priv_key.public_key()
    pub_key_bytes = pub_key.sec()
    address = keccak(pub_key_bytes[-64:])[-20:]
    return '0x' + address.hex()

with open('./keylist.txt', 'a') as key_list:
    print("scanning images for QR codes with cryptocurrency private keys...")
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
                if ((re.match(r'5(H|J|K).{49}$', code) or      # match private key (WIF, uncompressed pubkey) with length 51
                   re.match(r'(K|L).{51}$', code) or           # match private key (WIF, compressed pubkey) with length 52
                   re.match(r'S(.{21}|.{29})$', code)) and     # match mini private key with length 22 (deprecated) or 30
                   re.match(r'[1-9A-HJ-NP-Za-km-z]+', code)):  # match only BASE58
                    counter_privkeys += 1
                    try:
                        btc_key = btc_network.parse.private_key(code)
                        bch_key = bch_network.parse.private_key(code)
                        eth_key = btc_key.to_ethereum_key()

                        btc_req = requests.get('https://blockchain.info/q/addressbalance/{}?confirmations=1'.format(btc_key.address()))
                        bch_req = requests.get('https://blockchain.info/bch/addressbalance/{}?confirmations=1'.format(bch_key.address()))
                        eth_req = requests.get('https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest&apikey=YourApiKeyToken'.format(get_eth_address(eth_key)))

                        key_list.write(code + '\n')
                        print("booty found!: {} satoshi (BTC) contained in key {}".format(btc_req.json(), code))
                        print("booty found!: {} satoshi (BCH) contained in key {}".format(bch_req.json(), code))
                        print("booty found!: {} wei (ETH) contained in key {}".format(eth_req.json()['result'], code))
                    except (AssertionError, AttributeError, IndexError, ValueError) as e:
                        print("Address lookup error: {}".format(e))
    print("qr2key done. scanned {} images, with {} QR codes containing {} cryptocurrency private keys".format(counter_images, counter_qrcodes, counter_privkeys))
    print("saved private keys to keylist.txt")
