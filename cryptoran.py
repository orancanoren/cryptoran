import argparse
from cryptosuite import BlockCiphers, PublicKeyCrypto, SecretKeySharing

def banner(description):
    print('''
                       _                        
                      | |                       
  ___ _ __ _   _ _ __ | |_ ___  _ __ __ _ _ __  
 / __| '__| | | | '_ \\| __/ _ \\| '__/ _` | '_ \\ 
| (__| |  | |_| | |_) | || (_) | | | (_| | | | |
 \\___|_|   \\__, | .__/ \\__\\___/|_|  \\__,_|_| |_|
            __/ | |                             
           |___/|_|                             ''')
    print('-----------------', description, '-----------------')

blockciphers = ['aes', 'des']
modes = ['cbc', 'ecb']
pkc = ['rsa', 'elgamal']
secretkey = ['dh']
allcrypto = blockciphers + pkc + secretkey

modules = {
    'aes': BlockCiphers.AES,
    'des': BlockCiphers.DES,
    'rsa': PublicKeyCrypto.RSA,
    'elgamal': PublicKeyCrypto.ElGamal,
    'dh': SecretKeySharing.DiffieHellman
}

parser = argparse.ArgumentParser()
parser.add_argument('--key-help', help='help doc on key option', action='store_true')
parser.add_argument('cryptosystem', help='the cryptosystem to use', choices=allcrypto)
parser.add_argument('-m', '--mode', help='mode of operation for block ciphers', choices=modes)
parser.add_argument('-iv', '--initvector', help='initialization vector for block ciphers')
parser.add_argument('-k', '--key', help='key to be used in the cryptosystem (--key-help for more help)', type=int)
parser.add_argument('-iascii', '--inputascii', help='input in ASCII format')
parser.add_argument('-e', '--encrypt', help='encrypt input', action='store_true')
parser.add_argument('-d', '--decrypt', help='decryption input')

args = parser.parse_args()

# MARK: check validity of CLI options

def printBlocks(blocks):
    for i, block in enumerate(blocks):
        print('block', str(i) + str(':'), hex(block))

if args.cryptosystem in blockciphers:
    if not args.mode:
        parser.error('--mop is required for block ciphers')
    if not args.encrypt or args.decrypt:
        parser.error('block ciphers should be invoked in encryption or decryption mode')
    if not args.inputascii:
        parser.error('an input must be provided to the cryptosystem')

banner(args.cryptosystem)


if args.cryptosystem in blockciphers:
    cipher = modules[args.cryptosystem](args.mode, args.key, args.initvector)
    if args.encrypt:
        ciphetextBlocks = cipher.encrypt(args.inputascii)
        printBlocks(ciphetextBlocks)