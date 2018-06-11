import argparse
from cryptosuite import BlockCiphers, PublicKeyCrypto, SecretKeySharing

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
parser.add_argument('--mop', help='mode of operation for block ciphers', choices=modes)
parser.add_argument('--key', help='key to be used in the cryptosystem (--key-help for more help)', type=int)
parser.add_argument('-p', '--plaintext', help='plaintext message in ASCII string')

args = parser.parse_args()

# MARK: check validity of CLI options
if args.cryptosystem and args.cryptosystem in blockciphers and not args.mop:
    parser.error('--mop is required for block ciphers')

# MARK: check for help doc invokations
print(args)