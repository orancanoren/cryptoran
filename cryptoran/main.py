import argparse
from packages import BlockCiphers, PublicKeyCrypto, SecretKeySharing

if __name__ == '__main__':
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
        print('    ----------------------', description.upper(), '----------------------')

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
    parser.add_argument('-k', '--key', help='key to be used in the cryptosystem (--key-help for more help)')
    parser.add_argument('-i', '--input', help='input in ASCII format')
    parser.add_argument('-e', '--encrypt', help='encrypt input', action='store_true')
    parser.add_argument('-d', '--decrypt', help='decryption input', action='store_true')
    parser.add_argument('-p', '--prime', help='group order for key exchange and pkc protocols', type=int)
    parser.add_argument('-pl', '--primelength', help='bitlength for prime number', type=int)
    parser.add_argument('-g', '--generator',help='group generator for key exchange and pkc protocols', type=int)

    args = parser.parse_args()

    # MARK: check validity of CLI options

    def printBlocks(blocks):
        for i, block in enumerate(blocks):
            print('block', str(i) + str(':'), hex(block))

    if args.cryptosystem in blockciphers:
        if not args.mode:
            parser.error('--mop is required for block ciphers')
        if not args.encrypt and not args.decrypt:
            parser.error('block ciphers should be invoked in encryption or decryption mode')
        if args.decrypt and not args.key:
            parser.error('key must be provided to block ciphers in decryption mode')
        if not args.input:
            parser.error('an input must be provided to the cryptosystem')
        if args.mode != 'ecb' and not args.initvector and args.decrypt:
            parser.error('Initialization vector must be provided for mode ' + args.mode + ' mode for decryption')

    banner(args.cryptosystem)


    if args.cryptosystem in blockciphers:
        key = int(args.key, 16) if args.key else None
        iv = int(args.initvector, 16) if args.initvector else None
        cipher = modules[args.cryptosystem](args.mode, key, iv)
        if args.encrypt:
            ciphetextBlocks = cipher.encrypt(args.input)
            printBlocks(ciphetextBlocks)
        else:
            block = [int(args.input, 16)]
            print(cipher.decrypt(block))
        
    elif args.cryptosystem in secretkey:
        if not args.prime and not args.primelength:
            parser.error('A prime group order or prime length must be supplied with key exchange protocols')
        exchange = SecretKeySharing.DiffieHellman(args.prime, args.generator, args.primelength)
        prime, generator, expSecret = exchange.generateSecret()
        print(f'Multiplicative group properties:\nPrime (largest group element + 1):\n{prime}\nGenerator:\n{generator}\nThis party sends:\n{expSecret}')
        correspondentExp = int(input('\nPlease enter the correspondent input:\n>> '))
        print('Shared secret:\n', exchange.generateSharedKey(correspondentExp))