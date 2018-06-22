import argparse
from packages import blockcipher, pkc, keyexchange

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
    pubkeycrypto = ['rsa', 'elgamal']
    exchange = ['dh']
    allcrypto = blockciphers + pubkeycrypto + exchange

    modules = {
        'aes': blockcipher.AES,
        'des': blockcipher.DES,
        'rsa': pkc.RSA,
        'elgamal': pkc.ElGamal,
        'dh': keyexchange.DiffieHellman
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
    parser.add_argument('-oaep', help='enable OAEP - only for RSA', action='store_true')
    parser.add_argument('-pub', help='public key for PKC', type=int)
    parser.add_argument('-priv', help='private key for PKC', type=int)
    parser.add_argument('-mod', '--modulus', help='modulus for PKC', type=int)

    args = parser.parse_args()

    # MARK: check validity of CLI options
    if not args.encrypt and not args.decrypt and args.cryptosystem not in exchange:
        parser.error('ciphers should be invoked in encryption or decryption mode')
    if not args.input:
        parser.error('an input must be provided to the cryptosystem')

    def printBlocks(blocks):
        for i, block in enumerate(blocks):
            print('block', str(i) + str(':'), hex(block))

    if args.cryptosystem in blockciphers:
        if not args.mode:
            parser.error('--mop is required for block ciphers')

        if args.mode != 'ecb' and not args.initvector and args.decrypt:
            parser.error('Initialization vector must be provided for mode ' + args.mode + ' mode for decryption')

    banner(args.cryptosystem)


    if args.cryptosystem in blockciphers:
        if args.decrypt and not args.key:
            parser.error('key must be provided in decryption mode')

        key = int(args.key, 16) if args.key else None
        iv = int(args.initvector, 16) if args.initvector else None
        cipher = modules[args.cryptosystem](args.mode, key, iv)
        if args.encrypt:
            ciphetextBlocks = cipher.encrypt(args.input)
            printBlocks(ciphetextBlocks)
        else:
            block = [int(args.input, 16)]
            print(cipher.decrypt(block))
        
    elif args.cryptosystem in exchange:
        if not args.prime and not args.primelength:
            parser.error('A prime group order or prime length must be supplied with key exchange protocols')
        exchange = keyexchange.DiffieHellman(args.prime, args.generator, args.primelength)
        prime, generator, expSecret = exchange.generateSecret()
        print(f'Multiplicative group properties:\nPrime (largest group element + 1):\n{prime}\nGenerator:\n{generator}\nThis party sends:\n{expSecret}')
        correspondentExp = int(input('\nPlease enter the correspondent input:\n>> '))
        print('Shared secret:\n', exchange.generateSharedKey(correspondentExp))

    if args.cryptosystem in pubkeycrypto:
        if not (args.priv and args.pub and args.modulus) and not args.primelength:
            parser.error('Public-key cryptosystems must be supplied either a key pair along with modulus or prime length')

        cipher = modules[args.cryptosystem](pubKey=args.pub, privKey=args.priv, 
            modulus=args.modulus, oaep=args.oaep, primeLength=args.primelength)
        if args.primelength:
            pubkey, privkey = cipher.generateKeys()
            print('Public key:')
            for key, val in zip(pubkey.keys(), pubkey.values()):
                print(key + ':', val)
            print('\nPrivate key:')
            for key, val in zip(privkey.keys(), privkey.values()):
                print(key + ':', val)
        
        print('\nOutput:')
        if args.encrypt:
            print(cipher.encrypt(args.input))
        else:
            ciphertext = args.input
            try:
                ciphertext = int(args.input)
            except:
                parser.error('Supplied input must be an integer')
            print(cipher.decrypt(ciphertext))