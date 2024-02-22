import hashlib
import os
import sys
import getpass
from AESCipher import *

SHA512_LEN = 64

def encrypt_file(path, password, hashed_pass):
    aes = AESCipher(password)

    with open(path, 'rb') as file:
        data = file.read()
        
    enc = hashed_pass +aes.encrypt(data) + aes.salt
    
    with open(path + '.encr', 'wb') as file:
        file.write(enc)

    # os.remove(path)

def decrypt_file(path, password):
    with open(path, 'rb') as file:
        data = file.read()

    salt = data[-SALT_LEN:]
    file_pass = data[:SHA512_LEN]
    enc = data[SHA512_LEN:-SALT_LEN]
    aes = AESCipher(password, salt)
    dec = aes.decrypt(enc)

    with open(path[:-5], 'wb') as file:
        file.write(dec)

    # os.remove(path)

def password_input(salt):
    print('enter password: ')
    password = getpass.getpass()
    hashed_pass = password + salt
    hashed_pass = hashlib.sha512(hashed_pass.encode()).digest()
    return (password, hashed_pass)

def main():
    salt = 'somesalt'
    
    if len(sys.argv) != 3:
        print(f'Usage is "{sys.argv[0]} [lock/unlock] filename ')
        
    elif sys.argv[1] == 'lock':
        password, hashed_password = password_input(salt)
        path = sys.argv[2]
        try:
            encrypt_file(path, password, hashed_password)
            print('file encrypted')
        except Exception as ex:
            if type(ex).__name__ == 'FileNotFoundError':
                print(f'file {path} not found')
            else:
                print('unknown error occured')
                print(f'{ex.args}')
            sys.exit()
                
    elif sys.argv[1] == 'unlock':
        password, hashed_password = password_input(salt)
        path = sys.argv[2]
        file_hashed_pass = ''
        try:
            with open(path, 'rb') as file:
                data = file.read()
            file_hashed_pass = data[:SHA512_LEN]
        except Exception as ex:
            if type(ex).__name__ == 'FileNotFoundError':
                print(f'file {path} not found')
            else:
                print('unknown error occured')
            sys.exit()
            
        if hashed_password == file_hashed_pass:
            try:
                decrypt_file(path, password)
                print('file decrypted')
            except Exception as ex:
                print('unknown error occured')
        else:
            print('wrong password or not an encrypted file!')

if __name__ == '__main__':
    main()
