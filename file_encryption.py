import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import os
import sys

SALT_LEN = 16
SHA512_LEN = 64

class AESCipher(object):

    def __init__(self, password, salt = None):
        self.bs = AES.block_size
        if salt == None:
            self.salt = get_random_bytes(SALT_LEN)
        else:
            self.salt = salt
        self.key = scrypt(password, self.salt, 16, N=2**14, r=self.bs, p=1)

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        pad = ((self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)).encode()
        return s + pad

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


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
    password = input()
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
