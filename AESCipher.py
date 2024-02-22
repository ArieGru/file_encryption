import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

SALT_LEN = 16

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

