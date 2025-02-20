import base64
import json
import os

from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#PBKDF2HMAC master password
def gen_master_passwd_key(passwd,salt):
    password = passwd.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key  # this key used for encrypted and decrypted secret key

# encrypt
def encrypt_AES(key,iv, target_unencrypted_text):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    ciphertext = base64.b64encode(iv + cipher.encrypt(pad(target_unencrypted_text,AES.block_size)))
    return ciphertext

# decypt
def decrypt_AES(key, encrypted_text) :
    raw = base64.b64decode(encrypted_text)
    decrypted_cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    decrypted_text = unpad(decrypted_cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf_8')
    return decrypted_text

passwd = "nguyễn"
utf8_passwd = passwd.encode('utf_8')

master_passwd = 'testing'
# open key file
key_file = Path(".\key\key.txt")
key = ''
iv = token_bytes(AES.block_size)
fix_salt = '274f2589a5002d3d8e8412c2a877729b' # hex
passwd_cipher = Fernet(gen_master_passwd_key(master_passwd, fix_salt))

if key_file.is_file():  #if file exist
    with open(key_file, "r") as file:
        content = json.load(file)
        encrypted_key = bytes.fromhex(content.get('key')) #convert from hex to bytes
        key = passwd_cipher.decrypt(encrypted_key)
else: 
    key = token_bytes(AES.block_size)
    key_data_encrypted = passwd_cipher.encrypt(key)
    data = {'key': key_data_encrypted.hex()}    #save key as hex value
    with open(key_file, "w") as file:
        json.dump(data, file)  

encrypted_text = encrypt_AES(key,iv, utf8_passwd)
decrypted_text = decrypt_AES(key,encrypted_text)
print(decrypted_text)