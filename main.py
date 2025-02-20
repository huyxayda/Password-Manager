import base64
import json

from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Util.Padding import pad, unpad
from pathlib import Path

passwd = "nguyễn"
utf8_passwd = passwd.encode('utf_8')

# open key file
key_file = Path(".\key\key.txt")

if key_file.is_file():  #if file exist
    with open(key_file, "r") as file:
        content = json.load(file)
        key = bytes.fromhex(content.get('key')) #convert from hex to bytes
else:
    key = token_bytes(AES.block_size)
    data = {'key': key.hex()}
    with open(key_file, "w") as file:
        json.dump(data, file)  #save key as hex value 

iv = token_bytes(AES.block_size)

print('key: ' + key.hex())
print('iv: ' + iv.hex())

# encrypt
cipher = AES.new(key,AES.MODE_CBC,iv)
ciphertext = base64.b64encode(iv + cipher.encrypt(pad(utf8_passwd,AES.block_size)))
print(ciphertext)

# decypt
raw = base64.b64decode(ciphertext)
decrypted_cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
decrypted_text = unpad(decrypted_cipher.decrypt(raw[AES.block_size:]), AES.block_size)

print(decrypted_text.decode('utf_8'))