import base64
import json
import hashlib
import os

from Crypto.Cipher import AES
from secrets import token_bytes
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# master password hash calculation
def gen_master_password_hash(passwd,salt):
    t_sha = hashlib.sha256()
    t_sha.update(salt.encode('utf-8') + passwd.encode('utf-8'))
    hashed_password = t_sha.hexdigest()
    return hashed_password

#check master password file exist
def check_exist_master_password():
    if pass_file.is_file():
        return True
    else:
        return False

# create master password and save to a file
# mode 1 for first creating
# mode 2 for changing password
def create_master_password(user_input, mode):
    hash_value = gen_master_password_hash(user_input, fix_salt)
    # check if the file exist
    if check_exist_master_password():  #if file exist
        saved_pass_hash_value = get_passwd_from_file()
        if saved_pass_hash_value is not None:
            if(mode == 1):
                print("Master password already existed")
            elif(mode == 2):
                pass_key_pair = {'pass_hash': hash_value}
                with open(pass_file, 'w') as file:
                    json.dump(pass_key_pair, file) 
                    print("Master password created successfully")
    else:
        # write hash value to a file
        pass_key_pair = {'pass_hash': hash_value}
        with open(pass_file, 'w') as file:
            json.dump(pass_key_pair, file) 
            print("Master password created successfully")
        print("Secret key is creating...")
        create_secret_key(user_input,fix_salt, 1)
        key = open_secret_key(user_input,fix_salt)
        print("Your secret key is: ")
        print(key)

# change master password
def change_master_password():
    old_master_passwd = input("Please enter your old password: ")
    while check_master_password(old_master_passwd) == False:
        print("Your master password is not correct")
        old_master_passwd = input("Please enter your old password: ")
    new_master_passwd = input('Please enter your new master password: ')
    create_master_password(new_master_passwd, 2)
    print("Secret key is creating...")
    create_secret_key(new_master_passwd,fix_salt, 2, old_master_passwd)
    key = open_secret_key(new_master_passwd,fix_salt)
    print("Your secret key is: ")
    print(key)

# read master password file             
def get_passwd_from_file():
    with open(pass_file, "r") as file:
        content = json.load(file)
        saved_pass_hash_value = content.get('pass_hash')
        return saved_pass_hash_value
    
# check the master password true or not
def check_master_password(input_passwd):
    input_passwd_hash_value = gen_master_password_hash(input_passwd, fix_salt)
    saved_passwd_hash_value = get_passwd_from_file()
    if ( input_passwd_hash_value != saved_passwd_hash_value ):
        return False
    else:
        return True

# PBKDF2HMAC master password
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

# open secret key from file
def open_secret_key(master_passwd, salt):
    passwd_cipher = Fernet(gen_master_passwd_key(master_passwd, salt))
    with open(key_file, "r") as file:
        content = json.load(file)
        encrypted_key = bytes.fromhex(content.get('key')) #convert from hex to bytes
        key = passwd_cipher.decrypt(encrypted_key)
    return key

# def create new secret key then save to a file
# mode 1 for first creating
# mode 2 for changing password
def create_secret_key(master_passwd, salt, mode, old_passwd = ''):
    passwd_cipher = Fernet(gen_master_passwd_key(master_passwd, salt))
    if (mode == 1):
        key = token_bytes(AES.block_size)
    elif (mode == 2):
        key = open_secret_key(old_passwd, salt)
    key_data_encrypted = passwd_cipher.encrypt(key)
    data = {'key': key_data_encrypted.hex()}    #save key as hex value
    with open(key_file, "w") as file:
        json.dump(data, file)

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
pass_file = Path(".\key\pass.txt")
key = ''
iv = token_bytes(AES.block_size)
fix_salt = '274f2589a5002d3d8e8412c2a877729b' # hex
passwd_cipher = ''

# encrypted_text = encrypt_AES(key,iv, utf8_passwd)
# decrypted_text = decrypt_AES(key,encrypted_text)
# print( 'decrypted text: '+ decrypted_text)

# master_passwd_hash_value = gen_master_password_hash(master_passwd, fix_salt)
# print( 'maste passwd hash value: '+ master_passwd_hash_value)