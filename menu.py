from crypto_function import change_master_password,check_exist_master_password,check_master_password, create_master_password, set_encrypted_password
from database_manager import store_passwords
import subprocess

def menu():
    print('-'*30)
    print(('-'*13) + 'Menu'+ ('-' *13))
    print('1. If you do not have master password. Choose this')
    print('2. Log in')
    print('3. Change master password')
    print('Q. Exit')
    print('-'*30)
    return input(': ')

def create_password():
    user_input = input('Please enter a master password: ')
    create_master_password(user_input, 1)

def login():
    if (check_exist_master_password() == False):
        print('You do not have a master password, please create one.')
        create_password()
    else:
        passwd = input('Please enter the master password: ')
        # check master password correct or not
        if (check_master_password(passwd)):
            print('Master password is correct!!!')
            return True
        else:
            print('Master password is incorrect')
            return False
    
def menu_change_master_password():
    change_master_password()

def main_menu():
    print('-'*30)
    print(('-'*10) + 'Main Menu'+ ('-' *10))
    print('1. Create new password')
    print('2. Find all sites and apps connected to an email')
    print('3. Find a password for a site or app')
    print('Q. Exit')
    print('-'*30)
    return input(': ')

def create():
    print('Please proivide the name of the site or app you want to generate a password for')
    app_name = input()
    print('Please provide a simple password for this site: ')
    plaintext = input()
    passw = set_encrypted_password(plaintext)
    print('password: ' + passw.decode('utf-8'))
    # copy password to clipboaed
    # subprocess.run('xclip', universal_newlines=True, input=passw)
    print('-'*30)
    print('')
    print('Your password has now been created and copied to your clipboard')
    print('')
    print('-' *30)
    user_email = input('Please provide a user email for this app or site')
    username = input('Please provide a username for this app or site (if applicable)')
    if username == None:
        username = ''
    url = input('Please paste the url to the site that you are creating the password for')
    # store_passwords(passw, user_email, username, url, app_name)
choice = menu()
is_login = False

while not is_login:
    if choice == '1': #create master passwd
        create_password()
    if choice == '2':
        is_login = login()
    if choice == '3':
        menu_change_master_password()
    if choice == 'Q':
        exit()

choice = main_menu()
while choice != 'Q':
    if choice == '1': #create passwd
        create()
    if choice == '2':
        exit()
    if choice == '3':
        exit()
    else:
        choice = menu()
exit()
