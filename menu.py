from crypto_function import change_master_password,check_exist_master_password,check_master_password, create_master_password, set_encrypted_password, get_decrypted_password, auto_generate_passwd
from database_manager import store_passwords, find_encrypted_password, find_user
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
    print('2. Auto generate new password')
    print('3. Find all sites and apps connected to an email')
    print('4. Find a password for a site or app')
    print('Q. Exit')
    print('-'*30)
    return input(': ')

def create(mode):
    print('Please proivide the name of the site or app you want to generate a password for')
    app_name = input()
    passwd = ''
    plaintext = ''
    if( mode == 1 ):   
        print('Please provide a simple password for this site: ')
        plaintext = input()
        passwd = set_encrypted_password(plaintext)
    elif( mode == 2 ):
        plaintext = auto_generate_passwd()
        passwd = set_encrypted_password(plaintext)
    print('Your new password is: ' + plaintext)
    user_email = input('Please provide a user email for this app or site: ')
    username = input('Please provide a username for this app or site (if applicable): ')
    if username == None:
        username = ''
    url = input('Please paste the url to the site that you are creating the password for: ')
    store_passwords(passwd, user_email, username, url, app_name)
    continue_or_not(mode)

def find_password_for_app():
    mode = 4
    app_name = input('Please enter the application\'s name: ')
    encrypted_passwd = find_encrypted_password(app_name)
    if(encrypted_passwd != -1):
        decrypted_passwd = get_decrypted_password(encrypted_passwd)
        print('Your password for ' + app_name + ' is: ' + decrypted_passwd)
        continue_or_not(mode)
    else:
        print('Cannot find the app name or password!!!')
        find_password_for_app()    

def find_accounts():
    mode = 3
    user_email = input('Please enter the email that you want to find account for: ')
    result = find_user(user_email)
    title = ('Password: ', 'Email: ', 'Username: ', 'url: ', 'App/Site name: ')
    print('')
    print('RESULT')
    print('')
    for row in result:
        for i in range( 0, len(row) - 1 ):
            if ( i == 0 ): #password column
                decrypted_password = get_decrypted_password(row[i])
                print(title[i] + decrypted_password)
            else:
                print(title[i] + row[i])
        print('')
        print('-'*30)
    continue_or_not(mode)

def continue_or_not(choice):
    print("choice : " + str(choice))
    answer = input('Do you want to continue [Y/n]: ')
    if answer.lower() in {"y", "yes"}:
        if choice == 1: #create passwd
            create(1)
        if choice == 2:
            create(2)
        if choice == 3:
            find_accounts()
        if choice == 4:
            find_password_for_app()
    elif answer.lower() in {"n", "no"}:
        return_main_menu()
    else:
        continue_or_not(choice)

def return_main_menu():
    global choice
    choice = main_menu()

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
        create(1)
    if choice == '2':
        create(2)
    if choice == '3':
        find_accounts()
    if choice == '4':
        find_password_for_app()
    else:
        choice = main_menu()
exit()
