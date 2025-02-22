from crypto_function import check_exist_master_password,check_master_password, create_master_password


def menu():
    print('-'*30)
    print(('-'*13) + 'Menu'+ ('-' *13))
    print('1. If you do not have master password. Choose this')
    print('2. Log in')
    print('Q. Exit')
    print('-'*30)
    return input(': ')

def create_password():
    user_input = input('Please enter a master password: ')
    create_master_password(user_input)

def login():
    if (check_exist_master_password() == False):
        print('You do not have a master password, please create one.')
        create_password
    else:
        passwd = input('Please enter the master password: ')
        # check master password correct or not
        if (check_master_password(passwd)):
            print('Master password is correct!!!')
        else:
            print('Master password is incorre')

choice = menu()
while choice != 'Q':
    if choice == '1': #create master passwd
        create_password()
    if choice == '2':
        login()
    else:
        choice = menu()
exit()