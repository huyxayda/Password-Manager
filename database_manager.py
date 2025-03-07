import psycopg2

def connect():
    try:
        conn = psycopg2.connect(
        database="password_manager",
        user='postgres',
        password='password',
        host='localhost',
        port='5432'
        )
        return conn
    except (Exception, psycopg2.Error) as error:
        print (error)

def store_passwords(password, user_email, username, url, app_name):
    try:
        connection = connect()
        cursor = connection.cursor()
        postgres_insert_query = """ INSERT INTO accounts (password, email, username, url, app_name) VALUES (%s, %s, %s, %s, %s)"""
        record_to_insert = (password, user_email, username, url, app_name)
        cursor.execute(postgres_insert_query, record_to_insert)
        connection.commit()
    except (Exception, psycopg2.Error) as error:
        print(error)

def find_encrypted_password(app_name):
    try:
        connection = connect()
        cursor = connection.cursor()
        postgres_select_query = """ SELECT password FROM accounts WHERE app_name = '""" + app_name + "'"
        cursor.execute(postgres_select_query, app_name)
        connection.commit()
        result = cursor.fetchone()
        return result[0]
    except (Exception, psycopg2.Error) as error:
        print(error)
        return -1

def find_user(user_email):
    try:
        connection = connect()
        cursor = connection.cursor()
        postgres_select_query = """ SELECT * FROM accounts WHERE email = '""" + user_email + "'"
        cursor.execute(postgres_select_query, user_email)
        connection.commit()
        result = cursor.fetchall()
        return result
    except (Exception, psycopg2.Error) as error:
        print(error)
