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
