#!/usr/bin/python3

# Module Imports
import mysql.connector
import project
from project import newrunconfig

dbase = mysql.connector.connect(**newrunconfig.db_login)

mycursor = dbase.cursor()

sql = "INSERT INTO tableno2 (name, address) VALUES (%s, %s)"

val1 = input('name: ')
val2 = input('email address: ')

mycursor.execute (sql, (val1, val2 )) 

dbase.commit()

print (mycursor.rowcount, "record inserted.")
