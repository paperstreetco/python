#!/usr/bin/python3

# Module Imports
import mysql.connector
import project
from project import newrunconfig

dbase = mysql.connector.connect(**newrunconfig.db_login)

mycursor = dbase.cursor()

mycursor.execute("CREATE TABLE tableno2 (name VARCHAR(255), address VARCHAR(255))")

mycursor.close()
dbase.close()




