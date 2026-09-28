import sqlite3

connection = sqlite3.connect("database/forensic.db")
cursor = connection.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")

tables = cursor.fetchall()

print("Tables in database:")

for table in tables:
    print(table[0])

connection.close()