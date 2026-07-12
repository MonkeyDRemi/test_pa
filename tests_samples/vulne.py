import os

eval("print('hack')")

os.system("rm -rf /")

db.execute("SELECT * FROM users") 

user_id = "123"
db.execute("SELECT * FROM users WHERE id = " + user_id) 

db.execute(f"SELECT * FROM users WHERE id = {user_id}")

sql = "SELECT * FROM users"
db.execute(sql)
