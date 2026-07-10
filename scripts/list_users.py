import sqlite3, os, sys

db='instance/secureauth.db'
if not os.path.exists(db):
    print('DB not found', db)
    sys.exit(1)

conn=sqlite3.connect(db)
cur=conn.cursor()
cur.execute('SELECT id,email,role FROM users')
rows=cur.fetchall()
for r in rows:
    print(r)
conn.close()
