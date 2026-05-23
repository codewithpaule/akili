import sqlite3

db = 'backend/akili.db'
conn = sqlite3.connect(db)
cur = conn.cursor()
cur.execute("SELECT timestamp,user_id,user_email,ip_address,action,detail FROM audit_logs WHERE action LIKE 'auth.api_key.%' ORDER BY timestamp DESC LIMIT 10")
rows = cur.fetchall()
for r in rows:
    print(r)
conn.close()
