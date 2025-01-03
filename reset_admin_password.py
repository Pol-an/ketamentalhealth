# reset_admin_password.py

import sqlite3
from werkzeug.security import generate_password_hash
import os

DATABASE = 'clinic.db'

def reset_admin_password(new_password):
    hashed_password = generate_password_hash(new_password, method='sha256')
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, 'admin'))
    conn.commit()
    conn.close()
    print("Admin password has been reset successfully.")

if __name__ == "__main__":
    new_password = input("Enter new admin password: ")
    reset_admin_password(new_password)
