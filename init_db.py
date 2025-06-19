import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            barangay TEXT,
            municipality TEXT,
            province TEXT,
            contact_no TEXT,
            position TEXT,
            first_name TEXT,
            middle_name TEXT,
            last_name TEXT,
            age INTEGER,
            house_no TEXT,
            street_no TEXT
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()