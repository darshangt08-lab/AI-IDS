import sqlite3
import os

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # User table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    # Network logs table
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  source_ip TEXT,
                  protocol TEXT,
                  service TEXT,
                  attack_type TEXT,
                  status TEXT)''')
    
    # Blocked IPs table
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip_address TEXT UNIQUE NOT NULL,
                  reason TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    # Add a default admin user for testing (password: admin123)
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
    except sqlite3.IntegrityError:
        pass
        
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()
