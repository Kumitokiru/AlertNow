from flask import request, redirect, url_for, render_template
import sqlite3

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def signup_barangay():
    if request.method == 'POST':
        barangay = request.form['barangay']
        municipality = request.form['municipality']
        province = request.form['province']
        contact_no = request.form['contact_no']
        password = request.form['password']
        username = f"{barangay}_{contact_no}"
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password, role, barangay, municipality, province, contact_no)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, password, 'barangay', barangay, municipality, province, contact_no))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists", 400
        finally:
            conn.close()
    return render_template('SignUpPage.html')

def signup_na():
    return render_template('SignUpPage.html')