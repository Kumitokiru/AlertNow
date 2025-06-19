from flask import request, redirect, url_for, render_template
import sqlite3

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def signup_cdrmo_pnp():
    if request.method == 'POST':
        role = request.form['role']
        municipality = request.form['municipality']
        contact_no = request.form['contact_no']
        password = request.form['password']
        username = f"{role}_{municipality}_{contact_no}"
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password, role, municipality, contact_no)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password, role, municipality, contact_no))
            conn.commit()
            return redirect(url_for('login_cdrrmo_pnp'))
        except sqlite3.IntegrityError:
            return "Username already exists", 400
        finally:
            conn.close()
    return render_template('CDRRMOPNPUp.html')

def signup_muna():
    return render_template('CDRRMOPNPUp.html')