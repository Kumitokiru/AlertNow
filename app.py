from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_socketio import SocketIO
import logging
import ast
import os
import json
import sqlite3
import joblib
import cv2
import numpy as np
from collections import Counter
# Corrected imports: Changed relative imports to absolute imports
# Assuming these files are in the same directory as app.py
from BarangayDashboard import get_barangay_stats, get_latest_alert
from CDRRMODashboard import get_cdrmo_stats
from PNPDashboard import get_pnp_stats
from alert_data import alerts

app = Flask(__name__)
app.secret_key = 'your-secret-key-here' # Replace with a strong, secret key
socketio = SocketIO(app, cors_allowed_origins="*")
logging.basicConfig(level=logging.DEBUG)

# Load barangay_coords from coords.txt (assuming it's in an 'assets' folder)
try:
    with open(os.path.join('assets', 'coords.txt'), 'r') as f:
        barangay_coords = ast.literal_eval(f.read())
except FileNotFoundError:
    logging.error("coords.txt not found in assets directory. Using empty dict.")
    barangay_coords = {}
except Exception as e:
    logging.error(f"Error loading coords.txt: {e}. Using empty dict.")
    barangay_coords = {}

# Example municipality coordinates (if not in coords.txt)
municipality_coords = {
    "San Pablo City": {"lat": 14.0642, "lon": 121.3233},
    "Quezon Province": {"lat": 13.9347, "lon": 121.9473}
}


# Load Google Maps API key from environment variable or use a default
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', 'AIzaSyBSXRZPDX1x1d91Ck-pskiwGA8Y2-5gDVs')

# Load ML model
try:
    dt_classifier = joblib.load('decision_tree_model.pkl')
    logging.info("decision_tree_model.pkl loaded successfully.")
except FileNotFoundError:
    logging.error("decision_tree_model.pkl not found. ML prediction will not work.")
    dt_classifier = None
except Exception as e:
    logging.error(f"Error loading decision_tree_model.pkl: {e}")
    dt_classifier = None

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def construct_username(role, municipality=None, barangay=None, contact_no=None):
    """Constructs a unique username based on the role and relevant details."""
    if role == 'barangay':
        return f"{barangay}_{contact_no}"
    else: # cdrmo or pnp
        return f"{role}_{municipality}_{contact_no}"

@app.route('/')
def home():
    """Redirects to the signup type selection page."""
    app.logger.debug("Rendering SignUpType.html")
    return render_template('SignUpType.html')

@app.route('/signup_barangay', methods=['GET', 'POST'])
def signup_barangay():
    """Handles signup for Barangay officials via web form."""
    app.logger.debug("Accessing /signup_barangay with method: %s", request.method)
    if request.method == 'POST':
        # Retrieve form data
        barangay = request.form['barangay']
        municipality = request.form['municipality']
        province = request.form['province']
        contact_no = request.form['contact_no']
        password = request.form['password']
        
        # Construct username
        username = construct_username('barangay', barangay=barangay, contact_no=contact_no)
        
        conn = get_db_connection()
        try:
            # Insert user into database
            conn.execute('''
                INSERT INTO users (username, password, role, barangay, municipality, province, contact_no)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, password, 'barangay', barangay, municipality, province, contact_no))
            conn.commit()
            app.logger.debug("Web user signed up: %s", username)
            return redirect(url_for('login')) # Redirect to web login page
        except sqlite3.IntegrityError:
            app.logger.error("Web signup failed: Username %s already exists", username)
            return "Username already exists", 400
        except Exception as e:
            app.logger.error(f"Web signup failed for {username}: {e}", exc_info=True)
            return f"Signup failed: {e}", 500
        finally:
            conn.close()
    return render_template('SignUpPage.html')

@app.route('/signup_resident', methods=['POST'])
def signup_resident():
    """Handles signup for Resident/Official roles from Android app (via API)."""
    app.logger.debug("Accessing /signup_resident with method: POST (API)")
    data = request.get_json()
    
    # Extract data from JSON payload
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'resident') # Default to 'resident' if not specified
    barangay = data.get('barangay')
    municipality = data.get('municipality')
    province = data.get('province')
    contact_no = data.get('contact_no')
    first_name = data.get('first_name')
    middle_name = data.get('middle_name')
    last_name = data.get('last_name')
    age = data.get('age')
    house_no = data.get('house_no')
    street_no = data.get('street_no')
    position = data.get('position') if role == 'official' else None

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO users (username, password, role, barangay, municipality, province, contact_no,
                              first_name, middle_name, last_name, age, house_no, street_no, position)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, password, role, barangay, municipality, province, contact_no,
              first_name, middle_name, last_name, age, house_no, street_no, position))
        conn.commit()
        app.logger.debug("Resident/Official signed up via API: %s", username)
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        app.logger.error("API signup failed: Username %s already exists", username)
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        app.logger.error(f"API signup failed for {username}: {e}", exc_info=True)
        return jsonify({'error': f'Signup failed: {e}'}), 500
    finally:
        conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles login for Barangay officials via web form."""
    app.logger.debug("Accessing /login with method: %s", request.method)
    if request.method == 'POST':
        # Retrieve form data for Barangay official login
        barangay = request.form['barangay']
        contact_no = request.form['contact_no']
        password = request.form['password']
        
        # Construct username based on web signup logic
        username = construct_username('barangay', barangay=barangay, contact_no=contact_no)
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['role'] = user['role']
            if user['role'] == 'barangay':
                app.logger.debug(f"Web login successful for barangay: {username}")
                return redirect(url_for('barangay_dashboard'))
            else:
                app.logger.warning(f"Web login for /login attempted by non-barangay role: {username} ({user['role']})")
                return "Unauthorized role for this login page", 403
        app.logger.warning(f"Web login failed for username: {username}")
        return "Invalid credentials", 401
    return render_template('LoginPage.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    """Handles login from Android app (via API)."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    conn.close()
    
    if user:
        app.logger.debug(f"API login successful for user: {username} with role: {user['role']}")
        return jsonify({'status': 'success', 'role': user['role']})
    app.logger.warning(f"API login failed for username: {username}")
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/signup_cdrmo_pnp', methods=['GET', 'POST'])
def signup_cdrmo_pnp():
    """Handles signup for CDRRMO/PNP roles via web form."""
    app.logger.debug("Accessing /signup_cdrmo_pnp with method: %s", request.method)
    if request.method == 'POST':
        # Retrieve form data
        role = request.form['role'].lower()
        municipality = request.form['municipality']
        contact_no = request.form['contact_no']
        password = request.form['password']
        
        # Construct username
        username = construct_username(role, municipality=municipality, contact_no=contact_no)
        
        conn = get_db_connection()
        try:
            # Insert user into database
            conn.execute('''
                INSERT INTO users (username, password, role, municipality, contact_no)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password, role, municipality, contact_no))
            conn.commit()
            app.logger.debug("Web user signed up: %s", username)
            return redirect(url_for('login_cdrmo_pnp')) # Redirect to CDRRMO/PNP web login
        except sqlite3.IntegrityError:
            app.logger.error("Web signup failed: Username %s already exists", username)
            return "Username already exists", 400
        except Exception as e:
            app.logger.error(f"Web signup failed for {username}: {e}", exc_info=True)
            return f"Signup failed: {e}", 500
        finally:
            conn.close()
    return render_template('CDRRMOPNPUp.html')

# --- Web App Navigation Routes ---
@app.route('/go_to_login_page', methods=['GET'])
def go_to_login_page():
    app.logger.debug("Redirecting to /login (Barangay/Resident web login)")
    return redirect(url_for('login'))

@app.route('/go_to_signup_type', methods=['GET'])
def go_to_signup_type():
    app.logger.debug("Redirecting to / (web signup type selection)")
    return redirect(url_for('home'))

@app.route('/chooese_login_type', methods=['GET'])
def chooese_login_type():
    app.logger.debug("Rendering LoginType.html (web)")
    return render_template('LoginType.html')

@app.route('/go_to_cdrrmopnpin', methods=['GET'])
def go_to_cdrrmopnpin():
    app.logger.debug("Redirecting to /login_cdrmo_pnp (CDRRMO/PNP web login)")
    return redirect(url_for('login_cdrmo_pnp'))

@app.route('/signup_muna', methods=['GET']) # Typo in original, keeping for compatibility
def signup_muna():
    app.logger.debug("Redirecting to /signup_cdrmo_pnp (CDRRMO/PNP web signup)")
    return redirect(url_for('signup_cdrmo_pnp'))

@app.route('/signup_na', methods=['GET']) # Typo in original, keeping for compatibility
def signup_na():
    app.logger.debug("Redirecting to /signup_barangay (Barangay/Resident web signup)")
    return redirect(url_for('signup_barangay'))


@app.route('/login_cdrmo_pnp', methods=['GET', 'POST'])
def login_cdrmo_pnp():
    """Handles login for CDRRMO/PNP roles via web form."""
    app.logger.debug("Accessing /login_cdrmo_pnp with method: %s", request.method)
    if request.method == 'POST':
        municipality = request.form['municipality']
        contact_no = request.form['contact_no']
        password = request.form['password']
        
        # Attempt to log in as CDRRMO or PNP
        username_cdrmo = construct_username('cdrmo', municipality=municipality, contact_no=contact_no)
        username_pnp = construct_username('pnp', municipality=municipality, contact_no=contact_no)
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username_cdrmo, password)).fetchone()
        if not user: # If not found as CDRRMO, try as PNP
            user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username_pnp, password)).fetchone()
        conn.close()
        
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            app.logger.debug(f"Web login successful for user: {user['username']} ({user['role']})")
            if user['role'] == 'cdrmo':
                return redirect(url_for('cdrrmo_dashboard'))
            elif user['role'] == 'pnp':
                return redirect(url_for('pnp_dashboard'))
        app.logger.warning(f"Web login failed for municipality: {municipality}, contact: {contact_no}")
        return "Invalid credentials", 401
    return render_template('CDRRMOPNPIn.html')

@app.route('/logout')
def logout():
    """Logs out the current user and redirects based on their previous role."""
    role = session.pop('role', None) # Get role before clearing session
    session.clear() # Clear all session data
    app.logger.debug(f"User logged out. Redirecting from role: {role}")
    if role == 'barangay':
        return redirect(url_for('login')) # Redirect to Barangay login
    else: # Default for CDRRMO/PNP or other roles
        return redirect(url_for('login_cdrmo_pnp'))

def load_coords():
    coords_path = os.path.join(app.root_path, 'assets', 'coords.txt')
    alerts = []
    try:
        with open(coords_path, 'r') as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    parts = line.strip().split(',')
                    if len(parts) == 4:
                        barangay, municipality, message, timestamp = parts
                        alerts.append({
                            "barangay": barangay.strip(),
                            "municipality": municipality.strip(),
                            "message": message.strip(),
                            "timestamp": timestamp.strip()
                        })
    except FileNotFoundError:
        print("Warning: coords.txt not found, using empty alerts.")
    except Exception as e:
        print(f"Error loading coords.txt: {e}")
    return alerts

alerts = load_coords()



@app.route('/add_alert', methods=['POST'])
def add_alert():
    data = request.form
    new_alert = {
        "barangay": data['barangay'],
        "municipality": data['municipality'],
        "message": data['message'],
        "timestamp": data['timestamp']
    }
    alerts.append(new_alert)
    return jsonify({"status": "success", "alert": new_alert})

@app.route('/export_alerts')
def export_alerts():
    with open('alerts.json', 'w') as f:
        json.dump(alerts, f, indent=4)
    return jsonify({"status": "success", "file": "alerts.json"})

@app.route('/api/predict_image', methods=['POST'])
def predict_image():
    """Placeholder API for image classification (uses pre-trained model)."""
    if dt_classifier == None:
        return jsonify({'error': 'Model not loaded'}), 500
    data = request.get_json()
    base64_image = data.get('image')
    if not base64_image:
        return jsonify({'error': 'No image provided'}), 400
    
    try:
        import base64
        # Decode base64 image
        img_data = base64.b64decode(base64_image)
        nparr = np.frombuffer(img_data, np.uint8)
        # Read as grayscale image
        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        
        if img == None:
            return jsonify({'error': 'Failed to decode image'}), 400

        img = cv2.resize(img, (64, 64)) # Resize to model's expected input size
        features = img.flatten().reshape(1, -1) # Flatten and reshape for prediction
        
        prediction = dt_classifier.predict(features)[0] # Get prediction
        app.logger.debug(f"Image predicted as: {prediction}")
        return jsonify({'emergency_type': prediction})
    except Exception as e:
        app.logger.error(f"Image prediction failed: {e}", exc_info=True)
        return jsonify({'error': 'Prediction failed'}), 500

@app.route('/api/distribution')
def get_distribution():
    """Returns the distribution of emergency types based on roles."""
    role = request.args.get('role', 'all')
    if role == 'barangay':
        stats = get_barangay_stats()
    elif role == 'cdrmo':
        stats = get_cdrmo_stats()
    elif role == 'pnp':
        stats = get_pnp_stats()
    else: # 'all' or any other value
        stats = Counter([a.get('emergency_type', 'unknown') for a in alerts])
    
    app.logger.debug(f"Distribution for role '{role}': {dict(stats)}")
    return jsonify(dict(stats))

@app.route('/barangay_dashboard')
def barangay_dashboard():
    """Renders the Barangay Dashboard for logged-in Barangay officials."""
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    # Ensure user is logged in and has the correct role
    if not username or not user or user['role'] != 'barangay':
        app.logger.warning("Unauthorized access to barangay_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login'))
    
    barangay = user['barangay']
    municipality = user['municipality'] or 'San Pablo City' # Fallback for municipality
    
    # Get latest alert and stats (from separate modules)
    latest_alert = get_latest_alert()
    stats = get_barangay_stats()
    
    # Get coordinates for the barangay
    coords = barangay_coords.get(municipality, {}).get(barangay, {'lat': 14.5995, 'lon': 120.9842}) # Default coords
    
    # Convert coordinates to float, with error handling
    try:
        lat_coord = float(coords.get('lat', 14.5995))
        lon_coord = float(coords.get('lon', 120.9842))
    except (ValueError, TypeError):
        app.logger.error(f"Invalid coordinates for {barangay} in {municipality}, using defaults")
        lat_coord = 14.5995
        lon_coord = 120.9842

    app.logger.debug(f"Rendering BarangayDashboard for {barangay} in {municipality} with coords: lat={lat_coord}, lon={lon_coord}")
    return render_template('BarangayDashboard.html', 
                           latest_alert=latest_alert, 
                           stats=stats, 
                           barangay=barangay, 
                           lat_coord=lat_coord, 
                           lon_coord=lon_coord, 
                           google_api_key=GOOGLE_API_KEY)

@app.route('/cdrrmo_dashboard')
def cdrrmo_dashboard():
    """Renders the CDRRMO Dashboard for logged-in CDRRMO officials."""
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    # Ensure user is logged in and has the correct role
    if not username or not user or user['role'] != 'cdrmo':
        app.logger.warning("Unauthorized access to cdrrmo_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login_cdrmo_pnp'))
    
    municipality = user['municipality']
    stats = get_cdrmo_stats()
    
    # Get municipality coordinates
    coords = municipality_coords.get(municipality, {'lat': 14.5995, 'lon': 120.9842}) # Default coords
    
    # Convert coordinates to float, with error handling
    try:
        lat_coord = float(coords.get('lat', 14.5995))
        lon_coord = float(coords.get('lon', 120.9842))
    except (ValueError, TypeError):
        app.logger.error(f"Invalid coordinates for {municipality}, using defaults")
        lat_coord = 14.5995
        lon_coord = 120.9842

    app.logger.debug(f"Rendering CDRRMODashboard for {municipality} with coords: lat={lat_coord}, lon={lon_coord}")
    return render_template('CDRRMODashboard.html', 
                           stats=stats, 
                           municipality=municipality, 
                           lat_coord=lat_coord, 
                           lon_coord=lon_coord, 
                           google_api_key=GOOGLE_API_KEY)

@app.route('/pnp_dashboard')
def pnp_dashboard():
    """Renders the PNP Dashboard for logged-in PNP officials."""
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    # Ensure user is logged in and has the correct role
    if not username or not user or user['role'] != 'pnp':
        app.logger.warning("Unauthorized access to pnp_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login_cdrmo_pnp'))
    
    municipality = user['municipality']
    stats = get_pnp_stats()
    
    # Get municipality coordinates
    coords = municipality_coords.get(municipality, {'lat': 14.5995, 'lon': 120.9842}) # Default coords
    
    # Convert coordinates to float, with error handling
    try:
        lat_coord = float(coords.get('lat', 14.5995))
        lon_coord = float(coords.get('lon', 120.9842))
    except (ValueError, TypeError):
        app.logger.error(f"Invalid coordinates for {municipality}, using defaults")
        lat_coord = 14.5995
        lon_coord = 120.9842

    app.logger.debug(f"Rendering PNPDashboard for {municipality} with coords: lat={lat_coord}, lon={lon_coord}")
    return render_template('PNPDashboard.html', 
                           stats=stats, 
                           municipality=municipality, 
                           lat_coord=lat_coord, 
                           lon_coord=lon_coord, 
                           google_api_key=GOOGLE_API_KEY)

# Initialize database if it doesn't exist
# This should ideally be run once, e.g., on deployment or first run
# from init_db import init_db
# init_db()

if __name__ == '__main__':
    # Ensure the database is initialized when the app starts
    try:
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
        logging.info("Database 'users.db' initialized successfully or already exists.")
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}", exc_info=True)

    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True) # allow_unsafe_werkzeug for development
