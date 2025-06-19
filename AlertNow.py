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
from datetime import datetime
from alert_data import alerts
from collections import deque

# Assuming these files are in the same directory as app.py
from BarangayDashboard import get_barangay_stats, get_latest_alert
from CDRRMODashboard import get_cdrrmo_stats
from PNPDashboard import get_pnp_stats
from alert_data import alerts

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a strong, secret key
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

# Example municipality coordinates (expand this dictionary with all assigned municipalities)
municipality_coords = {
    "San Pablo City": {"lat": 14.0642, "lon": 121.3233},
    "Quezon Province": {"lat": 13.9347, "lon": 121.9473},
    # Add more municipalities here based on sign-up data
    # Example: "Davao City": {"lat": 7.0731, "lon": 125.6125}
}

# Load Google Maps API key from environment variable or use a default
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', 'AIzaSyBSXRZPDX1x1d91Ck-pskiwGA8Y2-5gDVs')

@socketio.on('responded')
def handle_responded(data):
    timestamp = data.get('timestamp')
    lat = data.get('lat')
    lon = data.get('lon')
    barangay = data.get('barangay')
    emergency_type = data.get('emergency_type')
    app.logger.debug(f"Received response for alert at {timestamp} - Lat: {lat}, Lon: {lon}, Barangay: {barangay}, Type: {emergency_type}")
    # Add logic to update alert status or notify other clients if needed
    socketio.emit('alert_responded', {
        'timestamp': timestamp,
        'lat': lat,
        'lon': lon,
        'barangay': barangay,
        'emergency_type': emergency_type
    })

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
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def construct_username(role, municipality=None, barangay=None, contact_no=None):
    """Constructs a unique username based on the role and relevant details."""
    if role == 'barangay':
        return f"{barangay}_{contact_no}"
    else:  # cdrrmo or pnp
        return f"{role}_{municipality}_{contact_no}"

# --- Routes remain unchanged ---
@app.route('/')
def home():
    app.logger.debug("Rendering SignUpType.html")
    return render_template('SignUpType.html')

@app.route('/signup_barangay', methods=['GET', 'POST'])
def signup_barangay():
    app.logger.debug("Accessing /signup_barangay with method: %s", request.method)
    if request.method == 'POST':
        barangay = request.form['barangay']
        municipality = request.form['municipality']
        province = request.form['province']
        contact_no = request.form['contact_no']
        password = request.form['password']
        username = construct_username('barangay', barangay=barangay, contact_no=contact_no)
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password, role, barangay, municipality, province, contact_no)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, password, 'barangay', barangay, municipality, province, contact_no))
            conn.commit()
            app.logger.debug("Web user signed up: %s", username)
            return redirect(url_for('login'))
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
    app.logger.debug("Accessing /signup_resident with method: POST (API)")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'resident')
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
    app.logger.debug("Accessing /login with method: %s", request.method)
    if request.method == 'POST':
        barangay = request.form['barangay']
        contact_no = request.form['contact_no']
        password = request.form['password']
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
    return render_template('LogInPage.html')

@app.route('/api/login', methods=['POST'])
def api_login():
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

@app.route('/signup_cdrrmo_pnp', methods=['GET', 'POST'])
def signup_cdrrmo_pnp():
    app.logger.debug("Accessing /signup_cdrrmo_pnp with method: %s", request.method)
    if request.method == 'POST':
        role = request.form['role'].lower()
        municipality = request.form['municipality']
        contact_no = request.form['contact_no']
        password = request.form['password']
        username = construct_username(role, municipality=municipality, contact_no=contact_no)
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password, role, municipality, contact_no)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password, role, municipality, contact_no))
            conn.commit()
            app.logger.debug("Web user signed up: %s", username)
            return redirect(url_for('login_cdrrmo_pnp'))
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
    app.logger.debug("Redirecting to /login_cdrrmo_pnp (CDRRMO/PNP web login)")
    return redirect(url_for('login_cdrrmo_pnp'))

@app.route('/signup_muna', methods=['GET'])
def signup_muna():
    app.logger.debug("Redirecting to /signup_cdrrmo_pnp (CDRRMO/PNP web signup)")
    return redirect(url_for('signup_cdrrmo_pnp'))

@app.route('/signup_na', methods=['GET'])
def signup_na():
    app.logger.debug("Redirecting to /signup_barangay (Barangay/Resident web signup)")
    return redirect(url_for('signup_barangay'))

@app.route('/login_cdrrmo_pnp', methods=['GET', 'POST'])
def login_cdrrmo_pnp():
    app.logger.debug("Accessing /login_cdrrmo_pnp with method: %s", request.method)
    if request.method == 'POST':
        municipality = request.form['municipality']
        contact_no = request.form['contact_no']
        password = request.form['password']
        username_cdrrmo = construct_username('cdrrmo', municipality=municipality, contact_no=contact_no)
        username_pnp = construct_username('pnp', municipality=municipality, contact_no=contact_no)
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username_cdrrmo, password)).fetchone()
        if not user:
            user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username_pnp, password)).fetchone()
        conn.close()
        
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            app.logger.debug(f"Web login successful for user: {user['username']} ({user['role']})")
            if user['role'] == 'cdrrmo':
                return redirect(url_for('cdrrmo_dashboard'))
            elif user['role'] == 'pnp':
                return redirect(url_for('pnp_dashboard'))
        app.logger.warning(f"Web login failed for municipality: {municipality}, contact: {contact_no}")
        return "Invalid credentials", 401
    return render_template('CDRRMOPNPIn.html')

@app.route('/logout')
def logout():
    role = session.pop('role', None)
    session.clear()
    app.logger.debug(f"User logged out. Redirecting from role: {role}")
    if role == 'barangay':
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login_cdrrmo_pnp'))

def load_coords():
    coords_path = os.path.join(app.root_path, 'assets', 'coords.txt')
    alerts = []
    try:
        with open(coords_path, 'r') as f:
            for line in f:
                if line.strip():
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



alerts = deque(maxlen=100)

@app.route('/send_alert', methods=['POST'])
def send_alert():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        lat = data.get('lat')
        lon = data.get('lon')
        emergency_type = data.get('emergency_type', 'General')
        image = data.get('image')
        user_role = data.get('user_role', 'unknown')
        image_upload_time = data.get('imageUploadTime', datetime.now().isoformat())

        # Check image expiration
        if image:
            upload_time = datetime.fromisoformat(image_upload_time)
            if (datetime.now() - upload_time).total_seconds() > 30 * 60:
                image = None  # Expire image if older than 30 minutes
                emergency_type = 'Not Specified'

        alert = {
            'lat': lat,
            'lon': lon,
            'emergency_type': emergency_type,
            'image': image,
            'role': user_role,
            'barangay': data.get('barangay', 'N/A'),
            'timestamp': datetime.now().isoformat(),
            'imageUploadTime': image_upload_time
        }
        alerts.append(alert)
        socketio.emit('new_alert', alert)
        return jsonify({'status': 'success', 'message': 'Alert sent'}), 200
    except Exception as e:
        app.logger.error(f"Error processing send_alert: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500



# New /api/stats endpoint
@app.route('/api/stats')
def get_stats():
    total = len(alerts)
    critical = len([a for a in alerts if a.get('emergency_type', '').lower() == 'critical'])
    return jsonify({'total': total, 'critical': critical})

# Updated /api/distribution endpoint
@app.route('/api/distribution')
def get_distribution():
    role = request.args.get('role', 'all')
    if role == 'barangay':
        filtered_alerts = [a for a in alerts if a.get('role') == 'barangay' or a.get('barangay')]
    elif role == 'cdrrmo':
        filtered_alerts = [a for a in alerts if a.get('role') == 'cdrrmo' or a.get('municipality')]
    elif role == 'pnp':
        filtered_alerts = [a for a in alerts if a.get('role') == 'pnp' or a.get('municipality')]
    else:
        filtered_alerts = alerts
    types = [a.get('emergency_type', 'unknown') for a in filtered_alerts]
    return jsonify(dict(Counter(types)))

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
    if dt_classifier is None:
        return jsonify({'error': 'Model not loaded'}), 500
    data = request.get_json()
    base64_image = data.get('image')
    if not base64_image:
        return jsonify({'error': 'No image provided'}), 400
    
    try:
        import base64
        img_data = base64.b64decode(base64_image)
        nparr = np.frombuffer(img_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        
        if img is None:
            return jsonify({'error': 'Failed to decode image'}), 400

        img = cv2.resize(img, (64, 64))
        features = img.flatten().reshape(1, -1)
        prediction = dt_classifier.predict(features)[0]
        app.logger.debug(f"Image predicted as: {prediction}")
        return jsonify({'emergency_type': prediction})
    except Exception as e:
        app.logger.error(f"Image prediction failed: {e}", exc_info=True)
        return jsonify({'error': 'Prediction failed'}), 500



@app.route('/barangay_dashboard')
def barangay_dashboard():
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not username or not user or user['role'] != 'barangay':
        app.logger.warning("Unauthorized access to barangay_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login'))
    
    barangay = user['barangay']
    municipality = user['municipality'] or 'San Pablo City'
    latest_alert = get_latest_alert()
    stats = get_barangay_stats()
    coords = barangay_coords.get(municipality, {}).get(barangay, {'lat': 14.5995, 'lon': 120.9842})
    
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
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not username or not user or user['role'] != 'cdrrmo':
        app.logger.warning("Unauthorized access to cdrrmo_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login_cdrrmo_pnp'))
    
    municipality = user['municipality']
    if not municipality:
        app.logger.error(f"No municipality assigned for user {username}")
        municipality = "San Pablo City"  # Fallback municipality
    stats = get_cdrrmo_stats()
    coords = municipality_coords.get(municipality, {'lat': 14.5995, 'lon': 120.9842})
    
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
    username = session.get('username')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not username or not user or user['role'] != 'pnp':
        app.logger.warning("Unauthorized access to pnp_dashboard. Session: %s, User: %s", session, user)
        return redirect(url_for('login_cdrrmo_pnp'))
    
    municipality = user['municipality']
    if not municipality:
        app.logger.error(f"No municipality assigned for user {username}")
        municipality = "San Pablo City"  # Fallback municipality
    stats = get_pnp_stats()
    coords = municipality_coords.get(municipality, {'lat': 14.5995, 'lon': 120.9842})
    
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

if __name__ == '__main__':
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

    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
