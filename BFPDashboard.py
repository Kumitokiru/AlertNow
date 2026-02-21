from alert_data import alerts
from flask import request, jsonify, session
from datetime import datetime
import pytz
from collections import Counter
import logging
import sqlite3
import os

logger = logging.getLogger(__name__)

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_bfp_stats():
    try:
        types = [a.get('emergency_type', 'unknown') for a in alerts if a.get('role') == 'bfp' or a.get('assigned_municipality')]
        return Counter(types)
    except Exception as e:
        logger.error(f"Error in get_bfp_stats: {e}")
        return Counter()



def get_latest_alert():
    try:
        if alerts:
            return alerts[-1]
        return None
    except Exception as e:
        logger.error(f"Error in get_latest_alert: {e}")
        return None
    
def get_the_stat_bfp():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT alert_id, fire_type, timestamp 
            FROM bfp_response
            ORDER BY timestamp DESC LIMIT 1
        ''')
        alert = cursor.fetchone()
        conn.close()
        return dict(alert) if alert else None
    except Exception as e:
        logger.error(f"Error fetching latest alert: {e}")
        return None

def get_bfp_alerts_per_month():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT strftime('%m', datetime(timestamp)) as month, COUNT(*) as count 
            FROM bfp_response 
            WHERE timestamp IS NOT NULL AND datetime(timestamp) IS NOT NULL
            GROUP BY strftime('%m', datetime(timestamp))
        ''')
        month_names = {
            '01': 'January', '02': 'February', '03': 'March', '04': 'April',
            '05': 'May', '06': 'June', '07': 'July', '08': 'August',
            '09': 'September', '10': 'October', '11': 'November', '12': 'December'
        }
        alerts_per_month = {
            'January': 0, 'February': 0, 'March': 0, 'April': 0, 'May': 0, 'June': 0,
            'July': 0, 'August': 0, 'September': 0, 'October': 0, 'November': 0, 'December': 0
        }
        for row in cursor:
            month_num = row['month']
            if month_num in month_names:
                alerts_per_month[month_names[month_num]] = row['count']
        conn.close()
        return alerts_per_month
    except Exception as e:
        logger.error(f"Error fetching alerts per month: {e}")
        return {
            'January': 0, 'February': 0, 'March': 0, 'April': 0, 'May': 0, 'June': 0,
            'July': 0, 'August': 0, 'September': 0, 'October': 0, 'November': 0, 'December': 0
        }

def get_bfp_responded_count():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT COUNT(*) as count 
            FROM bfp_response 
            WHERE responded = TRUE
        ''')
        count = cursor.fetchone()['count']
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Error fetching responded count: {e}")
        return 0

def emit_bfp_alerts_per_month_update(socketio):
    alerts_per_month = get_bfp_alerts_per_month()
    socketio.emit('update_alerts_per_month', alerts_per_month, room='bfp')
    
def get_heatmap_data(municipality):
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT lat, lon FROM bfp_response WHERE municipality = ?', (municipality,))
    data = cursor.fetchall()
    conn.close()
    return [{'lat': row[0], 'lon': row[1]} for row in data]

def save_bfp_officer():
    data = request.get_json()
    municipality = session.get('municipality')
    position = data.get('position')
    name = data.get('name')
    timestamp = datetime.now(pytz.timezone('Asia/Manila')).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO bfp_officer (municipality, position, name, created_at) VALUES (?, ?, ?, ?)',
        (municipality, position, name, timestamp)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

def get_recent_bfp_officers():
    municipality = session.get('municipality')
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT position, name, created_at 
        FROM bfp_officer 
        WHERE municipality = ? 
        ORDER BY datetime(created_at) DESC 
        LIMIT 20
        ''',
        (municipality,)
    ).fetchall()
    conn.close()
    
    return jsonify([
        {
            'name': f"{r['position']} {r['name']}",
            'date': datetime.strptime(r['created_at'], '%Y-%m-%d %H:%M:%S')
                            .strftime('%B %d, %Y')
        }
        for r in rows
    ])
    
def handle_store_bfp_alert(data):
    try:
        conn = get_db_connection()
        timestamp = data.get('timestamp') or data.get('time') or datetime.now(pytz.timezone('Asia/Manila')).isoformat()
        conn.execute('''
            INSERT OR IGNORE INTO bfp_alert (alert_id, status, time, barangay, type, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['alert_id'], 'PENDING', timestamp, data.get('barangay'), data.get('emergency_type'), data.get('image', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing bfp alert: {e}")

def handle_load_bfp_alerts():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM bfp_alert").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading bfp alerts: {e}")
        return jsonify([])

def handle_load_bfp_expired():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM bfp_alert_expire ORDER BY time DESC").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading expired bfp alerts: {e}")
        return jsonify([])

def handle_move_bfp_to_recent(alert_id):
    try:
        conn = get_db_connection()
        # Fetching all 8 columns from bfp_alert to ensure no data loss
        alert = conn.execute("SELECT * FROM bfp_alert WHERE alert_id = ?", (alert_id,)).fetchone()
        if alert:
            # Insert into expire table including lat and lon for map persistence
            conn.execute('''
                INSERT OR IGNORE INTO bfp_alert_expire (alert_id, status, time, barangay, type, image, lat, lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert['alert_id'], 'EXPIRED', alert['time'], alert['barangay'], alert['type'], alert['image'], alert['lat'], alert['lon']))
            
            # Remove from live alert table
            conn.execute("DELETE FROM bfp_alert WHERE alert_id = ?", (alert_id,))
            conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error moving BFP alert to recent: {e}")
        return jsonify({'success': False})

def handle_remove_bfp_alert(alert_id):
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM bfp_alert WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error removing bfp alert: {e}")
        return False
    
def get_bfp_recent_counts():
    try:
        conn = get_db_connection()
        # Loads bfp_alert_expire
        cursor = conn.execute("SELECT type FROM bfp_alert_expire")
        rows = cursor.fetchall()
        conn.close()
        
        # Counts the number of BOTH Road Accident and Fire Incident
        total = sum(1 for r in rows if r['type'] in ['Road Accident', 'Fire Incident'])
        
        return jsonify({'total': total})
    except Exception as e:
        logger.error(f"Error getting bfp recent counts: {e}")
        return jsonify({'total': 0})