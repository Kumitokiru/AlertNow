from alert_data import alerts
from collections import Counter
from flask import request, jsonify, session
from datetime import datetime
import pytz
import logging
import sqlite3
import os


logger = logging.getLogger(__name__)

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_pnp_stats():
    try:
        types = [a.get('emergency_type', 'unknown') for a in alerts if a.get('role') == 'pnp' or a.get('municipality')]
        return Counter(types)
    except Exception as e:
        logger.error(f"Error in get_pnp_stats: {e}")
        return Counter()

def get_latest_alert():
    try:
        if alerts:
            return alerts[-1]
        return None
    except Exception as e:
        logger.error(f"Error in get_latest_alert: {e}")
        return None
    
def get_the_pnp_stats():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT COUNT(*) as total 
            FROM pnp_response
        ''')
        total = cursor.fetchone()['total']
        conn.close()
        return type('Stats', (), {'total': lambda self: total})()
    except Exception as e:
        logger.error(f"Error fetching pnp stats: {e}")
        return type('Stats', (), {'total': lambda self: 0})()

def get_pnp_new_alert():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT alert_id, emergency_type, timestamp 
            FROM pnp_response
            ORDER BY timestamp DESC LIMIT 1
        ''')
        alert = cursor.fetchone()
        conn.close()
        return dict(alert) if alert else None
    except Exception as e:
        logger.error(f"Error fetching latest alert: {e}")
        return None

def get_pnp_alerts_per_month():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT strftime('%m', datetime(timestamp)) as month, COUNT(*) as count 
            FROM pnp_response 
            WHERE timestamp IS NOT NULL AND datetime(timestamp) IS NOT NULL
            UNION ALL
            SELECT strftime('%m', datetime(timestamp)) as month, COUNT(*) as count 
            FROM pnp_fire_response 
            WHERE timestamp IS NOT NULL AND datetime(timestamp) IS NOT NULL
            UNION ALL
            SELECT strftime('%m', datetime(timestamp)) as month, COUNT(*) as count 
            FROM pnp_crime_response 
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
        
def get_pnp_responded_count():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT SUM(count) as count
            FROM (
                SELECT COUNT(*) as count 
                FROM pnp_response 
                WHERE responded = TRUE
                UNION ALL
                SELECT COUNT(*) as count 
                FROM pnp_fire_response 
                WHERE responded = TRUE
                UNION ALL
                SELECT COUNT(*) as count 
                FROM pnp_crime_response 
                WHERE responded = TRUE
            )
        ''')
        count = cursor.fetchone()['count']
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Error fetching responded count: {e}")
        return 0

def emit_pnp_alerts_per_month_update(socketio):
    alerts_per_month = get_pnp_alerts_per_month()
    socketio.emit('update_alerts_per_month', alerts_per_month, room='pnp')
    
def get_heatmap_data(municipality):
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT lat, lon FROM pnp_response WHERE municipality = ?', (municipality,))
    data = cursor.fetchall()
    conn.close()
    return [{'lat': row[0], 'lon': row[1]} for row in data]

# Add this near the existing socketio event definitions (e.g., after @socketio.on('alert'))
def save_pnp_officer():
    data = request.get_json()
    municipality = session.get('municipality')
    position = data.get('position')
    name = data.get('name')
    timestamp = datetime.now(pytz.timezone('Asia/Manila')).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO pnp_officer (municipality, position, name, created_at) VALUES (?, ?, ?, ?)',
        (municipality, position, name, timestamp)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

def get_recent_pnp_officers():
    municipality = session.get('municipality')
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT position, name, created_at 
        FROM pnp_officer 
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
    
def handle_store_pnp_alert(data):
    try:
        conn = get_db_connection()
        timestamp = data.get('timestamp') or data.get('time') or datetime.now(pytz.timezone('Asia/Manila')).isoformat()
        conn.execute('''
            INSERT OR IGNORE INTO pnp_alert (alert_id, status, time, barangay, type, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['alert_id'], 'PENDING', timestamp, data.get('barangay'), data.get('emergency_type'), data.get('image', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing pnp alert: {e}")

def handle_load_pnp_alerts():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM pnp_alert").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading pnp alerts: {e}")
        return jsonify([])

def handle_load_pnp_expired():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM pnp_alert_expire ORDER BY time DESC").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading expired pnp alerts: {e}")
        return jsonify([])

def handle_move_pnp_to_recent(alert_id):
    try:
        conn = get_db_connection()
        alert = conn.execute("SELECT * FROM pnp_alert WHERE alert_id = ?", (alert_id,)).fetchone()
        if alert:
            conn.execute('''
                INSERT OR IGNORE INTO pnp_alert_expire (alert_id, status, time, barangay, type, image, lat, lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert['alert_id'], 'EXPIRED', alert['time'], alert['barangay'], alert['type'], alert['image'], alert['lat'], alert['lon']))
            conn.execute("DELETE FROM pnp_alert WHERE alert_id = ?", (alert_id,))
            conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def handle_remove_pnp_alert(alert_id):
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM pnp_alert WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error removing pnp alert: {e}")
        return False
    
