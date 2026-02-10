from flask import request, jsonify, session
from datetime import datetime
import pytz

from alert_data import alerts
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

def get_cdrrmo_stats():
    try:
        types = [a.get('emergency_type', 'unknown') for a in alerts if a.get('role') == 'cdrrmo' or a.get('assigned_municipality')]
        return Counter(types)
    except Exception as e:
        logger.error(f"Error in get_cdrrmo_stats: {e}")
        return Counter()

def get_latest_alert():
    if alerts:
        return list(alerts)[-1]
    return None



def get_the_cdrrmo_stats():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT COUNT(*) as total 
            FROM cdrrmo_response
        ''')
        total = cursor.fetchone()['total']
        conn.close()
        return type('Stats', (), {'total': lambda self: total})()
    except Exception as e:
        logger.error(f"Error fetching CDRRMO stats: {e}")
        return type('Stats', (), {'total': lambda self: 0})()

def get_cdrrmo_new_alert():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT alert_id, emergency_type, timestamp 
            FROM cdrrmo_response
            ORDER BY timestamp DESC LIMIT 1
        ''')
        alert = cursor.fetchone()
        conn.close()
        return dict(alert) if alert else None
    except Exception as e:
        logger.error(f"Error fetching latest alert: {e}")
        return None

def get_cdrrmo_alerts_per_month():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT strftime('%m', datetime(timestamp)) as month, COUNT(*) as count 
            FROM cdrrmo_response 
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

def get_cdrrmo_responded_count():
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT COUNT(*) as count 
            FROM cdrrmo_response 
            WHERE responded = TRUE
        ''')
        count = cursor.fetchone()['count']
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Error fetching responded count: {e}")
        return 0

def emit_cdrrmo_alerts_per_month_update(socketio):
    alerts_per_month = get_cdrrmo_alerts_per_month()
    socketio.emit('update_alerts_per_month', alerts_per_month, room='cdrrmo')

def get_heatmap_data(municipality):
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT lat, lon FROM cdrrmo_response WHERE municipality = ?', (municipality,))
    data = cursor.fetchall()
    conn.close()
    return [{'lat': row[0], 'lon': row[1]} for row in data]

def save_cdrrmo_officer():
    data = request.get_json()
    municipality = session.get('municipality')
    name = data.get('name')
    timestamp = datetime.now(pytz.timezone('Asia/Manila')).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO cdrrmo_officer (municipality, name, created_at) VALUES (?, ?, ?)',
        (municipality, name, timestamp)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

def get_recent_cdrrmo_officers():
    municipality = session.get('municipality')
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT name, created_at 
        FROM cdrrmo_officer 
        WHERE municipality = ? 
        ORDER BY datetime(created_at) DESC 
        LIMIT 20
        ''',
        (municipality,)
    ).fetchall()
    conn.close()
    
    return jsonify([
        {
            'name': r['name'],
            'date': datetime.strptime(r['created_at'], '%Y-%m-%d %H:%M:%S')
                            .strftime('%B %d, %Y')
        }
        for r in rows
    ])
    
def handle_store_cdrrmo_alert(data):
    try:
        conn = get_db_connection()
        # Safe retrieval of timestamp
        timestamp = data.get('timestamp') or data.get('time') or datetime.now(pytz.timezone('Asia/Manila')).isoformat()
        conn.execute('''
            INSERT OR IGNORE INTO cdrrmo_alert (alert_id, status, time, barangay, type, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['alert_id'], 'PENDING', timestamp, data.get('barangay'), data.get('emergency_type'), data.get('image', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing cdrrmo alert: {e}")

def handle_load_cdrrmo_alerts():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM cdrrmo_alert").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading cdrrmo alerts: {e}")
        return jsonify([])

def handle_load_cdrrmo_expired():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM cdrrmo_alert_expire ORDER BY time DESC").fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading expired cdrrmo alerts: {e}")
        return jsonify([])

def handle_move_cdrrmo_to_recent(alert_id):
    try:
        conn = get_db_connection()
        alert = conn.execute("SELECT * FROM cdrrmo_alert WHERE alert_id = ?", (alert_id,)).fetchone()
        if alert:
            conn.execute('''
                INSERT OR IGNORE INTO cdrrmo_alert_expire (alert_id, status, time, barangay, type, image)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert['alert_id'], 'EXPIRED', alert['time'], alert['barangay'], alert['type'], alert['image']))
            conn.execute("DELETE FROM cdrrmo_alert WHERE alert_id = ?", (alert_id,))
            conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error moving cdrrmo alert to recent: {e}")
        return jsonify({'success': False})

def handle_remove_cdrrmo_alert(alert_id):
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM cdrrmo_alert WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error removing cdrrmo alert: {e}")
        return False