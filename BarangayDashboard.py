from flask import request, jsonify, session
from datetime import datetime, timedelta
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

def get_barangay_stats():
    try:
        types = [a.get('emergency_type', 'unknown') for a in alerts if a.get('role') == 'barangay' or a.get('barangay')]
        return Counter(types)
    except Exception as e:
        logger.error(f"Error in get_barangay_stats: {e}")
        return Counter()

def get_latest_alert():
    try:
        if alerts:
            return alerts[-1]
        return None
    except Exception as e:
        logger.error(f"Error in get_latest_alert: {e}")
        return None
    
def get_the_stats(barangay):
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT COUNT(*) as total 
            FROM (
                SELECT barangay FROM barangay_response WHERE barangay = ?
                UNION ALL
                SELECT barangay FROM barangay_crime_response WHERE barangay = ?
                UNION ALL
                SELECT barangay FROM barangay_fire_response WHERE barangay = ?
                UNION ALL
                SELECT barangay FROM barangay_health_response WHERE barangay = ?
            ) AS combined
        ''', (barangay, barangay, barangay, barangay))
        total = cursor.fetchone()['total']
        conn.close()
        return type('Stats', (), {'total': lambda self: total})()
    except Exception as e:
        logger.error(f"Error fetching barangay stats for {barangay}: {e}")
        return type('Stats', (), {'total': lambda self: 0})()

def get_new_alert(barangay):
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT * FROM (
                SELECT alert_id, barangay, emergency_type, timestamp 
                FROM barangay_response WHERE barangay = ?
                UNION ALL
                SELECT alert_id, barangay, emergency_type, timestamp 
                FROM barangay_crime_response WHERE barangay = ?
                UNION ALL
                SELECT alert_id, barangay, emergency_type, timestamp 
                FROM barangay_fire_response WHERE barangay = ?
                UNION ALL
                SELECT alert_id, barangay, emergency_type, timestamp 
                FROM barangay_health_response WHERE barangay = ?
            ) AS combined
            ORDER BY timestamp DESC LIMIT 1
        ''', (barangay, barangay, barangay, barangay))
        alert = cursor.fetchone()
        conn.close()
        return dict(alert) if alert else None
    except Exception as e:
        logger.error(f"Error fetching latest alert for {barangay}: {e}")
        return None

def get_barangay_emergency_types(barangay=None):
    if not barangay:
        logger.warning("No barangay provided for emergency types")
        return {'Road Accident': 0, 'Crime Incident': 0, 'Fire Incident': 0, 'Health Emergency': 0}
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            SELECT emergency_type, COUNT(*) as count 
            FROM (
                SELECT emergency_type FROM barangay_response WHERE barangay = ?
                UNION ALL
                SELECT emergency_type FROM barangay_crime_response WHERE barangay = ?
                UNION ALL
                SELECT emergency_type FROM barangay_fire_response WHERE barangay = ?
                UNION ALL
                SELECT emergency_type FROM barangay_health_response WHERE barangay = ?
            ) AS combined
            GROUP BY emergency_type
        ''', (barangay, barangay, barangay, barangay))
        emergency_types = {'Road Accident': 0, 'Crime Incident': 0, 'Fire Incident': 0, 'Health Emergency': 0}
        for row in cursor:
            if row['emergency_type'] in emergency_types:
                emergency_types[row['emergency_type']] = row['count']
        conn.close()
        return emergency_types
    except Exception as e:
        logger.error(f"Error fetching emergency types for {barangay}: {e}")
        return {'Road Accident': 0, 'Crime Incident': 0, 'Fire Incident': 0, 'Health Emergency': 0}

def get_barangay_responded_count(barangay):
    try:
        conn = get_db_connection()
        cursor = conn.execute('SELECT COUNT(*) as count FROM barangay_response WHERE barangay = ?', (barangay,))
        count = cursor.fetchone()['count']
        conn.close()
        return count
    except Exception as e:
        logger.error(f"Error fetching responded count for {barangay}: {e}")
        return 0

def emit_emergency_types_update(socketio, barangay):
    if not barangay:
        logger.error("No barangay provided for emitting emergency types update")
        return
    emergency_types = get_barangay_emergency_types(barangay)
    socketio.emit('update_emergency_types', emergency_types, room=barangay)
    
def get_heatmap_data(barangay):
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'users_web.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT lat, lon FROM barangay_response WHERE barangay = ?', (barangay,))
    data = cursor.fetchall()
    conn.close()
    return [{'lat': row[0], 'lon': row[1]} for row in data]


def save_officer():
    data = request.get_json()

    barangay = session.get('barangay')
    position = data.get('position')
    name = data.get('name')

    timestamp = datetime.now(pytz.timezone('Asia/Manila')).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO officer (barangay, position, name, created_at) VALUES (?, ?, ?, ?)',
        (barangay, position, name, timestamp)
    )
    conn.commit()
    conn.close()

    return jsonify({'success': True})

def get_recent_officers():
    barangay = session.get('barangay')

    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT name, created_at
        FROM officer
        WHERE barangay = ?
        ORDER BY datetime(created_at) DESC
        LIMIT 20
        ''',
        (barangay,)
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
    
def handle_store_barangay_alert(data):
    try:
        conn = get_db_connection()
        timestamp = data.get('timestamp') or data.get('time') or datetime.now(pytz.timezone('Asia/Manila')).isoformat()
        conn.execute('''
            INSERT OR IGNORE INTO barangay_alert (alert_id, status, time, barangay, type, image)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['alert_id'], 'PENDING', timestamp, data.get('barangay'), data.get('emergency_type'), data.get('image', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing barangay alert: {e}")

def handle_load_barangay_alerts(barangay):
    """Load unaccepted alerts from the barangay_alert table for a specific barangay."""
    try:
        logger.info(f"Loading barangay alerts for: {barangay}")
        conn = get_db_connection()
        alerts = conn.execute('SELECT * FROM barangay_alert WHERE barangay = ?', (barangay,)).fetchall()
        conn.close()
        logger.info(f"Found {len(alerts)} alerts for barangay: {barangay}")
        return jsonify([dict(ix) for ix in alerts])
    except Exception as e:
        logger.error(f"Error loading live barangay alerts for {barangay}: {e}")
        return jsonify([])

def handle_load_barangay_expired(barangay):
    try:
        logger.info(f"Loading expired alerts for barangay: {barangay}")
        conn = get_db_connection()
        # Join with response tables to determine if an expired alert was actually responded to.
        query = """
            SELECT 
                e.*,
                CASE 
                    WHEN r.alert_id IS NOT NULL OR rf.alert_id IS NOT NULL OR rc.alert_id IS NOT NULL OR rh.alert_id IS NOT NULL THEN 'RESPONDED'
                    ELSE 'EXPIRED'
                END as final_status
            FROM barangay_alert_expire e
            LEFT JOIN barangay_response r ON e.alert_id = r.alert_id
            LEFT JOIN barangay_fire_response rf ON e.alert_id = rf.alert_id
            LEFT JOIN barangay_crime_response rc ON e.alert_id = rc.alert_id
            LEFT JOIN barangay_health_response rh ON e.alert_id = rh.alert_id
            WHERE e.barangay = ?
            GROUP BY e.alert_id
            ORDER BY e.time DESC
        """
        rows = conn.execute(query, (barangay,)).fetchall()
        conn.close()
        logger.info(f"Found {len(rows)} expired alerts for barangay: {barangay}")
        return jsonify([dict(row) for row in rows])
    except Exception as e:
        logger.error(f"Error loading expired barangay alerts: {e}")
        return jsonify([])

def handle_update_barangay_alert_type(alert_id, emergency_type):
    """Updates the 'type' of a pending alert in the barangay_alert table."""
    try:
        conn = get_db_connection()
        conn.execute("UPDATE barangay_alert SET type = ? WHERE alert_id = ?", (emergency_type, alert_id))
        conn.commit()
        conn.close()
        logger.info(f"Updated alert {alert_id} type to {emergency_type}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating barangay alert type: {e}")
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

def handle_move_barangay_to_recent(alert_id):
    try:
        conn = get_db_connection()
        # 1. Fetch the alert from the live table
        alert = conn.execute("SELECT * FROM barangay_alert WHERE alert_id = ?", (alert_id,)).fetchone()
        
        if alert:
            # 2. Insert into the expire table
            conn.execute('''
                INSERT OR IGNORE INTO barangay_alert_expire (alert_id, status, time, barangay, type, image)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert['alert_id'], 'EXPIRED', alert['time'], alert['barangay'], alert['type'], alert['image']))
            
            # 3. Delete from the live table
            conn.execute("DELETE FROM barangay_alert WHERE alert_id = ?", (alert_id,))
            conn.commit()
            conn.close()
            logger.info(f"Moved alert {alert_id} from live to expired table")
            return jsonify({'success': True})
        else:
            conn.close()
            # It might have already been moved or didn't exist
            return jsonify({'success': False, 'message': 'Alert not found in live table'})
    except Exception as e:
        logger.error(f"Error moving barangay alert to recent: {e}")
        return jsonify({'success': False, 'error': str(e)})

def handle_remove_barangay_alert(alert_id):
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM barangay_alert WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()
        logger.info(f"Removed alert {alert_id} from barangay_alert table")
        return True
    except Exception as e:
        logger.error(f"Error removing barangay alert: {e}")
        return False