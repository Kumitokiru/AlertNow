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


def handle_barangay_alert_store(alert_data):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO barangay_alert (
            alert_id, barangay, message, timestamp
        ) VALUES (?, ?, ?, ?)
    """, (
        alert_data['alert_id'],
        alert_data['barangay'],
        alert_data['message'],
        alert_data['timestamp']
    ))
    conn.commit()
    conn.close()
    
def handle_barangay_expire_alert(alert_id):
    conn = get_db_connection()
    conn.execute("""
        UPDATE barangay_alert SET expired = 1 WHERE alert_id = ?
    """, (alert_id,))
    conn.commit()
    conn.close()
    
def handle_bfp_alert_store(alert_data):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO bfp_alert (
            alert_id, barangay, message, timestamp
        ) VALUES (?, ?, ?, ?)
    """, (
        alert_data['alert_id'],
        alert_data['barangay'],
        alert_data['message'],
        alert_data['timestamp']
    ))
    conn.commit()
    conn.close()

def handle_bfp_expire_alert(alert_id):
    conn = get_db_connection()
    conn.execute("""
        UPDATE bfp_alert SET expired = 1 WHERE alert_id = ?
    """, (alert_id,))
    conn.commit()
    conn.close()

def handle_cdrrmo_alert_store(alert_data):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO cdrrmo_alert (
            alert_id, barangay, message, timestamp
        ) VALUES (?, ?, ?, ?)
    """, (
        alert_data['alert_id'],
        alert_data['barangay'],
        alert_data['message'],
        alert_data['timestamp']
    ))
    conn.commit()
    conn.close()
    
def handle_cdrrmo_expire_alert(alert_id):
    conn = get_db_connection()
    conn.execute("""
        UPDATE cdrrmo_alert SET expired = 1 WHERE alert_id = ?
    """, (alert_id,))
    conn.commit()
    conn.close()
def handle_pnp_alert_store(alert_data):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO pnp_alert (
            alert_id, barangay, message, timestamp
        ) VALUES (?, ?, ?, ?)
    """, (
        alert_data['alert_id'],
        alert_data['barangay'],
        alert_data['message'],
        alert_data['timestamp']
    ))
    conn.commit()
    conn.close()
    
def handle_pnp_expire_alert(alert_id):
    conn = get_db_connection()
    conn.execute("""
        UPDATE pnp_alert SET expired = 1 WHERE alert_id = ?
    """, (alert_id,))
    conn.commit()
    conn.close()