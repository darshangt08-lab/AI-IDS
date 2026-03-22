from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import pickle
import pandas as pd
import numpy as np
from datetime import datetime
import os
import sys

import sys

from network_scanner.scanner import scan_ip
from packet_monitor.monitor import monitor_instance
from device_detector.detector import scan_network_devices

app = Flask(__name__)
app.secret_key = 'cyber_security_secret_key'

# Load ML Model
try:
    with open('model.pkl', 'rb') as f:
        model_data = pickle.load(f)
        clf = model_data['model']
        encoders = model_data['encoders']
        features = model_data['features']
except Exception as e:
    print(f"Error loading model: {e}")
    clf = None

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                        (username, password)).fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'status': 'success', 'redirect': url_for('dashboard')})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials detected!'}), 401

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/scan', methods=['POST'])
def scan_packet():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    
    try:
        protocol = data.get('protocol', 'TCP')
        service = data.get('service', 'http')
        flag = data.get('flag', 'SF')
        src_bytes = int(data.get('src_bytes', 0))
        dst_bytes = int(data.get('dst_bytes', 0))
        duration = int(data.get('duration', 0))

        # RULE-BASED LOGIC (Step 168 Requirements)
        prediction = 0
        reason = "Normal Traffic"
        
        if src_bytes > 10000 or duration > 5000:
            prediction = 1
            reason = "High Data/Duration Anomaly"
        elif flag != 'SF':
            prediction = 1
            reason = "Suspicious Flag Detected"
        elif protocol == 'TCP' and service == 'http' and src_bytes < 5000:
            prediction = 0
            reason = "Standard Web Traffic"
        elif clf:
            # ML Fallback
            input_df = pd.DataFrame([{
                'protocol_type': protocol.lower(),
                'service': service.lower(),
                'flag': flag,
                'src_bytes': src_bytes,
                'dst_bytes': dst_bytes,
                'duration': duration
            }])
            
            for col in ['protocol_type', 'service', 'flag']:
                if col in encoders:
                    try:
                        input_df[col] = encoders[col].transform(input_df[col])
                    except:
                        input_df[col] = 0
            
            prediction = clf.predict(input_df)[0]
            reason = "AI Detected Anomaly" if prediction == 1 else "Normal Pattern"

        # DEMO MODE OVERRIDE
        if demo_mode_active:
            prediction = 1
            reason = "DEMO MODE: Forced Intrusion"
            
        result = "INTRUSION DETECTED" if prediction == 1 else "NORMAL TRAFFIC"
        status = "Warning" if prediction == 1 else "Safe"
        
        # Deterministic IP selection instead of random
        demo_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.5', '172.16.0.10']
        src_ip = data.get('source_ip')
        if not src_ip:
            # Use a stable IP based on the input data to avoid total randomness
            ip_idx = (src_bytes + duration) % len(demo_ips)
            src_ip = demo_ips[ip_idx]

        # Log entry
        conn = get_db_connection()
        conn.execute('INSERT INTO logs (source_ip, protocol, service, attack_type, status) VALUES (?, ?, ?, ?, ?)',
                    (src_ip, protocol, service, reason if prediction == 1 else 'None', status))
        
        if prediction == 1:
            try:
                conn.execute('INSERT OR IGNORE INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (src_ip, f'IDS: {reason}'))
            except: pass
                
        conn.commit()
        conn.close()
        
        return jsonify({
            'result': result, 
            'prediction': int(prediction),
            'source_ip': src_ip,
            'reason': reason,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/live_scan', methods=['POST'])
def perform_live_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ip_to_scan = data.get('ip')
    
    if not ip_to_scan:
        return jsonify({'error': 'No IP provided'}), 400
        
    results = scan_ip(ip_to_scan)
    if "error" in results:
        return jsonify(results), 400
        
    return jsonify(results)

@app.route('/api/device_scan', methods=['POST'])
def perform_device_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ip_range = data.get('ip_range', '192.168.1.0/24')
    
    results = scan_network_devices(ip_range)
    return jsonify(results)

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    # Real counts from DB
    total = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
    intrusions = conn.execute('SELECT COUNT(*) FROM logs WHERE status = "Warning"').fetchone()[0]
    normal = total - intrusions
    
    suspicious_ips = len(conn.execute('SELECT DISTINCT source_ip FROM logs WHERE status = "Warning"').fetchall())
    
    # Use real count from monitor or 0 if stopped
    active_connections = len(monitor_instance.packets) if monitor_instance.is_monitoring else 0
    
    # Get blocked IPs count
    blocked_count = conn.execute('SELECT COUNT(*) FROM blocked_ips').fetchone()[0]
    
    # Calculate threat level based on real intrusion percentage
    ratio = (intrusions / total) if total > 0 else 0
    if ratio > 0.4:
        threat_level = 'Critical'
    elif ratio > 0.15:
        threat_level = 'High'
    elif ratio > 0.05:
        threat_level = 'Medium'
    else:
        threat_level = 'Low'
        
    logs = [dict(row) for row in conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 10').fetchall()]
    blocked = [dict(row) for row in conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC LIMIT 5').fetchall()]
    
    conn.close()
    
    return jsonify({
        'total': total,
        'intrusions': intrusions,
        'normal': normal,
        'suspicious_ips': suspicious_ips,
        'active_connections': active_connections,
        'active_devices': 8, # Fixed to match deterministic demo device list
        'threat_level': threat_level,
        'blocked_count': blocked_count,
        'logs': logs,
        'blocked': blocked
    })

# Global flag for demo mode
demo_mode_active = False

@app.route('/api/toggle_demo', methods=['POST'])
def toggle_demo():
    global demo_mode_active
    data = request.get_json()
    demo_mode_active = data.get('active', False)
    return jsonify({'status': 'Demo mode ' + ('enabled' if demo_mode_active else 'disabled')})

@app.route('/api/live_packets', methods=['GET'])
def get_live_packets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    packets = monitor_instance.get_recent_packets(50)
    
    # Run through AI
    for pkt in packets:
        if clf is not None and not pkt.get('is_ai_checked'):
            try:
                service_map = {80: 'http', 21: 'ftp', 53: 'dns', 25: 'smtp', 22: 'ssh'}
                svc = service_map.get(pkt.get('service_port', 0), 'private')
                
                input_df = pd.DataFrame([{
                    'protocol_type': pkt['protocol'].lower(),
                    'service': svc,
                    'flag': 'SF',
                    'src_bytes': pkt['size'],
                    'dst_bytes': 0,
                    'duration': 0
                }])
                
                for col in ['protocol_type', 'service', 'flag']:
                    if col in encoders:
                        try:
                            input_df[col] = encoders[col].transform(input_df[col])
                        except:
                            input_df[col] = 0
                            
                prediction = clf.predict(input_df)[0]
                if prediction == 1:
                    pkt['is_suspicious'] = True
                    pkt['attack_type'] = "AI Detected Anomaly"
                    pkt['threat_level'] = "High"
                    
                    # Automatically block the source IP
                    try:
                        conn = get_db_connection()
                        conn.execute('INSERT OR IGNORE INTO blocked_ips (ip_address, reason) VALUES (?, ?)', 
                                   (pkt['source_ip'], 'AI-IDS Detection'))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        pass
                
                pkt['is_ai_checked'] = True
            except Exception as e:
                pass
                
    return jsonify(packets)

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    monitor_instance.start()
    return jsonify({'status': 'Monitoring started'})

@app.route('/api/stop_monitor', methods=['POST'])
def stop_monitor():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    monitor_instance.stop()
    return jsonify({'status': 'Monitoring stopped'})

@app.route('/api/logs')
def get_all_logs():
    conn = get_db_connection()
    logs = [dict(row) for row in conn.execute('SELECT * FROM logs ORDER BY timestamp DESC').fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/blocked')
def get_blocked_ips():
    conn = get_db_connection()
    ips = [dict(row) for row in conn.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC').fetchall()]
    conn.close()
    return jsonify(ips)

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual Block')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT OR IGNORE INTO blocked_ips (ip_address, reason) VALUES (?, ?)', (ip_address, reason))
        conn.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()
    
    return jsonify({'status': 'IP blocked successfully'})

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    conn = get_db_connection()
    conn.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'IP unblocked successfully'})

# Chatbot helper function
def create_bot_response(message):
    message = (message or '').strip().lower()
    stats = {}
    try:
        with get_db_connection() as conn:
            total = conn.execute('SELECT COUNT(*) FROM logs').fetchone()[0]
            intrusions = conn.execute('SELECT COUNT(*) FROM logs WHERE status = "Warning"').fetchone()[0]
            normal = total - intrusions
            threat_level = 'High' if (intrusions / total if total > 0 else 0) > 0.2 else 'Low'
            stats = {'total': total, 'intrusions': intrusions, 'normal': normal, 'threat_level': threat_level}
    except Exception:
        stats = {'total': 0, 'intrusions': 0, 'normal': 0, 'threat_level': 'Unknown'}

    if not message:
        return "Please type a question or command so I can assist you."

    if 'intrusion' in message or 'threat' in message or 'attack' in message:
        return (f"Current detection summary:\n" \
                f"- Total packets: {stats['total']}\n" \
                f"- Intrusions: {stats['intrusions']}\n" \
                f"- Safe: {stats['normal']}\n" \
                f"- Threat level: {stats['threat_level']}\n" \
                f"Response: I recommend reviewing the latest logs and blocking suspicious IPs.")

    if 'status' in message or 'health' in message or 'overall' in message:
        return (f"System status: Threat level is {stats['threat_level']}. "
                f"{stats['intrusions']} suspicious events found out of {stats['total']} packets. "
                f"All vital modules are up." )

    if 'scan' in message or 'analyze' in message:
        return "You can run a manual packet scan from the Manual Packet Analysis panel or call /api/scan with packet details."

    if 'help' in message or 'commands' in message or '?' in message:
        return ("Ask me about system status (e.g. 'What is threat level?'), "
                "intrusion stats, live scan guidance, or how to secure the network.")

    # Generic answer
    return "Data is stable. For network-specific guidance, ask me about threats, logs, or scan commands."

@app.route('/api/chat', methods=['POST'])
def chat_api():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    message = data.get('message', '')
    if not message:
        return jsonify({'reply': 'Please provide a message.'}), 400

    bot_reply = create_bot_response(message)
    return jsonify({'reply': bot_reply})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
