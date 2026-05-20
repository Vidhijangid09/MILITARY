from flask import Flask, render_template, request, redirect, jsonify, session, url_for
from flask_cors import CORS
from flask_session import Session
from datetime import datetime
from backend import auth, encryption, communication, dashboard, threat_detection, utils
import config

app = Flask(__name__, static_folder='frontend/static', template_folder='frontend/templates')
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
CORS(app)

@app.route('/')
def index():
    if session.get('username'):
        return redirect(url_for('dashboard_page'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard_page():
    if not session.get('username'):
        return redirect(url_for('index'))
    stats = dashboard.get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/chat')
def chat_page():
    if not session.get('username'):
        return redirect(url_for('index'))
    return render_template('chat.html', username=session.get('username'))

@app.route('/admin')
def admin_page():
    if not session.get('username') or session.get('role') != 'admin':
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.json or request.form
    username = data.get('username')
    password = data.get('password')
    client_ip = request.remote_addr
    user = auth.authenticate_user(username, password, client_ip)
    if user:
        session['username'] = username
        session['role'] = user.get('role', 'user')
        session['login_time'] = datetime.utcnow().isoformat()
        return jsonify({'success': True, 'message': 'Login successful'})
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/api/users')
def users_api():
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    all_users = auth.users.find({}, {'username': 1, '_id': 0})
    usernames = [u['username'] for u in all_users if u.get('username') != session.get('username')]
    return jsonify({'success': True, 'users': usernames})

@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.json or request.form
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    result = auth.register_user(username, password, email)
    if result['success']:
        return jsonify(result)
    return jsonify(result), 400

@app.route('/api/logout')
def logout_api():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/send_message', methods=['POST'])
def send_message_api():
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    data = request.json
    recipient = data.get('recipient')
    plain_text = data.get('message')
    subject = (data.get('subject') or '').strip()
    priority = data.get('priority', 'normal')
    allowed_priorities = {'low', 'normal', 'high', 'critical'}
    if not recipient or not plain_text:
        return jsonify({'success': False, 'message': 'Recipient and message required'}), 400
    if priority not in allowed_priorities:
        return jsonify({'success': False, 'message': 'Invalid priority value'}), 400
    encrypted_payload = encryption.encrypt_message(plain_text)
    communication.save_encrypted_message(
        session['username'], recipient, encrypted_payload,
        subject=subject, priority=priority
    )
    return jsonify({
        'success': True,
        'message': 'Message encrypted and transmitted securely',
        'preview': encrypted_payload['cipher_text'][:64],
        'subject': subject or 'No subject',
        'priority': priority,
    })

@app.route('/api/messages/<recipient>', methods=['GET'])
def get_messages_api(recipient):
    if not session.get('username'):
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    messages = communication.get_conversation(session['username'], recipient)
    return jsonify({'success': True, 'messages': messages})

@app.route('/api/decrypt_message', methods=['POST'])
def decrypt_message_api():
    data = request.json
    cipher_text = data.get('cipher_text')
    if not cipher_text:
        return jsonify({'success': False, 'message': 'Cipher text required'}), 400
    plain_text = encryption.decrypt_message(cipher_text)
    return jsonify({'success': True, 'plain_text': plain_text})

@app.route('/api/traffic_stats')
def traffic_stats_api():
    stats = dashboard.get_traffic_summary()
    return jsonify(stats)

@app.route('/api/threat_alerts')
def threat_alerts_api():
    alerts = dashboard.get_recent_alerts()
    return jsonify({'alerts': alerts})

@app.route('/api/check_threat', methods=['POST'])
def check_threat_api():
    data = request.json
    event = data.get('event')
    if not event:
        return jsonify({'success': False, 'message': 'Event payload required'}), 400
    threat_result = threat_detection.detect_intrusion(event)
    return jsonify(threat_result)

@app.route('/api/network_logs', methods=['GET'])
def network_logs_api():
    logs = dashboard.get_network_logs()
    return jsonify({'logs': logs})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
