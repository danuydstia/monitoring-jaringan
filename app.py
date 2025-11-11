from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import platform
from datetime import datetime, timedelta
import json
import time
import pytz
import re
import socket

app = Flask(__name__)
app.secret_key = 'rahasia-kantor-2025'
AGENT_API_KEY = 'rahasia-kantor-2025'  # Harus sama dengan di agent.py

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'network_monitoring'

mysql = MySQL(app)

# ZONA WAKTU INDONESIA
TIMEZONE_WIB = pytz.timezone('Asia/Jakarta')  # WIB (GMT+7)

def get_current_time():
    """Mendapatkan waktu sekarang dalam zona waktu Indonesia (WIB)"""
    return datetime.now(TIMEZONE_WIB)

# ========== DECORATOR FUNCTIONS ==========

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Akses ditolak. Hanya admin yang bisa mengakses halaman ini', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ========== HELPER FUNCTIONS - PING & NETWORK ==========

def test_connection(ip_address, timeout=3):
    """Test koneksi ke IP dengan berbagai metode"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(timeout * 1000), ip_address]
    
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout + 2, text=True)
        if result.returncode == 0:
            print(f"✓ {ip_address} reachable via PING")
            return True
    except:
        pass
    
    # Method 2: TCP Connection test
    common_ports = [80, 443, 22, 23, 3389, 8080]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result == 0:
                print(f"✓ {ip_address} reachable via TCP port {port}")
                return True
        except:
            pass
    
    print(f"✗ {ip_address} not reachable")
    return False

def ping_host(ip_address):
    """Ping host sederhana"""
    return test_connection(ip_address, timeout=3)

def ping_host_detailed(ip_address):
    """Ping host dan return detail: status, latency, packet_loss, response_time"""
    result = {
        'status': 'offline',
        'latency': None,
        'packet_loss': 100.0,
        'response_time': None
    }
    
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', '-w', '3000', ip_address]
    
    try:
        start_time = time.time()
        output = subprocess.run(command, capture_output=True, timeout=15, text=True)
        end_time = time.time()

        output_text = output.stdout
        duration_ms = round((end_time - start_time) * 1000, 2)
        result['response_time'] = duration_ms
        
        if output.returncode == 0:
            result['status'] = 'online'
            
            if platform.system().lower() == 'windows':
                # Parse latency
                latency_patterns = [
                    r'[Aa]verage\s*=\s*(\d+(?:\.\d+)?)ms',
                    r'[Rr]ata-rata\s*=\s*(\d+(?:\.\d+)?)ms',
                ]
                
                latency_found = False
                for pattern in latency_patterns:
                    match = re.search(pattern, output_text)
                    if match:
                        avg_value = float(match.group(1))
                        if avg_value > 0:
                            result['latency'] = avg_value
                            latency_found = True
                            break
                
                if not latency_found or result['latency'] == 0:
                    time_patterns = [r'time=(\d+)ms', r'time<(\d+)ms']
                    time_values = []
                    
                    for pattern in time_patterns:
                        matches = re.findall(pattern, output_text)
                        for match in matches:
                            time_val = float(match)
                            if '<' in pattern:
                                time_val = time_val * 0.5
                            time_values.append(time_val)
                    
                    if time_values:
                        result['latency'] = round(sum(time_values) / len(time_values), 2)
                    else:
                        result['latency'] = 0.5
                
                # Parse packet loss
                loss_patterns = [
                    r'\((\d+(?:\.\d+)?)%\s*loss\)',
                    r'\((\d+(?:\.\d+)?)%\s*hilang\)',
                    r'Lost\s*=\s*(\d+)',
                ]
                
                packet_loss_found = False
                for pattern in loss_patterns:
                    match = re.search(pattern, output_text, re.IGNORECASE)
                    if match:
                        if 'loss' in pattern.lower() or 'hilang' in pattern.lower():
                            result['packet_loss'] = float(match.group(1))
                        else:
                            lost_packets = int(match.group(1))
                            result['packet_loss'] = round((lost_packets / 4) * 100, 2)
                        packet_loss_found = True
                        break
                
                if not packet_loss_found:
                    result['packet_loss'] = 0.0
            else:
                # Linux/Mac
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output_text)
                if match:
                    result['latency'] = float(match.group(1))
                
                loss_match = re.search(r'(\d+(?:\.\d+)?)% packet loss', output_text)
                if loss_match:
                    result['packet_loss'] = float(loss_match.group(1))
                else:
                    result['packet_loss'] = 0.0
        else:
            if test_connection(ip_address, timeout=2):
                result['status'] = 'online'
                result['latency'] = 999
                result['packet_loss'] = 0.0
                result['response_time'] = duration_ms
            else:
                result['status'] = 'offline'
                result['packet_loss'] = 100.0
            
    except subprocess.TimeoutExpired:
        if test_connection(ip_address, timeout=2):
            result['status'] = 'online'
            result['latency'] = 999
            result['packet_loss'] = 0.0
        else:
            result['status'] = 'offline'
            result['packet_loss'] = 100.0
    except Exception as e:
        print(f"Error: {e}")
        if test_connection(ip_address, timeout=2):
            result['status'] = 'online'
            result['latency'] = 999
            result['packet_loss'] = 0.0
        else:
            result['status'] = 'offline'
            result['packet_loss'] = 100.0
    
    return result

# ========== AUTHENTICATION ROUTES ==========

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username dan password harus diisi', 'warning')
            return render_template('login.html')
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()
            
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[4]
                flash(f'Selamat datang, {username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Username atau password salah', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout', 'info')
    return redirect(url_for('login'))

# ========== MAIN DASHBOARD ==========

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM devices ORDER BY id DESC")
    devices = cur.fetchall()
    
    cur.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
    online = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM devices WHERE status = 'offline'")
    offline = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM devices")
    total = cur.fetchone()[0]
    
    cur.close()
    
    return render_template('dashboard.html', devices=devices, online=online, offline=offline, total=total)

# ========== DEVICE MANAGEMENT ROUTES ==========

@app.route('/add_device', methods=['GET', 'POST'])
@admin_required
def add_device():
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            ip_address = request.form.get('ip_address', '').strip()
            description = request.form.get('description', '').strip()
            monitored_by = request.form.get('monitored_by', 'server')  # 'server' atau 'agent'
            
            if not name or not ip_address:
                flash('Nama dan IP Address harus diisi', 'warning')
                return render_template('add_device.html')
            
            # Validasi format IP
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, ip_address):
                flash('Format IP Address tidak valid. Gunakan format xxx.xxx.xxx.xxx', 'warning')
                return render_template('add_device.html')
            
            # Validasi range IP
            octets = ip_address.split('.')
            for octet in octets:
                if int(octet) > 255:
                    flash('Setiap segmen IP harus antara 0-255', 'warning')
                    return render_template('add_device.html')
            
            # Check apakah IP sudah ada
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, name FROM devices WHERE ip_address = %s", (ip_address,))
            existing = cur.fetchone()
            
            if existing:
                cur.close()
                flash(f'IP Address {ip_address} sudah terdaftar dengan nama "{existing[1]}"', 'warning')
                return render_template('add_device.html')
            
            # Jika monitored by agent
            if monitored_by == 'agent':
                if description:
                    description = f"{description} [monitored_by_agent]"
                else:
                    description = "[monitored_by_agent]"
                
                status = 'offline'  # Default offline, agent akan update
                
                print(f"\n{'='*60}")
                print(f"Adding device (Agent Mode): {name} ({ip_address})")
                print(f"Status: Will be monitored by agent")
                print(f"{'='*60}\n")
            else:
                # Mode server: test koneksi
                print(f"\n{'='*60}")
                print(f"Testing connection to: {name} ({ip_address})")
                print(f"{'='*60}")
                
                is_online = ping_host(ip_address)
                status = 'online' if is_online else 'offline'
                
                print(f"Result: {status.upper()}")
                print(f"{'='*60}\n")
            
            cur.execute("""
                INSERT INTO devices (name, ip_address, description, status, last_check) 
                VALUES (%s, %s, %s, %s, %s)
            """, (name, ip_address, description, status, get_current_time()))
            
            mysql.connection.commit()
            device_id = cur.lastrowid
            cur.close()
            
            if monitored_by == 'agent':
                flash(f'✅ Device "{name}" berhasil ditambahkan. Menunggu update dari agent...', 'success')
            else:
                status_icon = "🟢" if status == 'online' else "🔴"
                flash(f'{status_icon} Device "{name}" berhasil ditambahkan dengan status {status.upper()}', 'success')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            
            try:
                mysql.connection.rollback()
            except:
                pass
            
            flash(f'Error menambahkan device: {str(e)}', 'danger')
            return render_template('add_device.html')
    
    return render_template('add_device.html')

@app.route('/edit_device/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_device(id):
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name or not ip_address:
            flash('Nama dan IP Address harus diisi', 'warning')
            cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
            device = cur.fetchone()
            cur.close()
            return render_template('edit_device.html', device=device)
        
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            flash('Format IP Address tidak valid', 'warning')
            cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
            device = cur.fetchone()
            cur.close()
            return render_template('edit_device.html', device=device)
        
        cur.execute("SELECT id, name FROM devices WHERE ip_address = %s AND id != %s", (ip_address, id))
        existing = cur.fetchone()
        
        if existing:
            flash(f'IP Address {ip_address} sudah digunakan oleh device "{existing[1]}"', 'warning')
            cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
            device = cur.fetchone()
            cur.close()
            return render_template('edit_device.html', device=device)
        
        cur.execute("""
            UPDATE devices 
            SET name = %s, ip_address = %s, description = %s 
            WHERE id = %s
        """, (name, ip_address, description, id))
        mysql.connection.commit()
        cur.close()
        
        flash('Device berhasil diupdate', 'success')
        return redirect(url_for('dashboard'))
    
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    cur.close()
    
    if not device:
        flash('Device tidak ditemukan', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_device.html', device=device)

@app.route('/delete_device/<int:id>')
@admin_required
def delete_device(id):
    cur = mysql.connection.cursor()
    
    cur.execute("SELECT name FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    device_name = device[0] if device else "Unknown"
    
    cur.execute("DELETE FROM devices WHERE id = %s", (id,))
    cur.execute("DELETE FROM monitoring_logs WHERE device_id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash(f'Device "{device_name}" berhasil dihapus', 'success')
    return redirect(url_for('dashboard'))

# ========== MONITORING ROUTES ==========

@app.route('/check_device/<int:device_id>')
@admin_required
def check_device(device_id):
    """Check single device"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
        device = cur.fetchone()
        
        if not device:
            flash('Device tidak ditemukan', 'danger')
            return redirect(url_for('dashboard'))
        
        device_name = device[1]
        ip_address = device[2]
        
        ping_result = ping_host_detailed(ip_address)
        
        status = ping_result['status']
        latency = ping_result['latency']
        packet_loss = ping_result['packet_loss']
        response_time = ping_result['response_time']
        
        cur.execute("""
            UPDATE devices 
            SET status = %s, last_check = %s 
            WHERE id = %s
        """, (status, get_current_time(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, get_current_time()))
        
        mysql.connection.commit()
        cur.close()
        
        status_icon = "🟢" if status == 'online' else "🔴"
        latency_text = f"{latency:.2f}ms" if latency and latency < 999 else "N/A"
        flash(f'{status_icon} {device_name}: {status.upper()} | Latency: {latency_text}', 'success' if status == 'online' else 'warning')
        
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error checking device: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/check_all')
@admin_required
def check_all():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM devices")
    devices = cur.fetchall()
    
    print(f"\n{'='*60}")
    print(f"Checking {len(devices)} devices...")
    print(f"{'='*60}\n")
    
    online_count = 0
    offline_count = 0
    
    for device in devices:
        device_id = device[0]
        device_name = device[1]
        ip_address = device[2]
        
        ping_result = ping_host_detailed(ip_address)
        
        status = ping_result['status']
        latency = ping_result['latency']
        packet_loss = ping_result['packet_loss']
        response_time = ping_result['response_time']
        
        if status == 'online':
            online_count += 1
        else:
            offline_count += 1
        
        cur.execute("""
            UPDATE devices 
            SET status = %s, last_check = %s 
            WHERE id = %s
        """, (status, get_current_time(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, get_current_time()))
    
    mysql.connection.commit()
    cur.close()
    
    flash(f'Semua device telah dicek: {online_count} online, {offline_count} offline', 'success')
    return redirect(url_for('dashboard'))

@app.route('/history/<int:device_id>')
@login_required
def history(device_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cur.fetchone()
    
    if not device:
        flash('Device tidak ditemukan', 'danger')
        return redirect(url_for('dashboard'))
    
    cur.execute("""
        SELECT * FROM monitoring_logs 
        WHERE device_id = %s 
        ORDER BY checked_at DESC 
        LIMIT 100
    """, (device_id,))
    logs = cur.fetchall()
    
    stats = None
    if logs:
        latencies = [log[3] for log in logs if log[3] is not None]
        packet_losses = [log[4] for log in logs if log[4] is not None]
        
        if latencies:
            stats = {
                'avg_latency': round(sum(latencies) / len(latencies), 2),
                'min_latency': round(min(latencies), 2),
                'max_latency': round(max(latencies), 2),
                'avg_packet_loss': round(sum(packet_losses) / len(packet_losses), 2) if packet_losses else 0
            }
    
    cur.close()
    
    return render_template('history.html', device=device, logs=logs, stats=stats)

@app.route('/analytics/<int:device_id>')
@login_required
def analytics(device_id):
    cur = mysql.connection.cursor()
    
    cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cur.fetchone()
    
    if not device:
        flash('Device tidak ditemukan', 'danger')
        cur.close()
        return redirect(url_for('dashboard'))
    
    cur.execute("""
        SELECT checked_at, status, latency, packet_loss 
        FROM monitoring_logs 
        WHERE device_id = %s 
        AND checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY checked_at ASC
    """, (device_id,))
    logs = cur.fetchall()
    
    if logs:
        latencies = [log[2] for log in logs if log[2] is not None]
        packet_losses = [log[3] for log in logs if log[3] is not None]
        
        avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0
        avg_packet_loss = round(sum(packet_losses) / len(packet_losses), 2) if packet_losses else 0
        min_latency = round(min(latencies), 2) if latencies else 0
        max_latency = round(max(latencies), 2) if latencies else 0
        
        stats = (avg_latency, avg_packet_loss, min_latency, max_latency)
        
        online_count = sum(1 for log in logs if log[1] == 'online')
        uptime_percentage = round((online_count / len(logs)) * 100, 2) if logs else 0
    else:
        stats = (0, 0, 0, 0)
        uptime_percentage = 0
    
    cur.close()
    
    return render_template('analytics.html', 
                         device=device, 
                         logs=logs, 
                         stats=stats,
                         uptime_percentage=uptime_percentage)

# ========== AGENT DEVICES PAGE ==========

@app.route('/agent_devices')
@login_required
def agent_devices():
    """Halaman khusus untuk melihat devices dari agent"""
    cur = mysql.connection.cursor()
    
    cur.execute("""
        SELECT * FROM devices 
        WHERE description LIKE '%agent%'
        ORDER BY last_check DESC
    """)
    devices = cur.fetchall()
    
    cur.close()
    
    return render_template('agent_devices.html', devices=devices)

# ========== API ROUTES ==========

@app.route('/api/device_status/<int:device_id>')
@login_required
def api_device_status(device_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT ip_address, status, last_check FROM devices WHERE id = %s", (device_id,))
    device = cur.fetchone()
    cur.close()
    
    if device:
        return jsonify({
            'ip_address': device[0],
            'status': device[1],
            'last_check': device[2].strftime('%Y-%m-%d %H:%M:%S') if device[2] else None
        })
    return jsonify({'error': 'Device not found'}), 404

@app.route('/api/check_device/<int:device_id>')
@admin_required
def api_check_device(device_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
        device = cur.fetchone()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        ip_address = device[2]
        ping_result = ping_host_detailed(ip_address)
        
        status = ping_result['status']
        latency = ping_result['latency']
        packet_loss = ping_result['packet_loss']
        response_time = ping_result['response_time']
        
        cur.execute("""
            UPDATE devices 
            SET status = %s, last_check = %s 
            WHERE id = %s
        """, (status, get_current_time(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, get_current_time()))
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({
            'success': True,
            'device_id': device_id,
            'status': status,
            'latency': latency,
            'packet_loss': packet_loss,
            'response_time': response_time,
            'last_check': get_current_time().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

# ========== AGENT API ENDPOINTS ==========

@app.route('/api/agent/test', methods=['GET'])
def agent_test():
    """Test endpoint untuk memastikan agent bisa connect"""
    return jsonify({
        'status': 'ok',
        'message': 'Agent endpoint is working',
        'server_time': get_current_time().isoformat()
    }), 200

@app.route('/api/agent/push_status', methods=['POST'])
def agent_push_status():
    """
    Endpoint untuk menerima push status dari agent lokal
    HYBRID MODE: Agent update status device yang sudah ada di database
    """
    try:
        data = request.get_json()
        
        # Validasi API Key
        api_key = data.get('api_key')
        if api_key != AGENT_API_KEY:
            return jsonify({'error': 'Invalid API Key'}), 401
        
        agent_name = data.get('agent_name', 'Unknown Agent')
        timestamp = data.get('timestamp')
        devices = data.get('devices', [])
        
        if not devices:
            return jsonify({'error': 'No devices data'}), 400
        
        print(f"\n{'='*60}")
        print(f"📡 Received data from agent: {agent_name}")
        print(f"Time: {timestamp}")
        print(f"Devices: {len(devices)}")
        print(f"{'='*60}")
        
        cur = mysql.connection.cursor()
        
        updated_count = 0
        created_count = 0
        
        for device_data in devices:
            device_name = device_data.get('name')
            ip_address = device_data.get('ip')
            status = device_data.get('status', 'offline')
            latency = device_data.get('latency')
            
            print(f"  {device_name} ({ip_address}): {status}")
            
            # Cek apakah device sudah ada di database (by IP)
            cur.execute("SELECT id FROM devices WHERE ip_address = %s", (ip_address,))
            existing = cur.fetchone()
            
            if existing:
                # Update device yang sudah ada
                device_id = existing[0]
                
                cur.execute("""
                    UPDATE devices 
                    SET status = %s, last_check = %s
                    WHERE id = %s
                """, (status, get_current_time(), device_id))
                
                updated_count += 1
            else:
                # Buat device baru jika belum ada (AUTO-ADD mode)
                cur.execute("""
                    INSERT INTO devices (name, ip_address, description, status, last_check) 
                    VALUES (%s, %s, %s, %s, %s)
                """, (device_name, ip_address, f'Auto-added by agent: {agent_name}', status, get_current_time()))
                
                device_id = cur.lastrowid
                created_count += 1
            
            # Simpan log monitoring
            cur.execute("""
                INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (device_id, status, latency, 0.0, None, get_current_time()))
        
        mysql.connection.commit()
        cur.close()
        
        print(f"✓ Updated: {updated_count}, Created: {created_count}")
        print(f"{'='*60}\n")
        
        return jsonify({
            'success': True,
            'message': f'Status received from {agent_name}',
            'devices_processed': len(devices),
            'updated': updated_count,
            'created': created_count
        }), 200
        
    except Exception as e:
        print(f"❌ Error processing agent data: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/agent/register_device', methods=['POST'])
def agent_register_device():
    """
    Endpoint untuk agent request daftar device yang harus dimonitor
    Agent akan ambil list device dari server, lalu monitor sesuai list tersebut
    """
    try:
        data = request.get_json()
        
        # Validasi API Key
        api_key = data.get('api_key')
        if api_key != AGENT_API_KEY:
            return jsonify({'error': 'Invalid API Key'}), 401
        
        agent_name = data.get('agent_name', 'Unknown Agent')
        
        cur = mysql.connection.cursor()
        
        # Ambil devices yang ditandai untuk dimonitor oleh agent
        cur.execute("""
            SELECT id, name, ip_address, description 
            FROM devices 
            WHERE description LIKE '%agent%' OR description LIKE '%monitored_by_agent%'
            ORDER BY id
        """)
        devices = cur.fetchall()
        cur.close()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device[0],
                'name': device[1],
                'ip': device[2],
                'description': device[3]
            })
        
        print(f"📋 Agent '{agent_name}' requested device list: {len(device_list)} devices")
        
        return jsonify({
            'success': True,
            'agent_name': agent_name,
            'devices': device_list,
            'count': len(device_list)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== RUN APPLICATION ==========

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Network Monitoring System - HYBRID MODE")
    print("="*60)
    print("✓ Server Mode: Direct ping from server")
    print("✓ Agent Mode: Push status from local agents")
    print("="*60)
    print("Agent Endpoints:")
    print("  - POST /api/agent/push_status")
    print("  - POST /api/agent/register_device")
    print("  - GET  /api/agent/test")
    print("="*60 + "\n")
    
    app.run(debug=True)