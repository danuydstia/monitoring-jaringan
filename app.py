from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import subprocess
import platform
from datetime import datetime, timedelta
import json
import time
import re
import socket

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'network_monitoring'

mysql = MySQL(app)

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
        
        print(f"\n{'='*60}")
        print(f"Checking single device: {device_name} ({ip_address})")
        print(f"{'='*60}")
        
        ping_result = ping_host_detailed(ip_address)
        
        status = ping_result['status']
        latency = ping_result['latency']
        packet_loss = ping_result['packet_loss']
        response_time = ping_result['response_time']
        
        cur.execute("""
            UPDATE devices 
            SET status = %s, last_check = %s 
            WHERE id = %s
        """, (status, datetime.now(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, datetime.now()))
        
        mysql.connection.commit()
        cur.close()
        
        print(f"✓ Device checked: {status}")
        print(f"{'='*60}\n")
        

        status_icon = "🟢" if status == 'online' else "🔴"
        latency_text = f"{latency:.2f}ms" if latency and latency < 999 else "N/A"
        flash(f'{status_icon} {device_name}: {status.upper()} | Latency: {latency_text}', 'success' if status == 'online' else 'warning')
        
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error checking device: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

def test_connection(ip_address, timeout=3):
    """
    Test koneksi ke IP dengan berbagai metode
    Return True jika bisa terconnect dengan cara apapun
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', str(timeout * 1000), ip_address]
    
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout + 2, text=True)
        if result.returncode == 0:
            print(f"✓ {ip_address} reachable via PING")
            return True
    except:
        pass
    
    # Method 2: TCP Connection test (untuk device yang block ICMP)
    # Coba common ports: HTTP(80), HTTPS(443), SSH(22), Telnet(23)
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
    
    # Method 3: DNS resolution check (untuk hostnames)
    try:
        socket.gethostbyname(ip_address)
        print(f"✓ {ip_address} resolvable via DNS")
        return True
    except:
        pass
    
    print(f"✗ {ip_address} not reachable")
    return False


def ping_host(ip_address):
    """
    Ping host sederhana - cek apakah device bisa terconnect
    Return: True jika online (terconnect), False jika offline
    """
    return test_connection(ip_address, timeout=3)


def ping_host_detailed(ip_address):
    """
    Ping host dan return detail: status, latency, packet_loss, response_time
    """
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

        print(f"\n=== Ping Output for {ip_address} ===")
        print(output_text[:500])
        print("="*50)
        
        # Jika ping berhasil
        if output.returncode == 0:
            result['status'] = 'online'
            
            if platform.system().lower() == 'windows':
                # STEP 1: Coba ambil Average dari statistics
                latency_patterns = [
                    r'[Aa]verage\s*=\s*(\d+(?:\.\d+)?)ms',
                    r'[Rr]ata-rata\s*=\s*(\d+(?:\.\d+)?)ms',
                ]
                
                latency_found = False
                for pattern in latency_patterns:
                    match = re.search(pattern, output_text)
                    if match:
                        avg_value = float(match.group(1))
                        # Jika Average = 0, berarti semua reply < 1ms
                        if avg_value > 0:
                            result['latency'] = avg_value
                            latency_found = True
                            print(f"Found latency from Average: {avg_value}ms")
                            break
                
                # STEP 2: Jika Average = 0 atau tidak ditemukan, parse individual times
                if not latency_found or result['latency'] == 0:
                    print("Parsing individual reply times...")
                    
                    # Pattern yang bisa handle: time=1ms, time<1ms, time=0ms
                    time_patterns = [
                        r'time=(\d+)ms',      # time=1ms, time=2ms
                        r'time<(\d+)ms',      # time<1ms
                    ]
                    
                    time_values = []
                    
                    # Cari semua time values
                    for pattern in time_patterns:
                        matches = re.findall(pattern, output_text)
                        for match in matches:
                            time_val = float(match)
                            
                            # Jika pattern adalah time<Xms, gunakan nilai lebih kecil
                            if '<' in pattern:
                                # time<1ms berarti sekitar 0.5ms
                                time_val = time_val * 0.5
                            
                            time_values.append(time_val)
                    
                    print(f"Individual time values found: {time_values}")
                    
                    if time_values:
                        # Hitung average dari individual times
                        avg = sum(time_values) / len(time_values)
                        result['latency'] = round(avg, 2)
                        print(f"Calculated latency from individual times: {result['latency']}ms")
                    else:
                        # Tidak ada time values ditemukan, set default untuk koneksi sangat cepat
                        result['latency'] = 0.5
                        print(f"No time values found, using default: 0.5ms")
                
                # STEP 3: Parsing Packet Loss
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
                    sent_match = re.search(r'Sent\s*=\s*(\d+)', output_text)
                    received_match = re.search(r'Received\s*=\s*(\d+)', output_text)
                    if sent_match and received_match:
                        sent = int(sent_match.group(1))
                        received = int(received_match.group(1))
                        if sent > 0:
                            result['packet_loss'] = round(((sent - received) / sent) * 100, 2)
                        else:
                            result['packet_loss'] = 0.0
                    else:
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
        
        # Jika ping gagal, coba method lain
        else:
            print(f"Ping failed, trying alternative connection methods...")
            if test_connection(ip_address, timeout=2):
                result['status'] = 'online'
                result['latency'] = 999
                result['packet_loss'] = 0.0
                result['response_time'] = duration_ms
                print(f"✓ Device reachable via alternative method")
            else:
                result['status'] = 'offline'
                result['packet_loss'] = 100.0
        
        print(f"Final Result: status={result['status']}, latency={result['latency']}, "
              f"packet_loss={result['packet_loss']}")
            
    except subprocess.TimeoutExpired:
        print(f"Timeout, trying alternative methods...")
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
            
            # Validasi input
            if not name or not ip_address:
                flash('Nama dan IP Address harus diisi', 'warning')
                return render_template('add_device.html')
            
            # Validasi format IP (basic)
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, ip_address):
                flash('Format IP Address tidak valid. Gunakan format xxx.xxx.xxx.xxx', 'warning')
                return render_template('add_device.html')
            
            # Validasi range IP (0-255 per octet)
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
            
            # Test koneksi ke device
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
            """, (name, ip_address, description, status, datetime.now()))
            
            mysql.connection.commit()
            device_id = cur.lastrowid
            cur.close()
            
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
        
        print(f"Checking: {device_name} ({ip_address})")
        
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
        """, (status, datetime.now(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, datetime.now()))
    
    mysql.connection.commit()
    cur.close()
    
    print(f"\n{'='*60}")
    print(f"✓ Completed: {online_count} online, {offline_count} offline")
    print(f"{'='*60}\n")
    
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
        """, (status, datetime.now(), device_id))
        
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, datetime.now()))
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({
            'success': True,
            'device_id': device_id,
            'status': status,
            'latency': latency,
            'packet_loss': packet_loss,
            'response_time': response_time,
            'last_check': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500
    

    

# ========== RUN APPLICATION ==========

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Network Monitoring System")
    print("="*60)
    print("Connection Test: PING + TCP Ports + DNS")
    print("="*60 + "\n")
    
    app.run(debug=True)