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

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'network_monitoring'

mysql = MySQL(app)

# Decorator untuk cek login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator untuk cek admin
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

# Fungsi ping sederhana (untuk add device)
def ping_host(ip_address):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip_address]
    try:
        output = subprocess.run(command, capture_output=True, timeout=5)
        return output.returncode == 0
    except:
        return False

# Fungsi ping lengkap dengan latency, packet_loss, dan response_time
def ping_host_detailed(ip_address):
    """
    Ping host dan return detail: status, latency, packet_loss, response_time
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', ip_address]
    
    result = {
        'status': 'offline',
        'latency': None,
        'packet_loss': 100.0,
        'response_time': None
    }
    
    try:
        start_time = time.time()  # waktu mulai ping
        output = subprocess.run(command, capture_output=True, timeout=10, text=True)
        end_time = time.time()    # waktu selesai ping

        output_text = output.stdout
        duration_ms = round((end_time - start_time) * 1000, 2)  # konversi ke ms
        result['response_time'] = duration_ms

        print(f"\n=== Ping Output for {ip_address} ===")
        print(output_text)
        print("="*50)
        
        if output.returncode == 0:
            result['status'] = 'online'
            
            if platform.system().lower() == 'windows':
                # Latency (Average)
                match = re.search(r'[Aa]verage = (\d+)ms', output_text) or \
                        re.search(r'[Rr]ata-rata = (\d+)ms', output_text)
                if match:
                    result['latency'] = float(match.group(1))
                
                # Packet Loss
                loss_match = re.search(r'\((\d+)% loss\)', output_text) or \
                             re.search(r'\((\d+)% hilang\)', output_text)
                if loss_match:
                    result['packet_loss'] = float(loss_match.group(1))
                else:
                    result['packet_loss'] = 0.0
            else:
                # Linux/Mac parsing
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output_text)
                if match:
                    result['latency'] = float(match.group(1))
                
                loss_match = re.search(r'(\d+)% packet loss', output_text)
                if loss_match:
                    result['packet_loss'] = float(loss_match.group(1))
                else:
                    result['packet_loss'] = 0.0
        else:
            result['packet_loss'] = 100.0
            result['status'] = 'offline'
            
    except subprocess.TimeoutExpired:
        print(f"Timeout pinging {ip_address}")
        result['status'] = 'offline'
        result['packet_loss'] = 100.0
    except Exception as e:
        print(f"Error pinging {ip_address}: {e}")
        result['status'] = 'offline'
        result['packet_loss'] = 100.0
    
    return result


# Route Login
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

# Route Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout', 'info')
    return redirect(url_for('login'))

# Route Dashboard
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

# Route Tambah Device (Admin Only)
@app.route('/add_device', methods=['GET', 'POST'])
@admin_required
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        ip_address = request.form['ip_address']
        description = request.form['description']
        
        status = 'online' if ping_host(ip_address) else 'offline'
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO devices (name, ip_address, description, status, last_check) VALUES (%s, %s, %s, %s, %s)",
                   (name, ip_address, description, status, datetime.now()))
        mysql.connection.commit()
        cur.close()
        
        flash('Device berhasil ditambahkan', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_device.html')

# Route Edit Device (Admin Only)
@app.route('/edit_device/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_device(id):
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        ip_address = request.form['ip_address']
        description = request.form['description']
        
        cur.execute("UPDATE devices SET name = %s, ip_address = %s, description = %s WHERE id = %s",
                   (name, ip_address, description, id))
        mysql.connection.commit()
        cur.close()
        
        flash('Device berhasil diupdate', 'success')
        return redirect(url_for('dashboard'))
    
    cur.execute("SELECT * FROM devices WHERE id = %s", (id,))
    device = cur.fetchone()
    cur.close()
    
    return render_template('edit_device.html', device=device)

# Route Delete Device (Admin Only)
@app.route('/delete_device/<int:id>')
@admin_required
def delete_device(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM devices WHERE id = %s", (id,))
    cur.execute("DELETE FROM monitoring_logs WHERE device_id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Device berhasil dihapus', 'success')
    return redirect(url_for('dashboard'))

# Route Check All Devices (Admin Only)
@app.route('/check_all')
@admin_required
def check_all():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM devices")
    devices = cur.fetchall()
    
    for device in devices:
        device_id = device[0]
        ip_address = device[2]
        
        # Ping device dengan detail
        ping_result = ping_host_detailed(ip_address)
        
        status = ping_result['status']
        latency = ping_result['latency']
        packet_loss = ping_result['packet_loss']
        response_time = ping_result['response_time']
        
        print(f"Device {device[1]}: status={status}, latency={latency}, packet_loss={packet_loss}, response_time={response_time}")
        
        # Update status di tabel devices
        cur.execute("""
            UPDATE devices 
            SET status = %s, last_check = %s 
            WHERE id = %s
        """, (status, datetime.now(), device_id))
        
        # Simpan log lengkap
        cur.execute("""
            INSERT INTO monitoring_logs (device_id, status, latency, packet_loss, response_time, checked_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (device_id, status, latency, packet_loss, response_time, datetime.now()))
    
    mysql.connection.commit()
    cur.close()
    
    flash('Semua device telah dicek dan response time berhasil ditambahkan.', 'success')
    return redirect(url_for('dashboard'))

# Route History Logs
@app.route('/history/<int:device_id>')
@login_required
def history(device_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cur.fetchone()
    
    cur.execute("SELECT * FROM monitoring_logs WHERE device_id = %s ORDER BY checked_at DESC LIMIT 100", (device_id,))
    logs = cur.fetchall()
    cur.close()
    
    return render_template('history.html', device=device, logs=logs)

# Route Analytics
@app.route('/analytics/<int:device_id>')
@login_required
def analytics(device_id):
    cur = mysql.connection.cursor()
    
    # ngambil info device nya
    cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cur.fetchone()
    
    if not device:
        flash('Device tidak ditemukan', 'error')
        return redirect(url_for('dashboard'))
    
   
    cur.execute("""
        SELECT checked_at, status, latency, packet_loss 
        FROM monitoring_logs 
        WHERE device_id = %s 
        AND checked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY checked_at ASC
    """, (device_id,))
    logs = cur.fetchall()
    
    # kalkukasi statistik
    if logs:
        latencies = [log[2] for log in logs if log[2] is not None]
        packet_losses = [log[3] for log in logs if log[3] is not None]
        
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        avg_packet_loss = sum(packet_losses) / len(packet_losses) if packet_losses else 0
        min_latency = min(latencies) if latencies else 0
        
        stats = (avg_latency, avg_packet_loss, min_latency)
        
        # ngekalkulasi uptime persentasenya
        online_count = sum(1 for log in logs if log[1] == 'online')
        uptime_percentage = round((online_count / len(logs)) * 100, 2) if logs else 0
    else:
        stats = (0, 0, 0)
        uptime_percentage = 0
    
    cur.close()
    
    return render_template('analytics.html', 
                         device=device, 
                         logs=logs, 
                         stats=stats,
                         uptime_percentage=uptime_percentage)

# API untuk realtime monitoring
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

if __name__ == '__main__':
    app.run(debug=True)