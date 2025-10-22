"""
Script untuk generate password hash yang benar dan update ke database
Jalankan: python fix_password.py
"""

from werkzeug.security import generate_password_hash
import MySQLdb

# Konfigurasi Database
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Sesuaikan dengan password MySQL Anda
    'database': 'network_monitoring'
}

def fix_passwords():
    print("="*60)
    print("FIX PASSWORD - Network Monitoring System")
    print("="*60)
    
    # Password yang akan digunakan
    admin_password = "admin123"
    viewer_password = "viewer123"
    
    # Generate hash
    admin_hash = generate_password_hash(admin_password)
    viewer_hash = generate_password_hash(viewer_password)
    
    print(f"\nGenerated Hashes:")
    print(f"Admin password: {admin_password}")
    print(f"Admin hash: {admin_hash[:50]}...")
    print(f"\nViewer password: {viewer_password}")
    print(f"Viewer hash: {viewer_hash[:50]}...")
    
    try:
        # Koneksi ke database
        conn = MySQLdb.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Update password admin
        cursor.execute("UPDATE users SET password = %s WHERE username = 'admin'", (admin_hash,))
        print("\n✓ Password admin berhasil diupdate")
        
        # Update password viewer
        cursor.execute("UPDATE users SET password = %s WHERE username = 'viewer'", (viewer_hash,))
        print("✓ Password viewer berhasil diupdate")
        
        # Commit changes
        conn.commit()
        
        # Verifikasi
        cursor.execute("SELECT username, role FROM users")
        users = cursor.fetchall()
        
        print("\n" + "="*60)
        print("DAFTAR USER SETELAH UPDATE:")
        print("="*60)
        for user in users:
            print(f"Username: {user[0]:10s} | Role: {user[1]}")
        
        print("\n" + "="*60)
        print("SELESAI! Sekarang coba login dengan:")
        print("="*60)
        print("Admin  → username: admin  | password: admin123")
        print("Viewer → username: viewer | password: viewer123")
        print("="*60)
        
        cursor.close()
        conn.close()
        
    except MySQLdb.Error as e:
        print(f"\n❌ Database Error: {e}")
        print("\nPastikan:")
        print("1. MySQL service berjalan")
        print("2. Database 'network_monitoring' sudah dibuat")
        print("3. Username/password MySQL di script ini benar")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    fix_passwords()