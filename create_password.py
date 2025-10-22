"""

untuk membuat user baru atau reset password
"""

from werkzeug.security import generate_password_hash

def create_password():
    print("=" * 50)
    print("PASSWORD HASH GENERATOR")
    print("=" * 50)
    
    password = input("\nMasukkan password yang ingin di-hash: ")
    
    # Generate hash
    hashed = generate_password_hash(password)
    
    print("\n" + "=" * 50)
    print("HASIL:")
    print("=" * 50)
    print(f"Password Original: {password}")
    print(f"Password Hash: {hashed}")
    print("\n" + "=" * 50)
    print("SQL QUERY untuk insert user baru:")
    print("=" * 50)
    
    username = input("\nUsername: ")
    email = input("Email: ")
    role = input("Role (admin/viewer): ")
    
    sql = f"""
INSERT INTO users (username, email, password, role) VALUES
('{username}', '{email}', '{hashed}', '{role}');
"""
    
    print("\n" + sql)
    print("\nCopy SQL di atas dan jalankan di MySQL untuk menambah user baru!")
    print("=" * 50)

if __name__ == "__main__":
    create_password()