#!/usr/bin/env python3
"""
==============================================================================
EXAMSHIELD - PERSISTENT DATABASE INITIALIZER & SCHEMA MIGRATION
==============================================================================
This script non-destructively initializes and verifies the MySQL database schema
for ExamShield across both local development (XAMPP / MySQL local) and cloud 
deployments (TiDB Cloud Serverless, Aiven MySQL, Railway, Clever Cloud, etc.).

Features:
- Reads credentials from DATABASE_URL / MYSQL_URL or individual DB_* env variables
- Creates all 8 core tables with CREATE TABLE IF NOT EXISTS
- Seeds default government officer and mock records only if tables are empty
- NEVER drops data during regular initialization (ensures persistence across redeploys)
- Provides diagnostic reporting and connectivity checks
==============================================================================
"""

import sys
import os
import urllib.parse
import mysql.connector
from dotenv import load_dotenv

# Load local .env if available
load_dotenv()


def get_db_config():
    """
    Parses and returns MySQL connection parameters from environment variables.
    Supports standard cloud connection URIs (DATABASE_URL / MYSQL_URL)
    as well as individual DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME variables.
    """
    db_url = (
        os.environ.get('DATABASE_URL') or
        os.environ.get('MYSQL_URL') or
        os.environ.get('JAWSDB_URL') or
        os.environ.get('CLEARDB_DATABASE_URL') or
        ''
    ).strip()

    if db_url and db_url.startswith(('mysql://', 'mysql2://')):
        if db_url.startswith('mysql2://'):
            db_url = 'mysql://' + db_url[9:]
        parsed = urllib.parse.urlparse(db_url)
        cfg = {
            'host': parsed.hostname or '127.0.0.1',
            'port': int(parsed.port or 3306),
            'user': urllib.parse.unquote(parsed.username or 'root'),
            'password': urllib.parse.unquote(parsed.password or ''),
            'database': parsed.path.lstrip('/') or 'examshield',
            'autocommit': True,
            'connection_timeout': int(os.environ.get('DB_CONNECT_TIMEOUT', '10'))
        }
        qs = urllib.parse.parse_qs(parsed.query)
        if 'ssl-mode' in qs or 'ssl' in qs or parsed.hostname not in ('localhost', '127.0.0.1', '0.0.0.0'):
            cfg['ssl_disabled'] = False
        else:
            cfg['ssl_disabled'] = True

        ssl_ca = os.environ.get('DB_SSL_CA')
        if ssl_ca:
            cfg['ssl_ca'] = ssl_ca
        return cfg

    host = os.environ.get('DB_HOST', '127.0.0.1').strip()
    port = int(os.environ.get('DB_PORT', '3306'))
    user = os.environ.get('DB_USER', 'root').strip()
    password = os.environ.get('DB_PASSWORD', 'root')
    database = os.environ.get('DB_NAME', 'examshield').strip()

    cfg = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database,
        'autocommit': True,
        'connection_timeout': int(os.environ.get('DB_CONNECT_TIMEOUT', '10'))
    }

    ssl_disabled_env = os.environ.get('DB_SSL_DISABLED')
    if ssl_disabled_env is not None:
        cfg['ssl_disabled'] = ssl_disabled_env.lower() in ('true', '1', 't')
    elif host not in ('localhost', '127.0.0.1', '0.0.0.0'):
        cfg['ssl_disabled'] = False
    else:
        cfg['ssl_disabled'] = True

    ssl_ca = os.environ.get('DB_SSL_CA')
    if ssl_ca:
        cfg['ssl_ca'] = ssl_ca

    return cfg


TABLE_SCHEMAS = [
    # 1. users table
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        government_id VARCHAR(100) UNIQUE NOT NULL,
        officer_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'Officer',
        status VARCHAR(50) DEFAULT 'Active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 2. otp table
    """
    CREATE TABLE IF NOT EXISTS otp (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        otp_hash VARCHAR(64) NOT NULL,
        created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expiry_time TIMESTAMP NOT NULL,
        attempts INT DEFAULT 0,
        verified TINYINT(1) DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 3. remember_tokens table
    """
    CREATE TABLE IF NOT EXISTS remember_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(64) UNIQUE NOT NULL,
        expiry_date TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 4. exams table
    """
    CREATE TABLE IF NOT EXISTS exams (
        id INT AUTO_INCREMENT PRIMARY KEY,
        exam_code VARCHAR(50) UNIQUE NOT NULL,
        exam_name VARCHAR(150) NOT NULL,
        authority VARCHAR(100) NOT NULL,
        total_questions INT DEFAULT 100,
        exam_date DATE NOT NULL,
        exam_time TIME NOT NULL,
        exam_type VARCHAR(50) NOT NULL,
        state_ut VARCHAR(100) NOT NULL,
        total_marks INT DEFAULT 100,
        passing_marks INT DEFAULT 35,
        negative_marking VARCHAR(3) DEFAULT 'No',
        duration INT DEFAULT 180,
        security_aes TINYINT(1) DEFAULT 1,
        security_ai TINYINT(1) DEFAULT 1,
        security_blockchain TINYINT(1) DEFAULT 1,
        security_qr TINYINT(1) DEFAULT 1,
        security_face TINYINT(1) DEFAULT 0,
        security_dual TINYINT(1) DEFAULT 0,
        paper_file_path VARCHAR(255) DEFAULT NULL,
        paper_hash VARCHAR(64) DEFAULT NULL,
        security_score INT DEFAULT 0,
        security_report LONGTEXT DEFAULT NULL,
        status VARCHAR(50) DEFAULT 'Created',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 5. centers table
    """
    CREATE TABLE IF NOT EXISTS centers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        city VARCHAR(100) NOT NULL,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        integrity_score INT DEFAULT 100,
        status VARCHAR(50) DEFAULT 'Online',
        exam_code VARCHAR(50) DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 6. notifications table
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(100) NOT NULL,
        message VARCHAR(255) NOT NULL,
        notification_type VARCHAR(50) DEFAULT 'system',
        is_read TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 7. blockchain_logs table
    """
    CREATE TABLE IF NOT EXISTS blockchain_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        exam_code VARCHAR(50) NOT NULL,
        block_index INT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action VARCHAR(100) NOT NULL,
        previous_hash VARCHAR(64) NOT NULL,
        block_hash VARCHAR(64) NOT NULL,
        operator VARCHAR(100) NOT NULL,
        status VARCHAR(50) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # 8. tracking_logs table
    """
    CREATE TABLE IF NOT EXISTS tracking_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        exam_code VARCHAR(50) NOT NULL,
        status VARCHAR(100) NOT NULL,
        location_name VARCHAR(150) NOT NULL,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by VARCHAR(100) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """
]


def initialize_database(reset=False, skip_if_populated=False):
    """
    Connects to MySQL and establishes the complete database schema.
    If reset=True, drops all tables before creating.
    If skip_if_populated=True, skips seeding if tables already exist.
    """
    cfg = get_db_config()
    target_db = cfg['database']

    print(f"[INIT] Connecting to MySQL server at {cfg['host']}:{cfg['port']}...")

    # Step 1: Connect without database specified first to ensure database exists if permitted
    conn = None
    try:
        # Create a shallow copy without database for initial server handshake
        srv_cfg = {k: v for k, v in cfg.items() if k != 'database'}
        srv_conn = mysql.connector.connect(**srv_cfg)
        srv_cur = srv_conn.cursor()
        try:
            srv_cur.execute(f"CREATE DATABASE IF NOT EXISTS `{target_db}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            srv_conn.commit()
            print(f"[INIT] Database `{target_db}` ensured on server.")
        except Exception as e:
            # Managed cloud databases (e.g. TiDB, Aiven) might restrict CREATE DATABASE
            print(f"[INIT] Notice on CREATE DATABASE: {e}. Proceeding directly to connect to `{target_db}`.")
        finally:
            srv_cur.close()
            srv_conn.close()
    except Exception as e:
        print(f"[INIT] Note: Could not connect to raw server ({e}), trying direct connection to `{target_db}`...")

    # Step 2: Connect directly to target database
    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor(dictionary=True)
    print(f"[INIT] Successfully connected to database `{target_db}`.")

    try:
        if reset:
            print("[CAUTION] Reset flag set. Dropping existing tables...")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
            for tbl in ['tracking_logs', 'blockchain_logs', 'notifications', 'centers', 'exams', 'remember_tokens', 'otp', 'users']:
                cursor.execute(f"DROP TABLE IF EXISTS `{tbl}`;")
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
            conn.commit()
            print("[INIT] Tables dropped.")

        # Step 3: Create core tables
        print("[INIT] Verifying and creating required tables...")
        for schema_stmt in TABLE_SCHEMAS:
            cursor.execute(schema_stmt)
        conn.commit()
        print("[INIT] All 8 core tables verified successfully.")

        # Step 4: Seed default officer user if table empty or user missing
        cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE government_id = 'officer@examshield.gov.in'")
        res = cursor.fetchone()
        if not res or res['cnt'] == 0:
            print("[INIT] Seeding default government officer user...")
            cursor.execute("""
                INSERT INTO users (government_id, officer_name, email, phone, password_hash, role, status)
                VALUES (
                    'officer@examshield.gov.in',
                    'Officer Alka',
                    'alkavarak17@gmail.com',
                    '+919137870458',
                    '$2b$12$yCDh/fC1OYs/jWiPcPCvhu5A1AqXwhkTfqbR4HpCPEEzJPaCL45mK',
                    'Officer',
                    'Active'
                )
                ON DUPLICATE KEY UPDATE officer_name = VALUES(officer_name);
            """)
            conn.commit()
            print("[INIT] Default officer seeded (ID: officer@examshield.gov.in / Password: SecurePassword123).")

        # Step 5: Seed mock exams if table is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM exams")
        exam_cnt = cursor.fetchone()['cnt']
        if exam_cnt == 0:
            print("[INIT] Seeding baseline examination records...")
            mock_exams = [
                ('EXM-2026-001', 'UPSC Civil Services Prelims', 'UPSC', 100, '2026-06-15', '09:30:00', 'Competitive', 'Delhi', 98, 'Created'),
                ('EXM-2026-002', 'SSC CGL Tier 1', 'SSC', 100, '2026-06-18', '14:00:00', 'Competitive', 'Maharashtra', 94, 'In Transit'),
                ('EXM-2026-003', 'JEE Main Session 1', 'NTA', 90, '2026-06-20', '09:00:00', 'Competitive', 'Rajasthan', 82, 'Arrived'),
                ('EXM-2026-004', 'NEET UG 2026', 'NTA', 180, '2026-06-25', '14:00:00', 'Competitive', 'Tamil Nadu', 97, 'Verified'),
                ('EXM-2026-005', 'IBPS PO Prelims', 'IBPS', 100, '2026-07-02', '10:00:00', 'Competitive', 'Karnataka', 92, 'Created')
            ]
            cursor.executemany("""
                INSERT INTO exams (exam_code, exam_name, authority, total_questions, exam_date, exam_time, exam_type, state_ut, security_score, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE exam_name=VALUES(exam_name);
            """, mock_exams)
            conn.commit()
            print("[INIT] Baseline examinations seeded.")

        # Step 6: Seed mock centers if table is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM centers")
        center_cnt = cursor.fetchone()['cnt']
        if center_cnt == 0:
            print("[INIT] Seeding baseline examination centers...")
            mock_centers = [
                ('Mumbai Central Academy', 'Mumbai', 19.0760, 72.8777, 98, 'Online'),
                ('Navi Mumbai Technical High School', 'Navi Mumbai', 19.0330, 73.0297, 91, 'Online'),
                ('Thane Public School Center 3', 'Thane', 19.2183, 72.9781, 76, 'Online'),
                ('Pune University Campus Hall 2', 'Pune', 18.5204, 73.8567, 96, 'Online'),
                ('Delhi National Trust Academy', 'Delhi', 28.7041, 77.1025, 88, 'Online')
            ]
            cursor.executemany("""
                INSERT INTO centers (name, city, latitude, longitude, integrity_score, status)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE name=VALUES(name);
            """, mock_centers)
            conn.commit()
            print("[INIT] Baseline examination centers seeded.")

        # Step 7: Seed baseline blockchain logs if empty
        cursor.execute("SELECT COUNT(*) as cnt FROM blockchain_logs")
        bc_cnt = cursor.fetchone()['cnt']
        if bc_cnt == 0:
            print("[INIT] Seeding baseline blockchain audit logs...")
            mock_blocks = [
                ('EXM-2026-004', 0, '2026-07-25 10:00:00', 'Paper Created', '0000000000000000000000000000000000000000000000000000000000000000', '8ca4a58b97d26456fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7cc0', 'officer@examshield.gov.in', 'Success'),
                ('EXM-2026-004', 1, '2026-07-25 10:15:00', 'Hash Generated', '8ca4a58b97d26456fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7cc0', '4fc5d8091ecb5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e987654a', 'officer@examshield.gov.in', 'Success'),
                ('EXM-2026-004', 2, '2026-07-25 10:30:00', 'AES Encrypted', '4fc5d8091ecb5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e987654a', '6e6f9de5d078c5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e99876f', 'officer@examshield.gov.in', 'Success'),
                ('EXM-2026-002', 0, '2026-07-25 11:20:00', 'Paper Created', '0000000000000000000000000000000000000000000000000000000000000000', 'd7a8fbb307d7cf56fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7bb1', 'officer@examshield.gov.in', 'Success')
            ]
            cursor.executemany("""
                INSERT INTO blockchain_logs (exam_code, block_index, timestamp, action, previous_hash, block_hash, operator, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE block_hash=VALUES(block_hash);
            """, mock_blocks)
            conn.commit()
            print("[INIT] Baseline blockchain logs seeded.")

        # Step 8: Seed baseline transit tracking if empty
        cursor.execute("SELECT COUNT(*) as cnt FROM tracking_logs")
        track_cnt = cursor.fetchone()['cnt']
        if track_cnt == 0:
            print("[INIT] Seeding baseline transit tracking waypoints...")
            mock_tracks = [
                ('EXM-2026-002', 'Vault Dispatch', 'Central Printing Vault, Pune', 18.52040000, 73.85670000, 'officer@examshield.gov.in'),
                ('EXM-2026-002', 'In Transit Stopover', 'Lonavala Expressway Security Outpost', 18.75570000, 73.40910000, 'officer@examshield.gov.in'),
                ('EXM-2026-002', 'In Transit - Current', 'Navi Mumbai Highway Toll Plaza', 19.03300000, 73.02970000, 'officer@examshield.gov.in'),
                ('EXM-2026-002', 'Destination Center', 'Thane Public School Center 3', 19.21830000, 72.97810000, 'officer@examshield.gov.in')
            ]
            cursor.executemany("""
                INSERT INTO tracking_logs (exam_code, status, location_name, latitude, longitude, updated_by)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE location_name=VALUES(location_name);
            """, mock_tracks)
            conn.commit()
            print("[INIT] Baseline transit tracking waypoints seeded.")

        print("=" * 65)
        print(" EXAMSHIELD DATABASE INITIALIZATION & VERIFICATION SUCCESSFUL")
        print("=" * 65)
        print(f" Database: {target_db}")
        print(f" Host:     {cfg['host']}:{cfg['port']}")
        print(f" SSL:      {'Enabled' if not cfg.get('ssl_disabled', True) else 'Disabled'}")
        print(" All tables and baseline records are ready for deployment.")
        print("=" * 65)
        return True

    except Exception as err:
        print(f"[INIT ERROR] Database initialization failed: {err}")
        return False
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def check_database():
    """
    Diagnostic tool to check current database connection and show table summary.
    """
    cfg = get_db_config()
    print("=" * 65)
    print(" EXAMSHIELD DATABASE DIAGNOSTICS")
    print("=" * 65)
    print(f" Host:     {cfg['host']}:{cfg['port']}")
    print(f" User:     {cfg['user']}")
    print(f" Database: {cfg['database']}")
    print(f" SSL:      {'Enabled' if not cfg.get('ssl_disabled', True) else 'Disabled'}")
    print("-" * 65)

    try:
        conn = mysql.connector.connect(**cfg)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SHOW TABLES")
        tables = [list(r.values())[0] for r in cursor.fetchall()]
        print(f" Active Tables ({len(tables)}): {', '.join(tables)}")

        for tbl in ['users', 'exams', 'centers', 'blockchain_logs', 'tracking_logs', 'otp', 'notifications']:
            if tbl in tables:
                cursor.execute(f"SELECT COUNT(*) as count FROM `{tbl}`")
                cnt = cursor.fetchone()['count']
                print(f"   - {tbl:<18}: {cnt:>5} records")

        cursor.close()
        conn.close()
        print("-" * 65)
        print(" Connectivity: OPERATIONAL")
        print("=" * 65)
        return True
    except Exception as e:
        print(f" Connection Failed: {e}")
        print("=" * 65)
        return False


if __name__ == '__main__':
    args = sys.argv[1:]
    if '--check' in args:
        success = check_database()
        sys.exit(0 if success else 1)
    elif '--reset' in args:
        confirm = input("Are you sure you want to completely DROP all ExamShield tables? (yes/no): ")
        if confirm.lower() == 'yes':
            success = initialize_database(reset=True)
            sys.exit(0 if success else 1)
        else:
            print("Reset aborted.")
            sys.exit(0)
    else:
        success = initialize_database()
        sys.exit(0 if success else 1)
