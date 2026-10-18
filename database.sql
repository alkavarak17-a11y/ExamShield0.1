-- ==========================================
-- EXAMSHIELD DATABASE INITIALIZATION
-- ==========================================
-- This script sets up the database schema for the entire ExamShield application.
-- It creates the database and the necessary tables for officer authentication.

-- 1. Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS examshield;
USE examshield;

-- 2. Create the 'users' table to hold credential information
-- (Note: Avoid DROP TABLE in production to preserve user accounts and logs across deployments)
-- DROP TABLE IF EXISTS remember_tokens;
-- DROP TABLE IF EXISTS otp;
-- DROP TABLE IF EXISTS officers;
-- DROP TABLE IF EXISTS users;

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

-- Create the 'otp' table for 2FA validation and Forgot Password flow
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

-- Create the 'remember_tokens' table for secure Remember Me sessions
CREATE TABLE IF NOT EXISTS remember_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) UNIQUE NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Seed initial default government officer for testing
-- Government ID: officer@examshield.gov.in
-- Plaintext Password: SecurePassword123
-- Stored Hash (Bcrypt): $2b$12$yCDh/fC1OYs/jWiPcPCvhu5A1AqXwhkTfqbR4HpCPEEzJPaCL45mK
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
ON DUPLICATE KEY UPDATE
    officer_name = VALUES(officer_name),
    password_hash = VALUES(password_hash);

-- 4. Create the 'exams' table to store examination records
-- Each column is explained below:
CREATE TABLE IF NOT EXISTS exams (
    -- 'id': Uniquely identifies each exam. Incrementing primary key.
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- 'exam_code': Unique alphanumeric security identifier for the exam (e.g. EXM-2026-001).
    exam_code VARCHAR(50) UNIQUE NOT NULL,
    
    -- 'exam_name': Formal name of the examination.
    exam_name VARCHAR(150) NOT NULL,
    
    -- 'authority': Conducting body (e.g. UPSC, NTA, SSC).
    authority VARCHAR(100) NOT NULL,
    
    -- 'total_questions': Total number of questions in the paper. Defaults to 100.
    total_questions INT DEFAULT 100,
    
    -- 'exam_date': Scheduled date of the exam.
    exam_date DATE NOT NULL,
    
    -- 'exam_time': Scheduled start time of the exam.
    exam_time TIME NOT NULL,
    
    -- 'exam_type': Type category (e.g. Competitive, University, Recruitment, Board).
    exam_type VARCHAR(50) NOT NULL,
    
    -- 'state_ut': State or Union Territory of administration.
    state_ut VARCHAR(100) NOT NULL,
    
    -- 'total_marks': Total paper marks. Defaults to 100.
    total_marks INT DEFAULT 100,
    
    -- 'passing_marks': Minimum marks required to pass. Defaults to 35.
    passing_marks INT DEFAULT 35,
    
    -- 'negative_marking': Whether incorrect answers deduct marks (Yes/No).
    negative_marking VARCHAR(3) DEFAULT 'No',
    
    -- 'duration': Duration in minutes. Defaults to 180 (3 hours).
    duration INT DEFAULT 180,
    
    -- 'security_aes': Configuration flag: AES-256 Encryption active (1=Yes, 0=No).
    security_aes TINYINT(1) DEFAULT 1,
    
    -- 'security_ai': Configuration flag: AI Threat Detection active (1=Yes, 0=No).
    security_ai TINYINT(1) DEFAULT 1,
    
    -- 'security_blockchain': Configuration flag: Blockchain protection active (1=Yes, 0=No).
    security_blockchain TINYINT(1) DEFAULT 1,
    
    -- 'security_qr': Configuration flag: SmartTrace QR tracking active (1=Yes, 0=No).
    security_qr TINYINT(1) DEFAULT 1,
    
    -- 'security_face': Configuration flag: Candidate Face Verification active.
    security_face TINYINT(1) DEFAULT 0,
    
    -- 'security_dual': Configuration flag: Dual Officer Approval active.
    security_dual TINYINT(1) DEFAULT 0,
    
    -- 'paper_file_path': Secure local filesystem directory path to the encrypted question paper document.
    paper_file_path VARCHAR(255) DEFAULT NULL,
    
    -- 'paper_hash': Cryptographic SHA-256 hash representation of the paper (Exam DNA).
    paper_hash VARCHAR(64) DEFAULT NULL,
    
    -- 'security_score': Computed risk integrity percentage score (0 to 100).
    security_score INT DEFAULT 0,
    
    -- 'security_report': Detailed report outcomes generated by the AI Security Engine.
    security_report LONGTEXT DEFAULT NULL,
    
    -- 'status': State of the exam paper in the dispatch chain.
    -- E.g. 'Created', 'Uploaded', 'Scanned', 'Encrypted', 'Dispatched', 'Arrived', 'Verified'.
    status VARCHAR(50) DEFAULT 'Created',
    
    -- 'created_at': Timestamp of exam generation.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Create the 'centers' table to store active examination center metadata
CREATE TABLE IF NOT EXISTS centers (
    -- 'id': Uniquely identifies each exam center.
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- 'name': The school, college or center name hosting the exam.
    name VARCHAR(150) NOT NULL,
    
    -- 'city': Location city of the exam center.
    city VARCHAR(100) NOT NULL,
    
    -- 'latitude': Geographic coordinate latitude (for Leaflet.js mapping).
    latitude DECIMAL(10, 8) NOT NULL,
    
    -- 'longitude': Geographic coordinate longitude.
    longitude DECIMAL(11, 8) NOT NULL,
    
    -- 'integrity_score': Current reliability score calculated from local sensor/breach monitoring.
    integrity_score INT DEFAULT 100,
    
    -- 'status': Connection and status flag (e.g. 'Online', 'Offline', 'Compromised').
    status VARCHAR(50) DEFAULT 'Online',
    
    -- 'exam_code': Links center to an active examination.
    exam_code VARCHAR(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Create the 'notifications' table to store user system notifications
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

-- 7. Create the 'blockchain_logs' table to log SecureChain ledger entries
CREATE TABLE IF NOT EXISTS blockchain_logs (
    -- 'id': Uniquely identifies each block log.
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- 'exam_code': Code of the exam this block relates to.
    exam_code VARCHAR(50) NOT NULL,
    
    -- 'block_index': Sequential height block index in the examination blockchain ledger.
    block_index INT NOT NULL,
    
    -- 'timestamp': Verification block time.
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- 'action': Operational milestone completed (e.g., 'Paper Created', 'Hash Generated', 'AES Encrypted', 'Dispatched', 'Arrived', 'Verified').
    action VARCHAR(100) NOT NULL,
    
    -- 'previous_hash': Hash block identifier of the parent link block in the chain.
    previous_hash VARCHAR(64) NOT NULL,
    
    -- 'block_hash': SHA-256 digital signature hash validating this block log integrity.
    block_hash VARCHAR(64) NOT NULL,
    
    -- 'operator': Identity ID of the government officer executing this operation block.
    operator VARCHAR(100) NOT NULL,
    
    -- 'status': Audit validation status (e.g. 'Success', 'Alerted', 'Failed').
    status VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Seed mock data for National Dashboard statistics and visual charts
-- Insert mock exams
INSERT INTO exams (exam_code, exam_name, authority, total_questions, exam_date, exam_time, exam_type, state_ut, security_score, status)
VALUES 
('EXM-2026-001', 'UPSC Civil Services Prelims', 'UPSC', 100, '2026-06-15', '09:30:00', 'Competitive', 'Delhi', 98, 'Created'),
('EXM-2026-002', 'SSC CGL Tier 1', 'SSC', 100, '2026-06-18', '14:00:00', 'Competitive', 'Maharashtra', 94, 'In Transit'),
('EXM-2026-003', 'JEE Main Session 1', 'NTA', 90, '2026-06-20', '09:00:00', 'Competitive', 'Rajasthan', 82, 'Arrived'),
('EXM-2026-004', 'NEET UG 2026', 'NTA', 180, '2026-06-25', '14:00:00', 'Competitive', 'Tamil Nadu', 97, 'Verified'),
('EXM-2026-005', 'IBPS PO Prelims', 'IBPS', 100, '2026-07-02', '10:00:00', 'Competitive', 'Karnataka', 92, 'Created')
ON DUPLICATE KEY UPDATE exam_name=VALUES(exam_name);

-- Insert mock centers in major areas for map visualization
INSERT INTO centers (name, city, latitude, longitude, integrity_score, status)
VALUES 
('Mumbai Central Academy', 'Mumbai', 19.0760, 72.8777, 98, 'Online'),
('Navi Mumbai Technical High School', 'Navi Mumbai', 19.0330, 73.0297, 91, 'Online'),
('Thane Public School Center 3', 'Thane', 19.2183, 72.9781, 76, 'Online'),
('Pune University Campus Hall 2', 'Pune', 18.5204, 73.8567, 96, 'Online'),
('Delhi National Trust Academy', 'Delhi', 28.7041, 77.1025, 88, 'Online')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- Insert mock blockchain timeline entries
INSERT INTO blockchain_logs (exam_code, block_index, timestamp, action, previous_hash, block_hash, operator, status)
VALUES
('EXM-2026-004', 0, '2026-07-25 10:00:00', 'Paper Created', '0000000000000000000000000000000000000000000000000000000000000000', '8ca4a58b97d26456fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7cc0', 'officer@examshield.gov.in', 'Success'),
('EXM-2026-004', 1, '2026-07-25 10:15:00', 'Hash Generated', '8ca4a58b97d26456fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7cc0', '4fc5d8091ecb5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e987654a', 'officer@examshield.gov.in', 'Success'),
('EXM-2026-004', 2, '2026-07-25 10:30:00', 'AES Encrypted', '4fc5d8091ecb5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e987654a', '6e6f9de5d078c5d9541eba2dacb1f64153fa4fe3185229142e1f9d260e99876f', 'officer@examshield.gov.in', 'Success'),
('EXM-2026-002', 0, '2026-07-25 11:20:00', 'Paper Created', '0000000000000000000000000000000000000000000000000000000000000000', 'd7a8fbb307d7cf56fa38b247f2db8323ff144f6ed47f390e9c3dff5d972b7bb1', 'officer@examshield.gov.in', 'Success')
ON DUPLICATE KEY UPDATE block_hash=VALUES(block_hash);

-- 8. Create the 'tracking_logs' table to store geographic transit logs
CREATE TABLE IF NOT EXISTS tracking_logs (
    -- 'id': Unique tracking log primary key.
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- 'exam_code': Links this log point to the corresponding examination.
    exam_code VARCHAR(50) NOT NULL,
    
    -- 'status': Status milestone at this coordinate point (e.g. 'Vault Dispatch', 'In Transit', 'Center Receipt').
    status VARCHAR(100) NOT NULL,
    
    -- 'location_name': Display name of this physical route landmark.
    location_name VARCHAR(150) NOT NULL,
    
    -- 'latitude': GPS latitude coordinate of this tracking milestone.
    latitude DECIMAL(10, 8) NOT NULL,
    
    -- 'longitude': GPS longitude coordinate of this tracking milestone.
    longitude DECIMAL(11, 8) NOT NULL,
    
    -- 'updated_at': Timestamp of coordinate entry.
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- 'updated_by': Officer identifier who authorized or scanned at this point.
    updated_by VARCHAR(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Seed mock transit route coordinates for tracking visualization
INSERT INTO tracking_logs (exam_code, status, location_name, latitude, longitude, updated_by)
VALUES
('EXM-2026-002', 'Vault Dispatch', 'Central Printing Vault, Pune', 18.52040000, 73.85670000, 'officer@examshield.gov.in'),
('EXM-2026-002', 'In Transit Stopover', 'Lonavala Expressway Security Outpost', 18.75570000, 73.40910000, 'officer@examshield.gov.in'),
('EXM-2026-002', 'In Transit - Current', 'Navi Mumbai Highway Toll Plaza', 19.03300000, 73.02970000, 'officer@examshield.gov.in'),
('EXM-2026-002', 'Destination Center', 'Thane Public School Center 3', 19.21830000, 72.97810000, 'officer@examshield.gov.in'),

('EXM-2026-004', 'Vault Dispatch', 'Delhi Central Security Vault', 28.70410000, 77.10250000, 'officer@examshield.gov.in'),
('EXM-2026-004', 'Center Receipt - Verified', 'Delhi National Trust Academy (Exam Center)', 28.63040000, 77.21770000, 'officer@examshield.gov.in'),

('EXM-2026-001', 'Vault Dispatch', 'Delhi Central Security Vault', 28.70410000, 77.10250000, 'officer@examshield.gov.in'),
('EXM-2026-001', 'In Transit Stopover', 'Ring Road Security Outpost 4', 28.67000000, 77.15000000, 'officer@examshield.gov.in'),
('EXM-2026-001', 'In Transit Stopover', 'ITO Security Check Gate', 28.63000000, 77.24000000, 'officer@examshield.gov.in'),
('EXM-2026-001', 'In Transit Stopover', 'Connaught Place Security Corridor', 28.63150000, 77.21670000, 'officer@examshield.gov.in'),
('EXM-2026-001', 'Center Receipt - Verified', 'Delhi National Trust Academy (Exam Center)', 28.63040000, 77.21770000, 'officer@examshield.gov.in')
ON DUPLICATE KEY UPDATE location_name=VALUES(location_name);
