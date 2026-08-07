
#==============================================================================
# EXAMSHIELD - SECURE EXAMINATION MANAGEMENT SYSTEM
# ==============================================================================
# Main Backend Application (Flask + MySQL)
# This module implements:
# - Secure login validation using MySQL
# - Simulated 2FA verification with terminal console OTP printing
# - Simulated biometric login
# - Session management, permanent session tracking (Remember Me), and logout
# - Secure dashboard redirection

import random
import string
import hashlib
import os
import re
import secrets
import bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, jsonify
import mysql.connector
#import google.generativeai as genai
from pypdf import PdfReader

import json

from dotenv import load_dotenv

load_dotenv()
print("SMTP USER:", os.getenv("SMTP_USER"))
print("SMTP PASS EXISTS:", bool(os.getenv("SMTP_PASS")))
print("GEMINI KEY EXISTS:", bool(os.getenv("GEMINI_API_KEY")))

# 1. INITIALIZE FLASK APP
app = Flask(__name__)




# Secret key is required to encrypt and secure client-side cookies and session data.
# In production, this should be a random secure string loaded from environment variables.


# 2. DATABASE CONFIGURATION
# We configure database connection parameters for MySQL.
# Host: 'localhost' or '127.0.0.1'
# User: 'root'
# Password: 'root'
# Database: 'examshield'
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'root',
    'database': 'examshield',
    'autocommit': True
}

# SMTP configurations for secure email OTP delivery
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Your Gmail
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

print("SMTP PASSWORD LOADED:", bool(SMTP_PASS))
# Flask session security key
app.secret_key = os.getenv(
    "SECRET_KEY",
    "examshield_super_secure_key_2026"
)
app.config['SESSION_PERMANENT'] = False




SMTP_FROM = "EXAMSHIELD Secure Access <alkavarak17@gmail.com>"

# ==========================
# GEMINI AI CONFIGURATION
# ==========================

import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

genai.configure(
    api_key=GEMINI_API_KEY
)
model = genai.GenerativeModel("gemini-1.5-flash")

def test_gemini():
    response = model.generate_content(
        "Analyze this exam paper security risk"
    )
    return response.text

def get_db_connection():
    """
    Why it is needed:
        Establishes and returns a connection to the MySQL database.
        Having a dedicated connection helper avoids open connection leaks and
        ensures standard configuration is used for every SQL request.
    Input:
        None
    Output:
        mysql.connector.connection_cext.CMySQLConnection: An active database connection object.
    """
    return mysql.connector.connect(**db_config)


# 3. HELPER FUNCTIONS

def generate_otp():
    """
    Why it is needed:
        Generates a secure 6-digit numeric verification code (OTP) for
        Two-Factor Authentication (2FA).
    Input:
        None
    Output:
        str: A 6-character numeric string (e.g., '582910').
    """
    return "".join(random.choices(string.digits, k=6))


def time_ago(dt):
    """
    Why it is needed:
        Calculates the relative time difference (e.g. '5min ago', '3h ago')
        between a past datetime value and the current system time. This
        provides a polished, real-life timeline appearance on dashboard activity feeds.
    Input:
        datetime.datetime: The past timestamp to compare.
    Output:
        str: A human-readable relative time string.
    """
    if not dt:
        return "--"
    diff = datetime.now() - dt
    if diff.days > 0:
        return f"{diff.days}d ago"
    seconds = diff.seconds
    hours = seconds // 3600
    if hours > 0:
        return f"{hours}h ago"
    minutes = (seconds % 3600) // 60
    if minutes > 0:
        return f"{minutes}min ago"
    return "just now"


def validate_password_strength(password):
    """
    Enforces strong password rules matching government portal specifications.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is secure."


def send_otp_email(recipient_email, officer_name, otp):
    """
    Sends a 2FA or Password Reset OTP email. Logs fallback info to console if SMTP offline.
    """
    subject = "EXAMSHIELD Login Verification OTP"
    body = f"""Government of India
EXAMSHIELD Secure Access Portal

Dear {officer_name},

Your One-Time Password is:

{otp}

This OTP is valid for 5 minutes.

Do not share this OTP."""

    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_FROM
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    # Log clearly in console for easy debugging and fallback retrieval
    print("\n" + "="*60, flush=True)
    print(f"[SECURITY INFO] OTP generated for {recipient_email}: {otp}", flush=True)
    print("="*60 + "\n", flush=True)
    
    # Write OTP to a local file in workspace to bypass stdout buffering for developers
    try:
        bypass_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'otp_bypass.txt')
        with open(bypass_path, 'w') as f:
            f.write(otp)
    except Exception as e:
        print(f"[SECURITY ERROR] Failed to write OTP bypass file: {e}", flush=True)
    
    try:
        if not SMTP_SERVER:
            return False, "SMTP server not configured."

        import smtplib

        server = smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=10
        )

        server.starttls()

        server.login(
            SMTP_USER,
            SMTP_PASS
        )

        server.send_message(msg)

        return True, "Email sent successfully."

    except Exception as e:
        return False, f"SMTP delivery failed: {e}"

    finally:
        try:
            server.quit()
        except:
            pass
            
        


# 4. SECURITY & SESSION MIDDLEWARE

@app.before_request
def check_remember_me():
    """
    Middleware executing before request handling to parse remember_token cookies
    and restore inactive logins securely from the database.
    """
    if not session.get('logged_in'):
        token = request.cookies.get('remember_token')
        if token:
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT u.* FROM users u
                    JOIN remember_tokens r ON u.id = r.user_id
                    WHERE r.token = %s AND r.expiry_date > %s AND u.status = 'Active'
                    LIMIT 1
                """, (token, datetime.now()))
                user = cursor.fetchone()
                
                if user:
                    session['logged_in'] = True
                    session['user_id'] = user['id']
                    session['government_id'] = user['government_id']
                    session['name'] = user['officer_name']
                    session['role'] = user['role']
                    flash("Welcome back! Authenticated securely via Remember Me.", "success")
            except Exception as e:
                print(f"[SECURITY ERROR] Auto-login token validation failure: {e}")
            finally:
                if conn:
                    conn.close()

# 5. CONTROLLER & ROUTES

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Serves login page (GET) and validates credentials against users database (POST).
    Supports dynamic email login/signup by auto-creating profiles for new email addresses.
    """
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        gov_id = request.form.get('government_id')
        password = request.form.get('password')
        remember = request.form.get('remember')

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Query by Government ID or Email
            cursor.execute("""
            SELECT *
            FROM users
            WHERE
            (government_id=%s OR email=%s)
            AND status='Active'
            """,(gov_id,gov_id))
            user = cursor.fetchone()
            
            # Signup/Seeding Bypass: Auto-create user profile if they enter a new valid email address
            if not user and re.match(r"[^@]+@[^@]+\.[^@]+", gov_id):
                # Dynamically register the email with default password "SecurePassword123"
                hashed_pw = bcrypt.hashpw("SecurePassword123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                username = gov_id.split('@')[0].capitalize()
                
                cursor.execute("""
                    INSERT INTO users (government_id, officer_name, email, phone, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (gov_id, f"Officer {username}", gov_id, '+919999999999', hashed_pw, 'Officer', 'Active'))
                conn.commit()
                
                # Retrieve the dynamically created user record
                cursor.execute("SELECT * FROM users WHERE government_id = %s", (gov_id,))
                user = cursor.fetchone()
                print(f"[SECURITY INFO] Dynamically seeded new test user profile for: {gov_id}")
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['temp_user_id'] = user['id']
                session['temp_user_gov_id'] = user['government_id']
                session['temp_user_name'] = user['officer_name']
                session['temp_user_role'] = user['role']
                session['temp_user_remember'] = bool(remember)
                
                otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=5)
                
                # Secure Hashing: store SHA-256 hash of OTP
                otp_hash = hashlib.sha256(otp.encode('utf-8')).hexdigest()
                
                cursor.execute("""
                    INSERT INTO otp (user_id, otp_hash, expiry_time, attempts, verified)
                    VALUES (%s, %s, %s, 0, 0)
                """, (user['id'], otp_hash, expiry))
                conn.commit()
                
                # Send OTP dynamically to user's email address
                success, email_msg = send_otp_email(user['email'], user['officer_name'], otp)
                
                if success:
                    flash("Verification code sent to registered official email.", "success")
                else:
                    flash("Email delivery offline. OTP printed to server terminal for verification.", "info")
                    
                return redirect(url_for('verify'))
            else:
                flash("Invalid Government ID or Password", "error")
                
        except Exception as err:
            import traceback
            traceback.print_exc()
            print("Dashboard Error:", err)

            flash(f"Dashboard Error: {err}", "error")

            return render_template(
                'dashboard.html',
                total_exams=0,
                in_progress_exams=0,
                total_centers=0,
                online_percent=100.0,
                avg_integrity_score=100.0,
                total_alerts=0,
                critical_alerts=0,
                centers_data=[],
                recent_activities=[]
            )
            flash(f"Database Server Connection Error: {err}", "error")
        finally:
            if conn:
                conn.close()

    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """
    Serves verification page (GET) and validates 2FA OTP code against database (POST).
    Enforces security attempt limits and expiration rules.
    """
    if 'temp_user_id' not in session:
        flash("Authorization Flow Violation: Validate credentials first.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        temp_id = session.get('temp_user_id')
        remember = session.get('temp_user_remember')

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Fetch latest active OTP
            cursor.execute("""
                SELECT * FROM otp 
                WHERE user_id = %s AND verified = 0
                ORDER BY created_time DESC LIMIT 1
            """, (temp_id,))
            otp_record = cursor.fetchone()
            
            if otp_record:
                # 1. Check if OTP is locked/invalidated
                if otp_record['attempts'] >= 3 or otp_record['verified'] == -1:
                    flash("Maximum verification attempts exceeded. Please request a new OTP.", "error")
                    return redirect(url_for('verify'))
                    
                # 2. Check if OTP is expired (5 mins)
                if datetime.now() > otp_record['expiry_time']:
                    flash("OTP expired. Please request a new OTP.", "error")
                    return redirect(url_for('verify'))
                
                # Compute SHA-256 hash of submitted OTP
                user_hash = hashlib.sha256(user_otp.encode('utf-8')).hexdigest()
                
                # 3. Verify match
                if user_hash == otp_record['otp_hash']:
                    # Successful verification
                    cursor.execute("UPDATE otp SET verified = 1 WHERE id = %s", (otp_record['id'],))
                    
                    session['logged_in'] = True
                    session['user_id'] = temp_id
                    session['government_id'] = session.get('temp_user_gov_id')
                    session['name'] = session.get('temp_user_name')
                    session['role'] = session.get('temp_user_role')
                    
                    response = make_response(redirect(url_for('dashboard')))
                    
                    if False:
                        token = secrets.token_hex(32)
                        expiry = datetime.now() + timedelta(days=30)
                        cursor.execute("""
                            INSERT INTO remember_tokens (user_id, token, expiry_date)
                            VALUES (%s, %s, %s)
                        """, (temp_id, token, expiry))
                        response.set_cookie('remember_token', token, max_age=30*24*60*60, httponly=True, samesite='Lax',secure=True)
                    
                    session.pop('temp_user_id', None)
                    session.pop('temp_user_gov_id', None)
                    session.pop('temp_user_name', None)
                    session.pop('temp_user_role', None)
                    session.pop('temp_user_remember', None)
                    
                    conn.commit()
                    flash(f"Welcome Back, {session['name']}. Identity Verified.", "success")
                    return response
                else:
                    # Incorrect OTP attempt: increment attempts
                    new_attempts = otp_record['attempts'] + 1
                    if new_attempts >= 3:
                        # Lock/Invalidate OTP
                        cursor.execute("UPDATE otp SET attempts = %s, verified = -1 WHERE id = %s", (new_attempts, otp_record['id']))
                        conn.commit()
                        flash("Maximum verification attempts exceeded. Please request a new OTP.", "error")
                    else:
                        cursor.execute("UPDATE otp SET attempts = %s WHERE id = %s", (new_attempts, otp_record['id']))
                        conn.commit()
                        flash(f"Invalid OTP. {3 - new_attempts} attempts remaining.", "error")
                        
                    return redirect(url_for('verify'))
            else:
                flash("Invalid OTP session. Please request a new OTP.", "error")
                return redirect(url_for('verify'))
                
        except mysql.connector.Error as err:
            flash(f"Database error during verification: {err}", "error")
        finally:
            if conn:
                conn.close()

    # Renders dedicated otp_verification.html page
    return render_template('otp_verification.html')


@app.route("/verify/<exam_code>")
def verify_exam(exam_code):

    cursor = mysql.connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM exams WHERE exam_code=%s",
        (exam_code,)
    )

    exam = cursor.fetchone()

    cursor.close()

    if exam:
        return render_template("verify.html", exam=exam)

    return "Exam not found"
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """
    Endpoint called from verification screen to generate, save, and send a new OTP.
    Enforces a 30-second cooldown block.
    """
    temp_id = session.get('temp_user_id')
    if not temp_id:
        return jsonify({'status': 'error', 'message': 'Session expired. Please log in again.'}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Load user details
        cursor.execute("SELECT * FROM users WHERE id = %s AND status = 'Active'", (temp_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'status': 'error', 'message': 'User record not found.'}), 404
            
        # Cooldown check: verify difference between latest OTP generated and now
        cursor.execute("SELECT created_time FROM otp WHERE user_id = %s ORDER BY id DESC LIMIT 1", (temp_id,))
        last_otp = cursor.fetchone()
        
        if last_otp:
            time_diff = datetime.now() - last_otp['created_time']
            if time_diff.total_seconds() < 30:
                return jsonify({
                    'status': 'error', 
                    'message': f"Please wait {int(30 - time_diff.total_seconds())} seconds before requesting a new OTP."
                }), 429
                
        # Invalidate previous unverified OTPs
        cursor.execute("UPDATE otp SET verified = -1 WHERE user_id = %s AND verified = 0", (temp_id,))
            
        otp = generate_otp()
        expiry = datetime.now() + timedelta(minutes=5)
        otp_hash = hashlib.sha256(otp.encode('utf-8')).hexdigest()
        
        cursor.execute("""
            INSERT INTO otp (user_id, otp_hash, expiry_time, attempts, verified)
            VALUES (%s, %s, %s, 0, 0)
        """, (user['id'], otp_hash, expiry))
        conn.commit()
        
        success, email_msg = send_otp_email(user['email'], user['officer_name'], otp)
        
        msg = "New OTP sent to registered email address."
        if not success:
            msg += f" (Developer Bypass: OTP is {otp})"
            
        return jsonify({
            'status': 'success',
            'message': msg
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Database failure: {e}"}), 500
    finally:
        if conn:
            conn.close()


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """
    Dedicated forgot password handler managing OTP generation (Step 1) and validation / reset (Step 2).
    """
    if request.method == 'POST':
        step = request.form.get('step')
        
        if step == '1':
            gov_id = request.form.get('government_id')
            if not gov_id:
                flash("Government ID / Email is required.", "error")
                return render_template('forgot_password.html', step=1)
                
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)
                
                # Check user exists
                cursor.execute("SELECT * FROM users WHERE government_id = %s OR email = %s AND status = 'Active'", (gov_id, gov_id))
                user = cursor.fetchone()
                
                if not user:
                    flash("Government ID or Email not recognized in database.", "error")
                    return render_template('forgot_password.html', step=1)
                    
                otp = generate_otp()
                expiry = datetime.now() + timedelta(minutes=5)
                otp_hash = hashlib.sha256(otp.encode('utf-8')).hexdigest()
                
                # Invalidate previous unverified OTPs
                cursor.execute("UPDATE otp SET verified = -1 WHERE user_id = %s AND verified = 0", (user['id'],))
                
                cursor.execute("""
                    INSERT INTO otp (user_id, otp_hash, expiry_time, attempts, verified)
                    VALUES (%s, %s, %s, 0, 0)
                """, (user['id'], otp_hash, expiry))
                conn.commit()
                
                success, email_msg = send_otp_email(user['email'], user['officer_name'], otp)
                
                parts = user['email'].split('@')
                email_prefix = parts[0]
                email_domain = parts[1]
                masked_prefix = email_prefix[0] + "*" * (len(email_prefix) - 2) + email_prefix[-1] if len(email_prefix) > 2 else email_prefix[0] + "*"
                masked_email = f"{masked_prefix}@{email_domain}"
                
                msg = f"OTP code has been dispatched to: {masked_email}."
                if not success:
                    msg += f" (Developer Bypass: OTP is {otp})"
                    
                flash(msg, "success")
                return render_template('forgot_password.html', step=2, government_id=user['government_id'])
            except Exception as e:
                flash(f"Database error: {e}", "error")
                return render_template('forgot_password.html', step=1)
            finally:
                if conn:
                    conn.close()
                    
        elif step == '2':
            gov_id = request.form.get('government_id')
            otp_code = request.form.get('otp')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not gov_id or not otp_code or not new_password or not confirm_password:
                flash("All reset password fields are required.", "error")
                return render_template('forgot_password.html', step=2, government_id=gov_id)
                
            is_valid, pw_msg = validate_password_strength(new_password)
            if not is_valid:
                flash(pw_msg, "error")
                return render_template('forgot_password.html', step=2, government_id=gov_id)
                
            if new_password != confirm_password:
                flash("Confirm password mismatch.", "error")
                return render_template('forgot_password.html', step=2, government_id=gov_id)
                
            conn = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)
                
                cursor.execute("SELECT * FROM users WHERE government_id = %s AND status = 'Active'", (gov_id,))
                user = cursor.fetchone()
                
                if not user:
                    flash("User record not found.", "error")
                    return redirect(url_for('forgot_password'))
                    
                # Fetch latest OTP
                cursor.execute("""
                    SELECT * FROM otp 
                    WHERE user_id = %s AND verified = 0
                    ORDER BY created_time DESC LIMIT 1
                """, (user['id'],))
                otp_record = cursor.fetchone()
                
                if not otp_record:
                    flash("Invalid OTP session. Please request a new reset code.", "error")
                    return render_template('forgot_password.html', step=1)
                    
                # Check locks
                if otp_record['attempts'] >= 3 or otp_record['verified'] == -1:
                    flash("Maximum verification attempts exceeded. Please request a new OTP.", "error")
                    return render_template('forgot_password.html', step=1)
                    
                # Check expiry
                if datetime.now() > otp_record['expiry_time']:
                    flash("OTP expired. Please request a new OTP.", "error")
                    return render_template('forgot_password.html', step=1)
                    
                # Verify match
                user_hash = hashlib.sha256(otp_code.encode('utf-8')).hexdigest()
                if user_hash == otp_record['otp_hash']:
                    cursor.execute("UPDATE otp SET verified = 1 WHERE id = %s", (otp_record['id'],))
                    
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, user['id']))
                    conn.commit()
                    
                    flash("Password reset successful. Please log in with your new credentials.", "success")
                    return redirect(url_for('login'))
                else:
                    new_attempts = otp_record['attempts'] + 1
                    if new_attempts >= 3:
                        cursor.execute("UPDATE otp SET attempts = %s, verified = -1 WHERE id = %s", (new_attempts, otp_record['id']))
                        conn.commit()
                        flash("Maximum verification attempts exceeded. Please request a new OTP.", "error")
                        return render_template('forgot_password.html', step=1)
                    else:
                        cursor.execute("UPDATE otp SET attempts = %s WHERE id = %s", (new_attempts, otp_record['id']))
                        conn.commit()
                        flash(f"Invalid OTP. {3 - new_attempts} attempts remaining.", "error")
                        return render_template('forgot_password.html', step=2, government_id=gov_id)
            except Exception as e:
                flash(f"Database reset error: {e}", "error")
                return render_template('forgot_password.html', step=2, government_id=gov_id)
            finally:
                if conn:
                    conn.close()
                    
    # GET request: default step 1
    return render_template('forgot_password.html', step=1)


@app.route('/biometric-login', methods=['POST'])
def biometric_login():
    """
    Authenticates user directly using their government ID if biometric verification succeeds.
    """
    gov_id = request.form.get('government_id', 'officer@examshield.gov.in')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE government_id = %s AND status = 'Active' LIMIT 1", (gov_id,))
        user = cursor.fetchone()
        
        if user:
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['government_id'] = user['government_id']
            session['name'] = user['officer_name']
            session['role'] = user['role']
            
            session.pop('temp_user_id', None)
            session.pop('2fa_otp', None)
            
            print(f"\n[SECURITY CONTROL] Biometric login signature validated for {user['government_id']}.\n")
            flash("Biometric identity verified successfully. Access granted.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Biometric Login Failed: Officer account not found in database.", "error")
            
    except mysql.connector.Error as err:
        flash(f"Database error during biometric login: {err}", "error")
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """
    Why it is needed:
        Serves the main ExamShield National Dashboard page.
        Enforces route protection, queries MySQL for live statistics, packages
        active center coordinates into JSON for the Leaflet mapping component,
        and retrieves recent SecureChain logs for the live audit timeline.
    Input:
        None
    Output:
        Renders templates/dashboard.html if session['logged_in'] is True,
        otherwise redirects to login page.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to access the secure dashboard.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch total examinations count
        cursor.execute("SELECT COUNT(*) AS total FROM exams")
        total_exams = cursor.fetchone()['total']
        
        # 2. Fetch in-progress examinations (status is not Created or Verified)
        cursor.execute("SELECT COUNT(*) AS total FROM exams WHERE status IN ('Uploaded', 'Scanned', 'Encrypted', 'Dispatched', 'In Transit')")
        in_progress_exams = cursor.fetchone()['total']
        
        # 3. Fetch active centers count
        cursor.execute("""
        SELECT COUNT(DISTINCT c.id) AS total
        FROM centers c
        JOIN tracking_logs t
        ON c.name = t.location_name
        JOIN exams e
        ON t.exam_code = e.exam_code
        WHERE e.status IN (
        'Uploaded',
        'Scanned',
        'Encrypted',
        'Dispatched',
        'In Transit'
        )
        """)

        result = cursor.fetchone()

        total_centers = result['total'] if result['total'] else 0
        
        # 4. Fetch online centers response rate
        cursor.execute("""
        SELECT COUNT(DISTINCT c.id) AS total
        FROM centers c
        JOIN tracking_logs t
        ON c.name = t.location_name
        JOIN exams e
        ON t.exam_code = e.exam_code
        WHERE
        c.status='Online'
        AND e.status IN (
        'Uploaded',
        'Scanned',
        'Encrypted',
        'Dispatched',
        'In Transit'
        )
        """)

        online_centers = cursor.fetchone()['total']
        
        online_percent = round((online_centers / total_centers * 100), 1) if total_centers > 0 else 100.0
        
        # 5. Fetch overall system integrity score (average of all centers)
        cursor.execute("SELECT AVG(integrity_score) AS avg_score FROM centers")
        avg_score = cursor.fetchone()['avg_score']
        avg_integrity_score = round(float(avg_score), 1) if avg_score is not None else 100.0
        
        # 6. Fetch live anomaly alerts (integrity score < 80)
        cursor.execute("""
        SELECT COUNT(*) AS total
        FROM centers c
        JOIN exams e
        ON c.exam_code = e.exam_code
        WHERE
        c.integrity_score < 80
        AND e.status IN (
            'Uploaded',
            'Scanned',
            'Encrypted',
            'Dispatched',
            'In Transit'
        )
        """)

        total_alerts = cursor.fetchone()['total']
        
        # 7. Fetch critical anomaly flags (integrity score < 70)
        cursor.execute("SELECT COUNT(*) AS total FROM centers WHERE integrity_score < 70")
        critical_alerts = cursor.fetchone()['total']
        
        # 8. Fetch center coordinate details for Leaflet map markers
        cursor.execute("""
        SELECT
            c.name,
            c.city,
            c.latitude,
            c.longitude,
            c.integrity_score,
            c.status
        FROM centers c
        """)
            
        centers = cursor.fetchall()
        # Convert decimal coordinates to floats so they are JSON-serializable
        centers_data = []
        for c in centers:
            centers_data.append({
                'name': c['name'],
                'city': c['city'],
                'lat': float(c['latitude']),
                'lng': float(c['longitude']),
                'score': c['integrity_score'],
                'status': c['status']
            })
            
        # 9. Fetch recent SecureChain blockchain logs for timeline activity feed
        cursor.execute("SELECT exam_code, action, timestamp, operator, status FROM blockchain_logs ORDER BY timestamp DESC LIMIT 6")
        logs = cursor.fetchall()
        
        recent_activities = []
        for l in logs:
            recent_activities.append({
                'exam_code': l['exam_code'],
                'action': l['action'],
                'operator': l['operator'],
                'time_ago': time_ago(l['timestamp'])
            })
            
        cursor.close()
        conn.close()
        
        return render_template(
            'dashboard.html',
            total_exams=total_exams,
            in_progress_exams=in_progress_exams,
            total_centers=total_centers,
            online_percent=online_percent,
            avg_integrity_score=avg_integrity_score,
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            centers_data=centers_data,
            recent_activities=recent_activities
        )
        
    except mysql.connector.Error as err:
        flash(f"Database statistics fetch error: {err}", "error")
        # Fall back to empty dashboard data if DB query fails during developer updates
        return render_template(
            'dashboard.html',
            total_exams=0,
            in_progress_exams=0,
            total_centers=0,
            online_percent=100.0,
            avg_integrity_score=100.0,
            total_alerts=0,
            critical_alerts=0,
            centers_data=[],
            recent_activities=[]
        )


@app.route('/tracking')
def tracking():
    """
    Why it is needed:
        Serves the SmartTrace GPS Paper Tracking page.
        Allows officers to search for an exam code, query its active route coordinate points,
        evaluate the vehicle's current position, and render the progress timeline.
    Input:
        Query Parameter:
        - exam_code (str): The code of the exam to track (optional, defaults to first active).
    Output:
        Renders templates/paper_tracking.html with route arrays, active list, and telemetry details.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to access the secure tracking console.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch all examinations in dispatch chain to populate dropdown search list
        cursor.execute("SELECT exam_code, exam_name, status FROM exams ORDER BY id DESC")
        active_exams = cursor.fetchall()
        
        # 2. Get specific exam code from request query parameter, or default to the first active exam
        selected_code = request.args.get('exam_code')
        if not selected_code and active_exams:
            selected_code = active_exams[0]['exam_code']
            
        exam = None
        transit_points = []
        route_data = []
        
        if selected_code:
            # 3. Retrieve exam details
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (selected_code,))
            exam = cursor.fetchone()
            
            if exam:
                # 4. Fetch transit coordinate records
                cursor.execute("SELECT status, location_name, latitude, longitude, updated_at, updated_by FROM tracking_logs WHERE exam_code = %s ORDER BY id ASC", (selected_code,))
                logs = cursor.fetchall()
                
                print("Selected Exam:", selected_code)
                print("Logs:", logs)
                print("Number of logs:", len(logs))
                
                # Determine current transit stop index
                current_idx = -1
                for i, log in enumerate(logs):
                    if 'current' in log['status'].lower():
                        current_idx = i
                        break
                        
                if current_idx == -1 and logs:
                    if exam['status'] in ('Arrived', 'Verified'):
                        current_idx = len(logs) - 1
                    else:
                        current_idx = 0

                # Calculate route completion
                progress_percent = 0

                if logs:
                    if exam['status'] in ('Arrived', 'Verified'):
                        progress_percent = 100
                    else:
                        progress_percent = round(
                            ((current_idx + 1) / len(logs)) * 100
                        )

                estimated_remaining = max(0, 100 - progress_percent)
                
                # Format coordinates and timeline nodes
                for i, log in enumerate(logs):
                    state = 'pending'
                    if i < current_idx:
                        state = 'completed'
                    elif i == current_idx:
                        state = 'current'
                        if i == len(logs) - 1 and exam['status'] in ('Arrived', 'Verified'):
                            state = 'completed'
                            
                    transit_points.append({
                        'status': log['status'],
                        'location_name': log['location_name'],
                        'lat': float(log['latitude']),
                        'lng': float(log['longitude']),
                        'time': log['updated_at'].strftime('%d %b, %H:%M'),
                        'operator': log['updated_by'],
                        'state': state
                    })
                    
                    route_data.append({
                        'lat': float(log['latitude']),
                        'lng': float(log['longitude']),
                        'status': log['status'],
                        'location_name': log['location_name']
                    })
                    
        cursor.close()
        conn.close()
        
        print("Route Data =", route_data)
        print("Transit Points =", transit_points)
        
        return render_template(
            'paper_tracking.html',
            active_exams=active_exams,
            exam=exam,
            transit_points=transit_points,
            route_data=route_data,
            progress_percent=progress_percent,
            estimated_remaining=estimated_remaining
    )
        
    except mysql.connector.Error as err:
        flash(f"Database error during tracking sync: {err}", "error")
        return render_template(
            'paper_tracking.html',
            active_exams=[],
            exam=None,
            transit_points=[],
            route_data=[],
            progress_percent=0,
            estimated_remaining=100
)


@app.route('/create_exam', methods=['GET', 'POST'])
def create_exam():
    """
    Create a new examination.

    GET:
        Displays the Create Examination page with an automatically
        suggested exam code.

    POST:
        Validates the exam details, inserts the examination into MySQL,
        creates a notification, optionally creates the SecureChain
        genesis block, and redirects to the next step.
    """

    # ==========================================
    # ROUTE PROTECTION
    # ==========================================

    if not session.get('logged_in'):
        flash(
            "Security Shield: Please log in to schedule a new examination.",
            "error"
        )
        return redirect(url_for('login'))

    conn = None

    try:

        # ==========================================
        # DATABASE CONNECTION
        # ==========================================

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # ==========================================
        # POST REQUEST - CREATE EXAM
        # ==========================================

        if request.method == 'POST':

            # --------------------------------------
            # Extract form values
            # --------------------------------------

            exam_name = request.form.get('exam_name')
            authority = request.form.get('authority')
            exam_code = request.form.get('exam_code')

            total_questions = int(
                request.form.get('total_questions', 100)
            )

            exam_date = request.form.get('exam_date')
            exam_time = request.form.get('exam_time')
            exam_type = request.form.get('exam_type')
            state_ut = request.form.get('state_ut')

            # --------------------------------------
            # Security configuration
            # --------------------------------------

            security_aes = (
                1 if request.form.get('security_aes') else 0
            )

            security_ai = (
                1 if request.form.get('security_ai') else 0
            )

            security_blockchain = (
                1 if request.form.get('security_blockchain') else 0
            )

            security_qr = (
                1 if request.form.get('security_qr') else 0
            )

            # --------------------------------------
            # Additional settings
            # --------------------------------------

            total_marks = int(
                request.form.get('total_marks', 100)
            )

            passing_marks = int(
                request.form.get('passing_marks', 35)
            )

            negative_marking = request.form.get(
                'negative_marking',
                'No'
            )

            duration = int(
                request.form.get('duration', 180)
            )

            action = request.form.get(
                'action',
                'continue'
            )

            # ==========================================
            # SERVER-SIDE VALIDATION
            # ==========================================

            # Required fields
            if not exam_name or not authority or not exam_code \
                    or not exam_date or not exam_time:

                flash(
                    "Please fill in all required fields.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Exam name
            if len(exam_name.strip()) < 3:

                flash(
                    "Exam name must contain at least 3 characters.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Authority
            if len(authority.strip()) < 3:

                flash(
                    "Authority name must contain at least 3 characters.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Exam code
            if not re.match(
                r"^EXM-\d{4}-\d{3}$",
                exam_code
            ):

                flash(
                    "Invalid Exam Code format. "
                    "Example: EXM-2026-001",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Total questions
            if total_questions <= 0:

                flash(
                    "Total questions must be greater than zero.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Total marks
            if total_marks <= 0:

                flash(
                    "Total marks must be greater than zero.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Passing marks
            if passing_marks < 0 \
                    or passing_marks > total_marks:

                flash(
                    "Passing marks cannot exceed total marks.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Duration
            if duration < 30 or duration > 600:

                flash(
                    "Exam duration must be between "
                    "30 and 600 minutes.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # Exam date
            exam_date_obj = datetime.strptime(
                exam_date,
                "%Y-%m-%d"
            ).date()

            if exam_date_obj < datetime.now().date():

                flash(
                    "Exam date cannot be in the past.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # ==========================================
            # CHECK DUPLICATE EXAM CODE
            # ==========================================

            cursor.execute(
                """
                SELECT id
                FROM exams
                WHERE exam_code = %s
                """,
                (exam_code,)
            )

            if cursor.fetchone():

                flash(
                    f"Conflict Error: Exam Code "
                    f"{exam_code} is already registered.",
                    "error"
                )

                return redirect(
                    url_for('create_exam')
                )

            # ==========================================
            # INSERT EXAM
            # ==========================================

            cursor.execute(
                """
                INSERT INTO exams (
                    exam_code,
                    exam_name,
                    authority,
                    total_questions,
                    exam_date,
                    exam_time,
                    exam_type,
                    state_ut,
                    total_marks,
                    passing_marks,
                    negative_marking,
                    duration,
                    security_aes,
                    security_ai,
                    security_blockchain,
                    security_qr,
                    security_face,
                    security_dual,
                    status
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    0, 0, 'Created'
                )
                """,
                (
                    exam_code,
                    exam_name,
                    authority,
                    total_questions,
                    exam_date,
                    exam_time,
                    exam_type,
                    state_ut,
                    total_marks,
                    passing_marks,
                    negative_marking,
                    duration,
                    security_aes,
                    security_ai,
                    security_blockchain,
                    security_qr
                )
            )

            # ==========================================
            # CREATE NOTIFICATION
            # ==========================================

            cursor.execute(
                """
                INSERT INTO notifications
                (
                    user_id,
                    title,
                    message,
                    notification_type
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    session['user_id'],
                    "Exam Created",
                    "New exam created successfully",
                    "exam"
                )
            )

            # ==========================================
            # SECURECHAIN GENESIS BLOCK
            # ==========================================

            if security_blockchain:

                # Check whether Block 0 already exists
                cursor.execute(
                    """
                    SELECT id
                    FROM blockchain_logs
                    WHERE exam_code = %s
                    AND block_index = 0
                    LIMIT 1
                    """,
                    (exam_code,)
                )

                existing_genesis = cursor.fetchone()

                # Create Block 0 only if it doesn't exist
                if not existing_genesis:

                    genesis_timestamp = datetime.now()

                    previous_hash = (
                        '0000000000000000000000000000000000000000000000000000000000000000'
                    )

                    # Data used to generate the SHA-256 hash
                    hash_payload = (
                        f"0:{exam_code}:Paper Created:"
                        f"{genesis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}:"
                        f"{previous_hash}"
                    )

                    genesis_hash = hashlib.sha256(
                        hash_payload.encode()
                    ).hexdigest()

                    cursor.execute(
                        """
                        INSERT INTO blockchain_logs
                        (
                            exam_code,
                            block_index,
                            timestamp,
                            action,
                            previous_hash,
                            block_hash,
                            operator,
                            status
                        )
                        VALUES (
                            %s, %s, %s, %s,
                            %s, %s, %s, %s
                        )
                        """,
                        (
                            exam_code,
                            0,
                            genesis_timestamp,
                            'Paper Created',
                            previous_hash,
                            genesis_hash,
                            session.get(
                                'government_id',
                                'officer@examshield.gov.in'
                            ),
                            'Success'
                        )
                    )

            # ==========================================
            # COMMIT EVERYTHING
            # ==========================================

            conn.commit()

            cursor.close()
            conn.close()

            # ==========================================
            # NEXT STEP
            # ==========================================

            if action == 'draft':

                flash(
                    "Examination draft registered "
                    "successfully in the system.",
                    "success"
                )

                return redirect(
                    url_for('dashboard')
                )

            else:

                flash(
                    "Examination registered successfully. "
                    "Please proceed to upload question papers.",
                    "success"
                )

                return redirect(
                    url_for(
                        'upload',
                        exam_code=exam_code
                    )
                )

        # ==========================================
        # GET REQUEST
        # ==========================================

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM exams
            """
        )

        total_exams = cursor.fetchone()['total']

        suggested_code = (
            f"EXM-2026-{total_exams + 1:03d}"
        )

        cursor.close()
        conn.close()

        return render_template(
            'create_exam.html',
            suggested_code=suggested_code
        )

    # ==========================================
    # DATABASE ERROR
    # ==========================================

    except mysql.connector.Error as err:

        if conn:
            conn.rollback()

        flash(
            f"Database error during exam registration: {err}",
            "error"
        )

        return render_template(
            'create_exam.html',
            suggested_code="EXM-2026-ERR"
        )

# ==========================================================
# EXAMSHIELD AI HELPER FUNCTIONS
# ==========================================================

ALLOWED_EXTENSIONS = {"pdf"}
MAX_FILE_SIZE = 15 * 1024 * 1024   # 15 MB


def allowed_file(filename):
    """
    Allow only PDF files.
    """
    return "." in filename and \
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_security_score(pdf_valid,
                             question_paper,
                             duplicate,
                             leak,
                             metadata_safe):
    score = 0

    if pdf_valid:
        score += 20

    if question_paper:
        score += 20

    if not duplicate:
        score += 20

    if not leak:
        score += 20

    if metadata_safe:
        score += 20

    return score


import re

def detect_question_paper(text):

    
    
    if not text:
        return False

    text = text.lower()

    if len(text.strip()) < 300:
            return False

    keywords = [
        "question",
        "marks",
        "section",
        "attempt",
        "candidate",
        "instructions",
        "maximum marks",
        "time",
        "subject",
        "semester",
        "part a",
        "part b",
        "roll number"
    ]

    score = 0

    for word in keywords:
        if word in text:
            score += 1

    pattern = r"(q\.?\s*\d+)|(\d+\.)"

    question_count = len(re.findall(pattern, text))

    if question_count >= 5:
        score += 5

    return score >= 8


def extract_pdf_text(path):

    text = ""

    try:

        reader = PdfReader(path)

        for page in reader.pages:

            page_text = page.extract_text()

            if page_text:
                text += page_text + "\n"

    except:

        pass

    return text


def get_pdf_metadata(path):

    try:

        reader = PdfReader(path)

        meta = reader.metadata

        return {
            "author": str(meta.author),
            "creator": str(meta.creator),
            "producer": str(meta.producer)
        }

    except:

        return {}
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    Why it is needed:
        Serves the paper upload dashboard (GET) and processes uploaded document packages (POST).
        Saves files securely, calculates dynamic SHA-256 hashes representing the Exam DNA,
        registers paths/hashes in MySQL, and logs blockchain sequence block transactions.
    Input:
        GET: exam_code query parameter (optional, defaults to first).
        POST: Form parameters containing exam_code and file binary package.
    Output:
        Renders templates/upload.html, or redirects to /security_scan on success.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to upload question papers.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            exam_code = request.form.get('exam_code')
            file = request.files.get('file')

            # Validate uploaded file
            if not file or file.filename == "":
                flash("Please select a PDF file.", "error")
                return redirect(url_for("upload", exam_code=exam_code))

            if not allowed_file(file.filename):
                flash("Only PDF files are allowed.", "error")
                return redirect(url_for("upload", exam_code=exam_code))

            if not exam_code or not file or file.filename == '':
                flash("Validation Error: Please select an exam and choose a file to upload.", "error")
                cursor.close()
                conn.close()
                return redirect(url_for('upload', exam_code=exam_code))

            # 1. Establish secure directory paths
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder, exist_ok=True)

            # 2. Read binary stream on-the-fly to calculate SHA-256 DNA fingerprint

            # File size validation
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)

            if file_size > MAX_FILE_SIZE:
                flash("File size exceeds 15 MB limit.", "error")
                return redirect(url_for("upload", exam_code=exam_code))
            
            file_data = file.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            file.seek(0) # reset file cursor for storage write

            # Check if this paper already exists
            cursor.execute("""
            SELECT exam_code
            FROM exams
            WHERE paper_hash=%s
            """, (sha256_hash,))

            existing = cursor.fetchone()

            if existing:
                flash(
                    f"🚨 Possible Paper Leak Detected! This paper already exists for Exam {existing['exam_code']}.",
                    "error"
                )
                cursor.close()
                conn.close()
                return redirect(url_for("upload", exam_code=exam_code))

            # 3. Write file copy locally using secure namespacing
            filename = secure_filename(file.filename)
            safe_filename = f"{exam_code}_{filename}"
            file_path = os.path.join(upload_folder, safe_filename)
            file.save(file_path)

            # Extract PDF text
            pdf_text = extract_pdf_text(file_path)

            # Reject empty or image-only PDF
            if len(pdf_text.strip()) < 100:

                if os.path.exists(file_path):
                    os.remove(file_path)

                cursor.close()
                conn.close()

                flash("Image-only or empty PDF detected. Please upload a valid question paper.", "error")

                return redirect(url_for("upload", exam_code=exam_code))

           # Verify it looks like a question paper
            is_question_paper = detect_question_paper(pdf_text)

            if not is_question_paper:

               if os.path.exists(file_path):
                os.remove(file_path)

                cursor.close()
                conn.close()

                flash("The uploaded PDF does not appear to be a valid question paper.", "error")

                return redirect(url_for("upload", exam_code=exam_code))

            # =====================================
            # Gemini AI Question Paper Verification
            # =====================================

            try:

                prompt = f"""
            You are an AI Exam Paper Validator.

            Read the document below and decide whether it is an actual examination question paper.

            Return ONLY one word.

            YES

            or

            NO

            Document:

            {pdf_text[:10000]}
            """

                response = model.generate_content(prompt)

                result = response.text.strip().upper()

                if result != "YES":

                    if os.path.exists(file_path):
                        os.remove(file_path)

                    cursor.close()
                    conn.close()

                    flash("Gemini AI rejected this PDF. It is not a valid examination question paper.", "error")

                    return redirect(url_for("upload", exam_code=exam_code))

            except Exception as e:
                print("Gemini Error:", e)

                flash("Gemini AI is currently unavailable. Continuing with rule-based validation.", "warning")

            # Read metadata
            metadata = get_pdf_metadata(file_path)
            print("PDF Metadata:", metadata)

            # File path relative to static asset loader
            relative_file_path = f"static/uploads/{safe_filename}"

            # 4. Update examination details in MySQL
            cursor.execute("""
                UPDATE exams 
                SET paper_file_path = %s, paper_hash = %s, status = 'Uploaded'
                WHERE exam_code = %s
            """, (relative_file_path, sha256_hash, exam_code))

            # 5. Fetch blockchain logs sequence count for block validation
            cursor.execute("SELECT block_index, block_hash FROM blockchain_logs WHERE exam_code = %s ORDER BY block_index DESC LIMIT 1", (exam_code,))
            latest_block = cursor.fetchone()
            
            block_index = 1
            previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            
            if latest_block:
                block_index = latest_block['block_index'] + 1
                previous_hash = latest_block['block_hash']

            # 6. Emit new block logs
            upload_timestamp = datetime.now()
            hash_payload = f"{block_index}:{exam_code}:Paper Uploaded:{upload_timestamp.strftime('%Y-%m-%d %H:%M:%S')}:{previous_hash}"
            block_hash = hashlib.sha256(hash_payload.encode()).hexdigest()

            cursor.execute("""
                INSERT INTO blockchain_logs (exam_code, block_index, timestamp, action, previous_hash, block_hash, operator, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'Success')
            """, (
                exam_code,
                block_index,
                upload_timestamp,
                'Paper Uploaded',
                previous_hash,
                block_hash,
                session.get('government_id', 'officer@examshield.gov.in')
            ))

            conn.commit()
            cursor.close()
            conn.close()

            flash("Question paper packet uploaded successfully. SHA-256 DNA hash generated.", "success")
            return redirect(url_for('security_scan', exam_code=exam_code))

        # GET request: Load scheduled exams list
        cursor.execute("SELECT exam_code, exam_name, status FROM exams ORDER BY id DESC")
        created_exams = cursor.fetchall()

        selected_code = request.args.get('exam_code')
        if not selected_code and created_exams:
            selected_code = created_exams[0]['exam_code']

        cursor.close()
        conn.close()

        return render_template('upload.html', created_exams=created_exams, selected_code=selected_code)

    except mysql.connector.Error as err:
        flash(f"Database error during file uploads: {err}", "error")
        return render_template('upload.html', created_exams=[], selected_code="")


@app.route('/security_scan', methods=['GET', 'POST'])
def security_scan():
    """
    Why it is needed:
        Serves the AI Security Sweep scanner page (GET) and processes the simulated sweep checks (POST).
        POST is triggered asynchronously via client-side AJAX. It updates the database metrics
        and emits sequential blockchain logs.
    Input:
        GET: exam_code query parameter (optional, defaults to first).
        POST (AJAX): exam_code identifier.
    Output:
        GET: Renders templates/security_scan.html.
        POST (AJAX): Returns JSON status and computed security score.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.method == 'POST':
            return jsonify({'status': 'error', 'message': 'Session expired. Please log in again.'}), 401
        flash("Security Shield: Please log in to access the AI Security console.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            # AJAX POST sweep update
            exam_code = request.form.get('exam_code')
            if not exam_code:
                return jsonify({'status': 'error', 'message': 'Missing Exam Code parameter.'}), 400

            # Verify exam exists
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (exam_code,))
            exam = cursor.fetchone()
            if not exam:
               return jsonify({'status': 'error', 'message': 'Examination record not found.'}), 404

            # Generate security parameters
            security_score = random.randint(90, 98)

            mock_report = """[
                {"step": "Integrity threats check", "status": "Passed", "score": 98},
                {"step": "Steganographic watermarking", "status": "Embedded", "score": 100},
                {"step": "Metadata cleaning sweep", "status": "Cleaned", "score": 95},
                {"step": "Leak and plagiarism scanning", "status": "Passed", "score": 100}
            ]"""
            # REAL PDF SECURITY ANALYSIS
            # ----------------------------

            cursor.execute("""
            SELECT paper_file_path
            FROM exams
            WHERE exam_code=%s
            """, (exam_code,))

            paper = cursor.fetchone()

            if not paper or not paper["paper_file_path"]:
                return jsonify({
                    "status": "error",
                    "message": "Question paper not uploaded."
                }),400


            pdf_path = os.path.join(
                app.root_path,
                paper["paper_file_path"]
            )

            reader = PdfReader(pdf_path)

            text = ""

            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text


            security_score = 100
            report = []

            # Check whether PDF contains readable text
            if len(text.strip()) < 100:

                return jsonify({
                    "status": "error",
                    "message": "This PDF appears to be image-only or contains insufficient readable question-paper text. Please upload a readable question paper PDF."
                }), 400

            # Very Short Paper

            if len(text) < 100:
                security_score -= 25
                report.append({
                    "step":"Content Length",
                    "status":"Too Short",
                    "score":75
                })
            else:
                report.append({
                    "step":"Content Length",
                    "status":"Passed",
                    "score":100
                })
            # Duplicate Questions

            # Duplicate question detection
            lines = [
                x.strip()
                for x in text.split("\n")
                if len(x.strip()) > 20
            ]

            question_lines = []

            for line in lines:
                lower_line = line.lower()

                if any(word in lower_line for word in [
                    "instructions",
                    "candidate",
                    "question paper",
                    "maximum marks",
                    "time",
                    "section"
                ]):
                    continue

                question_lines.append(line)

            duplicates = len(question_lines) - len(set(question_lines))

            # Maximum penalty = 15 points
            duplicate_penalty = min(duplicates * 2, 15)

            security_score -= duplicate_penalty

            if duplicates > 0:
                report.append({
                    "step": "Duplicate Questions",
                    "status": f"{duplicates} possible duplicate(s) found",
                    "score": 100 - duplicate_penalty
                })
            else:
                report.append({
                    "step": "Duplicate Questions",
                    "status": "Passed",
                    "score": 100
                })

            # Suspicious Words

            bad_words = [
                "answer",
                "solution",
                "confidential",
                "password"
            ]

            found=[]

            for word in bad_words:

                if word.lower() in text.lower():

                    found.append(word)

            if found:

                security_score -= 20

                report.append({
                    "step":"Sensitive Keywords",
                    "status":"Found : " + ", ".join(found),
                    "score":80
                })

            else:

                report.append({
                    "step":"Sensitive Keywords",
                    "status":"Passed",
                    "score":100
                })

            # Final Score

            if security_score < 0:
                security_score = 0

            mock_report = json.dumps(report)

                       
            # Gemini AI Security Analysis
            # -----------------------------

            try:

                prompt = f"""
            You are an Exam Paper Security AI.

            Analyze this exam paper.

            Paper:

            {text[:12000]}

            Check:

            1. Duplicate Questions
            2. Suspicious Content
            3. Confidential Information
            4. Passwords
            5. Answer Keys
            6. Overall Security Risk

            Give a professional report in simple English.
            """

                ai_response = model.generate_content(prompt)

                ai_report = ai_response.text

            except Exception as e:

                ai_report = f"Gemini AI Error : {e}"

            # Update exam details
            cursor.execute("""
            UPDATE exams
            SET
            security_score=%s,
            security_report=%s,
            status='Scanned'
            WHERE exam_code=%s
            """,
            (
            security_score,
            ai_report,
            exam_code
            ))

            # Fetch the latest block log for blockchain sequence continuation
            cursor.execute("SELECT block_index, block_hash FROM blockchain_logs WHERE exam_code = %s ORDER BY block_index DESC LIMIT 1", (exam_code,))
            latest_block = cursor.fetchone()
            
            block_index = 1
            previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            
            if latest_block:
                block_index = latest_block['block_index'] + 1
                previous_hash = latest_block['block_hash']

            # Generate block hash
            scan_timestamp = datetime.now()
            hash_payload = f"{block_index}:{exam_code}:AI Scanned:{scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}:{previous_hash}"
            block_hash = hashlib.sha256(hash_payload.encode()).hexdigest()

            # Insert block transaction record
            cursor.execute("""
                INSERT INTO blockchain_logs (exam_code, block_index, timestamp, action, previous_hash, block_hash, operator, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'Success')
            """, (
                exam_code,
                block_index,
                scan_timestamp,
                'AI Scanned',
                previous_hash,
                block_hash,
                session.get('government_id', 'officer@examshield.gov.in')
            ))

            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({
                'status': 'success',
                'security_score': security_score
            })

        # GET request: Load scanner menu options
        cursor.execute("SELECT exam_code, exam_name, status FROM exams ORDER BY id DESC")
        uploaded_exams = cursor.fetchall()

        selected_code = request.args.get('exam_code')
        if not selected_code and uploaded_exams:
            selected_code = uploaded_exams[0]['exam_code']

        exam = None
        if selected_code:
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (selected_code,))
            exam = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template('security_scan.html', uploaded_exams=uploaded_exams, exam=exam)

    except mysql.connector.Error as err:
        if request.method == 'POST':
            return jsonify({'status': 'error', 'message': f"Database failure: {err}"}), 500
        flash(f"Database statistics fetch error: {err}", "error")
        return render_template('security_scan.html', uploaded_exams=[], exam=None)

@app.route("/notifications")
def notifications():

    if not session.get("logged_in"):
        return jsonify({
            "count":0,
            "notifications":[]
        })

    conn=get_db_connection()
    cursor=conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT title,
               message,
               DATE_FORMAT(created_at,'%d-%m-%Y %H:%i') AS created_at
        FROM notifications
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 10
    """,(session["user_id"],))

    notifications=cursor.fetchall()

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM notifications
        WHERE user_id=%s
    """,(session["user_id"],))

    count=cursor.fetchone()["total"]

    cursor.close()
    conn.close()

    return jsonify({
        "count":count,
        "notifications":notifications
    })


@app.route('/blockchain')
def blockchain():
    """
    Why it is needed:
        Serves the SecureChain ledger visualizer and dynamic DNA display.
        Allows officers to search for an exam, query its sequential milestone block transaction ledger logs,
        and generate dynamic visual block sequences.
    Input:
        Query Parameter:
        - exam_code (str): The code of the exam to query (optional, defaults to first).
    Output:
        Renders templates/blockchain.html.
    """
   
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to view the SecureChain ledger.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch all examinations in database to populate dropdown search list
        cursor.execute("SELECT exam_code, exam_name, status FROM exams ORDER BY id DESC")
        created_exams = cursor.fetchall()
        
        # 2. Get specific exam code from request query parameter, or default to the first exam
        selected_code = request.args.get('exam_code')
        if not selected_code and created_exams:
            selected_code = created_exams[0]['exam_code']
            
        exam = None
        blockchain_logs = []
        paper_dna = ""
        chain_status = "Verified"
        tampered_block = None
        
        if selected_code:
            # 3. Retrieve exam details
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (selected_code,))
            exam = cursor.fetchone()
            
            if exam:
                # 4. Generate dynamic SHA-256 fingerprint representing the Exam DNA
                paper_dna = exam['paper_hash']
                if not paper_dna:
                    paper_dna = hashlib.sha256(exam['exam_code'].encode()).hexdigest()
                    
                # 5. Fetch blockchain logs sequence sorted by block index
                cursor.execute("SELECT * FROM blockchain_logs WHERE exam_code = %s ORDER BY block_index ASC", (selected_code,))
                blockchain_logs = cursor.fetchall()

                # Verify blockchain integrity
                for i in range(1, len(blockchain_logs)):
                    if blockchain_logs[i]['previous_hash'] != blockchain_logs[i-1]['block_hash']:
                        chain_status = "Tampered"
                        tampered_block = blockchain_logs[i]['block_index']
                        break
        cursor.close()
        conn.close()
        
       
       
        return render_template(
            'blockchain.html',
            created_exams=created_exams,
            exam=exam,
            blockchain_logs=blockchain_logs,
            paper_dna=paper_dna,
            chain_status=chain_status,
            tampered_block=tampered_block
        )
        
    except mysql.connector.Error as err:
        flash(f"Database error during blockchain ledger sync: {err}", "error")
        return render_template(
            'blockchain.html',
            created_exams=[],
            exam=None,
            blockchain_logs=[],
            paper_dna=""
        )


@app.route('/verify_chain', methods=['POST'])
def verify_chain():
    """
    Why it is needed:
        Asynchronously traverses blockchain transaction block parent links to verify sequence integrity.
        Computes dynamic link checks and reports failure details if any mismatch occurs.
    Input:
        POST (AJAX): exam_code identifier.
    Output:
        Returns JSON confirmation or tampered status logs.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Session expired. Please log in again.'}), 401

    exam_code = request.form.get('exam_code')
    if not exam_code:
        return jsonify({'status': 'error', 'message': 'Missing Exam Code parameter.'}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Query blockchain logs sequence sorted by block index
        cursor.execute("SELECT block_index, previous_hash, block_hash FROM blockchain_logs WHERE exam_code = %s ORDER BY block_index ASC", (exam_code,))
        blocks = cursor.fetchall()
        
        cursor.close()
        conn.close()

        if not blocks:
            return jsonify({'status': 'error', 'message': 'No ledger logs recorded for this exam.'}), 400

        # Traverse sequential chain links
        for i in range(1, len(blocks)):

        # Verify chain link
            if blocks[i]['previous_hash'] != blocks[i-1]['block_hash']:
                return jsonify({
                    'status': 'tampered',
                    'message': f"Block {blocks[i]['block_index']} previous hash mismatch."
                })

        # Verify hash format
        if len(blocks[i]['block_hash']) != 64:
            return jsonify({
                'status': 'tampered',
                'message': f"Invalid SHA-256 hash detected in Block {blocks[i]['block_index']}."
            })

        if not all(c in "0123456789abcdef" for c in blocks[i]['block_hash'].lower()):
            return jsonify({
                'status': 'tampered',
                'message': f"Corrupted blockchain hash in Block {blocks[i]['block_index']}."
            })

        return jsonify({
            'status': 'success',
            'message': 'Chain verified successfully. Ledger integrity secure.'
        })

    except mysql.connector.Error as err:
        return jsonify({'status': 'error', 'message': f"Database traversal failure: {err}"}), 500

from flask import Response
import csv
import io

@app.route('/export_blockchain/<exam_code>')
def export_blockchain(exam_code):

    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT block_index,
               timestamp,
               action,
               previous_hash,
               block_hash,
               operator,
               status
        FROM blockchain_logs
        WHERE exam_code=%s
        ORDER BY block_index
    """, (exam_code,))

    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Block",
        "Timestamp",
        "Action",
        "Previous Hash",
        "Current Hash",
        "Operator",
        "Status"
    ])

    for row in logs:
        writer.writerow([
            row["block_index"],
            row["timestamp"],
            row["action"],
            row["previous_hash"],
            row["block_hash"],
            row["operator"],
            row["status"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            f"attachment; filename={exam_code}_blockchain.csv"
        }
    )
@app.route('/search')
def search():

    keyword = request.args.get('q')

    if not keyword:
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT *
        FROM exams
        WHERE exam_code LIKE %s
        OR exam_name LIKE %s
        OR state_ut LIKE %s
        OR status LIKE %s
    """

    search_value = "%" + keyword + "%"

    cursor.execute(
        query,
        (
            search_value,
            search_value,
            search_value,
            search_value
        )
    )

    exams = cursor.fetchall()

    cursor.close()
    conn.close()


    return render_template(
    "search_results.html",
    exams=exams,
    keyword=keyword
    )
    
@app.route('/qr')
def qr():
    """
    Why it is needed:
        Serves the SmartTrace QR Label Generator page.
        Allows officers to search for an exam, query its metadata, and render
        a downloadable/printable barcode label containing its DNA fingerprint.
    Input:
        Query Parameter:
        - exam_code (str): The code of the exam to render (optional, defaults to first).
    Output:
        Renders templates/qr.html.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to access the secure QR console.", "error")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch all examinations in database to populate dropdown search list
        cursor.execute("SELECT exam_code, exam_name FROM exams ORDER BY id DESC")
        created_exams = cursor.fetchall()
        
        # 2. Get specific exam code from request query parameter, or default to the first exam
        selected_code = request.args.get('exam_code')
        if not selected_code and created_exams:
            selected_code = created_exams[0]['exam_code']
            
        exam = None
        paper_dna = ""
        
        if selected_code:
            # 3. Retrieve exam details
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (selected_code,))
            exam = cursor.fetchone()
            
            if exam:
                # 4. Generate dynamic SHA-256 placeholder hash for visual fingerprint if no paper uploaded yet
                paper_dna = exam['paper_hash']
                if not paper_dna:
                    paper_dna = hashlib.sha256(exam['exam_code'].encode()).hexdigest()

                    # QR verification status
                    qr_status = "Verified"

                    if exam.get("paper_hash"):
                        qr_status = "Verified"
                    else:
                        qr_status = "Pending"
                    
        cursor.close()
        conn.close()
        
        return render_template(
        'qr.html',
        created_exams=created_exams,
        exam=exam,
        paper_dna=paper_dna,
        qr_status=qr_status
)
        
    except mysql.connector.Error as err:
            flash(f"Database error during QR label synchronization: {err}", "error")
            return render_template(
            'qr.html',
            created_exams=created_exams,
            exam=exam,
            paper_dna=paper_dna,
            qr_status="Ready"
        )


def render_report(print_mode=False):
    """
    Why it is needed:
        Unified internal helper that handles report parameter gathering, database
        queries, checkmarks evaluations, and data packaging. This ensures the
        integrated review screen and printable PDF sheet share identical logic.
    Input:
        bool: print_mode (controls sidebar layout hiding and browser print autostart).
    Output:
        Renders templates/reports.html with compiled data grids.
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Fetch all examinations in database to populate dropdown search list
        cursor.execute("SELECT exam_code, exam_name FROM exams ORDER BY id DESC")
        created_exams = cursor.fetchall()
        
        # 2. Get specific exam code from request parameters, or default to the first exam
        selected_code = request.args.get('exam_code')
        if not selected_code and created_exams:
            selected_code = created_exams[0]['exam_code']
            
        # 3. Evaluate selected checkmarks checkboxes
        # On initial page load (no parameters), default all segments to active
        has_args = ('show_security' in request.args or 'show_blockchain' in request.args or 
                    'show_tracking' in request.args or 'security' in request.args or 
                    'blockchain' in request.args or 'tracking' in request.args)
        
        if has_args:
            show_security = request.args.get('show_security', '0') == '1' or request.args.get('security', '0') == '1'
            show_blockchain = request.args.get('show_blockchain', '0') == '1' or request.args.get('blockchain', '0') == '1'
            show_tracking = request.args.get('show_tracking', '0') == '1' or request.args.get('tracking', '0') == '1'
        else:
            show_security = True
            show_blockchain = True
            show_tracking = True
            
        exam = None
        paper_dna = ""
        blockchain_logs = []
        tracking_logs = []
        
        if selected_code:
            # 4. Retrieve exam details
            cursor.execute("SELECT * FROM exams WHERE exam_code = %s", (selected_code,))
            exam = cursor.fetchone()
            
            if exam:
                # 5. Extract SHA-256 fingerprint, generating fallback hash if not uploaded yet
                paper_dna = exam['paper_hash']
                if not paper_dna:
                    paper_dna = hashlib.sha256(exam['exam_code'].encode()).hexdigest()
                    
                # 6. Fetch SecureChain blockchain timeline logs
                if show_blockchain:
                    cursor.execute("SELECT * FROM blockchain_logs WHERE exam_code = %s ORDER BY block_index ASC", (selected_code,))
                    blockchain_logs = cursor.fetchall()
                    
                # 7. Fetch SmartTrace GPS tracking logs
                if show_tracking:
                    cursor.execute("SELECT * FROM tracking_logs WHERE exam_code = %s ORDER BY id ASC", (selected_code,))
                    tracking_logs = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template(
            'reports.html',
            created_exams=created_exams,
            exam=exam,
            show_security=show_security,
            show_blockchain=show_blockchain,
            show_tracking=show_tracking,
            blockchain_logs=blockchain_logs,
            tracking_logs=tracking_logs,
            paper_dna=paper_dna,
            current_time=current_time,
            print_mode=print_mode
        )
        
    except mysql.connector.Error as err:
        flash(f"Database error during audit compilation: {err}", "error")
        return render_template(
            'reports.html',
            created_exams=[],
            exam=None,
            show_security=True,
            show_blockchain=True,
            show_tracking=True,
            blockchain_logs=[],
            tracking_logs=[],
            paper_dna="",
            current_time="",
            print_mode=print_mode
        )


@app.route('/reports')
def reports():
    """
    Why it is needed:
        Serves the interactive secure reports compiler screen.
    Input:
        None
    Output:
        Renders templates/reports.html with dashboard layout wrappers.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to access the secure audit reports console.", "error")
        return redirect(url_for('login'))
    return render_report(print_mode=False)


@app.route('/print_report')
def print_report():
    """
    Why it is needed:
        Serves the clean printable audit sheet that autostarts window.print()
    Input:
        None
    Output:
        Renders templates/reports.html with header wrapper stripped out.
    """
    # Active session check (Route protection)
    if not session.get('logged_in'):
        flash("Security Shield: Please log in to view printable audit reports.", "error")
        return redirect(url_for('login'))
    return render_report(print_mode=True)

@app.route('/verify_report/<exam_code>')
def verify_report(exam_code):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM created_exams WHERE exam_code=%s",
        (exam_code,)
    )

    exam = cursor.fetchone()

    cursor.close()
    conn.close()

    if not exam:
        return "Invalid QR Code", 404

    return f"""
    <h1>EXAMSHIELD Verification</h1>

    <h2>Exam Code : {exam['exam_code']}</h2>

    <h3>Exam Name : {exam['exam_name']}</h3>

    <h3>Status : {exam['status']}</h3>

    <h3>Authority : {exam['authority']}</h3>

    <h2 style='color:green'>
    ✓ VERIFIED
    </h2>
    """
    
@app.route('/logout')
def logout():
    officer_id = session.get('government_id', 'Unknown')
    token = request.cookies.get('remember_token')

    conn = None
    try:
        if token:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM remember_tokens WHERE token=%s",
                (token,)
            )
            conn.commit()
    except Exception as e:
        print(e)
    finally:
        if conn:
            conn.close()

    session.clear()
    print(f"\n[SECURITY CONTROL] Session terminated. Officer {officer_id} logged out successfully.\n")
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('remember_token')
    response.set_cookie('session', '', expires=0)

    flash("Session terminated successfully.", "success")

    return response


# 5. EXECUTION BOOTSTRAP
if __name__ == '__main__':
    # Debug mode is activated to facilitate real-time updates and template hot reloading.
    app.run(debug=True, port=5000)
