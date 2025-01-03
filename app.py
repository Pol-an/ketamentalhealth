# app.py

import os
import sqlite3
import csv
import io
import math
import shutil
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

# Configuration
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')  # Replace with a strong secret key in production
DATABASE = 'clinic.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'db'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Establish a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable accessing columns by name
    return conn

def init_db():
    """
    Initialize the database with required tables.
    Creates 'users', 'patients', and 'appointments' tables.
    Inserts a default admin user if not present.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Create 'users' table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin'
        )
    """)

    # Create 'patients' table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            date_of_visit TEXT NOT NULL,
            history_illness TEXT,
            diagnosis TEXT,
            treatment TEXT,
            price REAL,
            address TEXT
        )
    """)

    # Create 'appointments' table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            appointment_date TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'scheduled',
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
    """)

    # Check if default admin exists
    cur.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    admin = cur.fetchone()
    if not admin:
        # Create default admin user with username 'admin' and password 'admin'
        hashed_password = generate_password_hash('admin', method='sha256')
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ('admin', hashed_password, 'admin'))
        logger.info("Default admin user created with username 'admin' and password 'admin'. Please change the password immediately.")

    conn.commit()
    conn.close()

# Initialize the database
init_db()

# ------------------------------------------------------
#   Authentication Routes
# ------------------------------------------------------
@app.route('/', methods=['GET','POST'])
@app.route('/login', methods=['GET','POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Please enter both username and password.", "warning")
            return redirect(url_for('login'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # Successful login
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Login successful!", "success")
            logger.info(f"User '{username}' logged in.")
            return redirect(url_for('dashboard'))
        else:
            # Invalid credentials
            flash("Invalid username or password!", "danger")
            logger.warning(f"Failed login attempt for username '{username}'.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    username = session.get('username', 'Unknown User')
    session.clear()
    flash("You have been logged out.", "info")
    logger.info(f"User '{username}' logged out.")
    return redirect(url_for('login'))

# ------------------------------------------------------
#   Password Reset / Change Routes
# ------------------------------------------------------
@app.route('/reset_password', methods=['GET','POST'])
def reset_password():
    """Allow users to reset their password by providing their username."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not username or not new_password or not confirm_password:
            flash("All fields are required.", "warning")
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('reset_password'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user:
            hashed_password = generate_password_hash(new_password, method='sha256')
            cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            conn.commit()
            flash("Password reset successful!", "success")
            logger.info(f"Password reset for user '{username}'.")
        else:
            flash("User not found!", "danger")
            logger.warning(f"Password reset attempted for non-existent user '{username}'.")

        conn.close()
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/change_password', methods=['GET','POST'])
def change_password():
    """Allow logged-in users to change their current password."""
    if not session.get('logged_in'):
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form.get('old_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not old_password or not new_password or not confirm_password:
            flash("All fields are required.", "warning")
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("New passwords do not match!", "danger")
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], old_password):
            hashed_new_password = generate_password_hash(new_password, method='sha256')
            cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, session['username']))
            conn.commit()
            flash("Password changed successfully!", "success")
            logger.info(f"User '{session['username']}' changed their password.")
        else:
            flash("Old password is incorrect!", "danger")
            logger.warning(f"User '{session['username']}' provided incorrect old password.")

        conn.close()
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# ------------------------------------------------------
#   User Management Routes
# ------------------------------------------------------
@app.route('/create_user', methods=['GET','POST'])
def create_user():
    """Allow admin users to create new users with specific roles."""
    if not session.get('logged_in'):
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash("You do not have permission to create users!", "danger")
        logger.warning(f"User '{session['username']}' attempted to access create_user without admin privileges.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()

        if not username or not password or not role:
            flash("All fields are required.", "warning")
            return redirect(url_for('create_user'))

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            hashed_password = generate_password_hash(password, method='sha256')
            cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (username, hashed_password, role))
            conn.commit()
            flash(f"User '{username}' created successfully with role '{role}'!", "success")
            logger.info(f"Admin '{session['username']}' created new user '{username}' with role '{role}'.")
        except sqlite3.IntegrityError:
            flash("Username already exists!", "danger")
            logger.warning(f"Attempt to create user with existing username '{username}'.")
        finally:
            conn.close()

        return redirect(url_for('create_user'))

    return render_template('create_user.html')

# ------------------------------------------------------
#   Dashboard Route (Register & List Patients)
# ------------------------------------------------------
@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    """Display patient registration form and list of patients with search and pagination."""
    if not session.get('logged_in'):
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        # Only admin or doctor can register new patients
        if session['role'] not in ['admin', 'doctor']:
            flash("You do not have permission to add new patients!", "danger")
            logger.warning(f"User '{session['username']}' attempted to add a new patient without sufficient privileges.")
            return redirect(url_for('dashboard'))

        # Retrieve form data
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()
        gender = request.form.get('gender', '').strip()
        phone = request.form.get('phone', '').strip()
        date_of_visit = request.form.get('date_of_visit', '').strip()
        history_illness = request.form.get('history_illness', '').strip()
        diagnosis = request.form.get('diagnosis', '').strip()
        treatment = request.form.get('treatment', '').strip()
        price = request.form.get('price', '').strip()
        address = request.form.get('address', '').strip()

        # Input validation can be enhanced as needed
        if not name or not age or not gender or not phone or not date_of_visit:
            flash("Please fill in all required fields.", "danger")
            logger.warning(f"User '{session['username']}' submitted incomplete patient registration form.")
            return redirect(url_for('dashboard'))

        try:
            price = float(price) if price else 0.0
        except ValueError:
            flash("Invalid price format.", "danger")
            logger.warning(f"User '{session['username']}' entered invalid price '{price}' for patient '{name}'.")
            return redirect(url_for('dashboard'))

        try:
            cur.execute("""
                INSERT INTO patients 
                (name, age, gender, phone, date_of_visit, history_illness, diagnosis, treatment, price, address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, age, gender, phone, date_of_visit, history_illness, diagnosis, treatment, price, address))
            conn.commit()
            flash("Patient registered successfully!", "success")
            logger.info(f"User '{session['username']}' registered new patient '{name}'.")
        except sqlite3.IntegrityError:
            flash("Phone number must be unique.", "danger")
            logger.warning(f"Attempt to register patient with existing phone number '{phone}'.")
        finally:
            conn.close()

        return redirect(url_for('dashboard'))

    # Handle GET request: display patient list with search and pagination
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = "SELECT * FROM patients"
    params = []

    if search_query:
        query += " WHERE name LIKE ? OR phone LIKE ?"
        like_query = f"%{search_query}%"
        params.extend([like_query, like_query])

    query += " ORDER BY id DESC"

    cur.execute(query, params)
    all_patients = cur.fetchall()

    total_patients = len(all_patients)
    total_pages = math.ceil(total_patients / per_page)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_patients = all_patients[start:end]

    conn.close()

    return render_template(
        'dashboard.html',
        patients=paginated_patients,
        search_query=search_query,
        page=page,
        total_pages=total_pages,
        total_patients=total_patients
    )

# ------------------------------------------------------
#   Patient Profile Route
# ------------------------------------------------------
@app.route('/patient_profile/<int:patient_id>')
def patient_profile(patient_id):
    """Display detailed information about a specific patient."""
    if not session.get('logged_in'):
        flash("Please log in to view patient profiles.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cur.fetchone()
    conn.close()

    if not patient:
        flash("Patient not found.", "danger")
        logger.warning(f"User '{session.get('username')}' attempted to view non-existent patient ID '{patient_id}'.")
        return redirect(url_for('dashboard'))

    return render_template('patient_profile.html', patient=patient)

# ------------------------------------------------------
#   Edit Patient Route (Admin/Doctor)
# ------------------------------------------------------
@app.route('/edit_patient/<int:patient_id>', methods=['POST'])
def edit_patient(patient_id):
    """Allow admin and doctor users to edit existing patient information."""
    if not session.get('logged_in'):
        flash("Please log in to edit patient information.", "warning")
        return redirect(url_for('login'))

    if session['role'] not in ['admin', 'doctor']:
        flash("You do not have permission to edit patient information.", "danger")
        logger.warning(f"User '{session['username']}' attempted to edit patient ID '{patient_id}' without sufficient privileges.")
        return redirect(url_for('dashboard'))

    # Retrieve form data
    name = request.form.get('name', '').strip()
    age = request.form.get('age', '').strip()
    gender = request.form.get('gender', '').strip()
    phone = request.form.get('phone', '').strip()
    date_of_visit = request.form.get('date_of_visit', '').strip()
    history_illness = request.form.get('history_illness', '').strip()
    diagnosis = request.form.get('diagnosis', '').strip()
    treatment = request.form.get('treatment', '').strip()
    price = request.form.get('price', '').strip()
    address = request.form.get('address', '').strip()

    # Input validation can be enhanced as needed
    if not name or not age or not gender or not phone or not date_of_visit:
        flash("Please fill in all required fields.", "danger")
        logger.warning(f"User '{session['username']}' submitted incomplete edit form for patient ID '{patient_id}'.")
        return redirect(url_for('dashboard'))

    try:
        price = float(price) if price else 0.0
    except ValueError:
        flash("Invalid price format.", "danger")
        logger.warning(f"User '{session['username']}' entered invalid price '{price}' for patient ID '{patient_id}'.")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE patients
            SET name = ?, age = ?, gender = ?, phone = ?, date_of_visit = ?,
                history_illness = ?, diagnosis = ?, treatment = ?, price = ?, address = ?
            WHERE id = ?
        """, (name, age, gender, phone, date_of_visit, history_illness, diagnosis, treatment, price, address, patient_id))
        conn.commit()
        flash("Patient information updated successfully.", "success")
        logger.info(f"User '{session['username']}' updated information for patient ID '{patient_id}'.")
    except sqlite3.IntegrityError:
        flash("Phone number must be unique.", "danger")
        logger.warning(f"Attempt to update patient ID '{patient_id}' with existing phone number '{phone}'.")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

# ------------------------------------------------------
#   Delete Patient Route (Admin Only)
# ------------------------------------------------------
@app.route('/delete_patient/<int:patient_id>')
def delete_patient(patient_id):
    """Allow admin users to delete a patient record."""
    if not session.get('logged_in'):
        flash("Please log in to delete patient records.", "warning")
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash("You do not have permission to delete patient records.", "danger")
        logger.warning(f"User '{session['username']}' attempted to delete patient ID '{patient_id}' without admin privileges.")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cur.fetchone()

    if not patient:
        flash("Patient not found.", "danger")
        logger.warning(f"User '{session['username']}' attempted to delete non-existent patient ID '{patient_id}'.")
        conn.close()
        return redirect(url_for('dashboard'))

    cur.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
    conn.commit()
    conn.close()

    flash("Patient deleted successfully.", "info")
    logger.info(f"Admin '{session['username']}' deleted patient ID '{patient_id}'.")
    return redirect(url_for('dashboard'))

# ------------------------------------------------------
#   Export CSV Route
# ------------------------------------------------------
@app.route('/export_csv')
def export_csv():
    """Allow logged-in users to export patient data as a CSV file."""
    if not session.get('logged_in'):
        flash("Please log in to export patient data.", "warning")
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()

    conn = get_db_connection()
    cur = conn.cursor()

    query = "SELECT * FROM patients"
    params = []

    if search_query:
        query += " WHERE name LIKE ? OR phone LIKE ?"
        like_query = f"%{search_query}%"
        params.extend([like_query, like_query])

    query += " ORDER BY id DESC"

    cur.execute(query, params)
    patients = cur.fetchall()
    conn.close()

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Age', 'Gender', 'Phone', 'Date of Visit',
                     'History Illness', 'Diagnosis', 'Treatment', 'Price', 'Address'])

    for patient in patients:
        writer.writerow([
            patient['id'],
            patient['name'],
            patient['age'],
            patient['gender'],
            patient['phone'],
            patient['date_of_visit'],
            patient['history_illness'],
            patient['diagnosis'],
            patient['treatment'],
            patient['price'],
            patient['address']
        ])

    # Prepare response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=patients.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

# ------------------------------------------------------
#   Backup and Restore Database Routes
# ------------------------------------------------------
@app.route('/backup_db')
def backup_db():
    """Allow admin users to download a backup of the current database."""
    if not session.get('logged_in'):
        flash("Please log in to backup the database.", "warning")
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash("You do not have permission to backup the database!", "danger")
        logger.warning(f"User '{session['username']}' attempted to backup the database without admin privileges.")
        return redirect(url_for('dashboard'))

    try:
        backup_filename = f"clinic_backup_{int(math.floor(os.path.getmtime(DATABASE)))}.db"
        return send_file(DATABASE, as_attachment=True, download_name=backup_filename)
    except Exception as e:
        flash("Failed to backup the database.", "danger")
        logger.error(f"Failed to backup the database: {e}")
        return redirect(url_for('dashboard'))

@app.route('/restore_db', methods=['GET','POST'])
def restore_db():
    """Allow admin users to restore the database from a backup file."""
    if not session.get('logged_in'):
        flash("Please log in to restore the database.", "warning")
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash("You do not have permission to restore the database!", "danger")
        logger.warning(f"User '{session['username']}' attempted to restore the database without admin privileges.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash("No file part!", "danger")
            return redirect(request.url)

        file = request.files['backup_file']

        if file.filename == '':
            flash("No selected file!", "danger")
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Backup current database before restoring
            backup_current_db = f"{DATABASE}.backup"
            try:
                shutil.copy(DATABASE, backup_current_db)
                shutil.copy(filepath, DATABASE)
                flash("Database restored successfully!", "success")
                logger.info(f"Admin '{session['username']}' restored the database from '{filename}'.")
            except Exception as e:
                flash("Failed to restore the database.", "danger")
                logger.error(f"Failed to restore the database from '{filename}': {e}")
                # Restore from backup
                shutil.copy(backup_current_db, DATABASE)
            finally:
                # Remove the uploaded backup file
                os.remove(filepath)

            return redirect(url_for('dashboard'))
        else:
            flash("Invalid file type! Only .db files are allowed.", "danger")
            return redirect(request.url)

    return render_template('restore_db.html')

# ------------------------------------------------------
#   Appointment Management Routes
# ------------------------------------------------------
@app.route('/schedule_appointment', methods=['GET','POST'])
def schedule_appointment():
    """Allow admin and doctor users to schedule new appointments for patients."""
    if not session.get('logged_in'):
        flash("Please log in to schedule appointments.", "warning")
        return redirect(url_for('login'))

    if session.get('role') not in ['admin', 'doctor']:
        flash("You do not have permission to schedule appointments!", "danger")
        logger.warning(f"User '{session['username']}' attempted to schedule an appointment without sufficient privileges.")
        return redirect(url_for('view_appointments'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        patient_id = request.form.get('patient_id', '').strip()
        appointment_date = request.form.get('appointment_date', '').strip()
        reason = request.form.get('reason', '').strip()

        if not patient_id or not appointment_date:
            flash("Please select a patient and appointment date/time.", "danger")
            logger.warning(f"User '{session['username']}' submitted incomplete appointment scheduling form.")
            return redirect(url_for('schedule_appointment'))

        try:
            cur.execute("""
                INSERT INTO appointments (patient_id, appointment_date, reason)
                VALUES (?, ?, ?)
            """, (patient_id, appointment_date, reason))
            conn.commit()
            flash("Appointment scheduled successfully!", "success")
            logger.info(f"User '{session['username']}' scheduled an appointment for patient ID '{patient_id}' on '{appointment_date}'.")
        except Exception as e:
            flash("Failed to schedule appointment.", "danger")
            logger.error(f"Failed to schedule appointment for patient ID '{patient_id}': {e}")
        finally:
            conn.close()

        return redirect(url_for('view_appointments'))

    # GET request: Fetch list of patients for the dropdown
    cur.execute("SELECT id, name FROM patients ORDER BY name ASC")
    patient_list = cur.fetchall()
    conn.close()

    return render_template('schedule_appointment.html', patient_list=patient_list)

@app.route('/view_appointments', methods=['GET'])
def view_appointments():
    """Display all scheduled appointments with options to update their status."""
    if not session.get('logged_in'):
        flash("Please log in to view appointments.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT a.id, p.name, a.appointment_date, a.reason, a.status, a.patient_id
        FROM appointments AS a
        JOIN patients AS p ON a.patient_id = p.id
        ORDER BY a.appointment_date DESC
    """)
    appointments = cur.fetchall()
    conn.close()

    return render_template('view_appointments.html', appointments=appointments)

@app.route('/update_appointment/<int:appt_id>', methods=['POST'])
def update_appointment(appt_id):
    """Allow admin and doctor users to update the status of an appointment."""
    if not session.get('logged_in'):
        flash("Please log in to update appointments.", "warning")
        return redirect(url_for('login'))

    if session.get('role') not in ['admin', 'doctor']:
        flash("You do not have permission to update appointments!", "danger")
        logger.warning(f"User '{session['username']}' attempted to update appointment ID '{appt_id}' without sufficient privileges.")
        return redirect(url_for('view_appointments'))

    new_status = request.form.get('status', '').strip()

    if new_status not in ['scheduled', 'completed', 'canceled']:
        flash("Invalid status selected.", "danger")
        logger.warning(f"User '{session['username']}' selected invalid status '{new_status}' for appointment ID '{appt_id}'.")
        return redirect(url_for('view_appointments'))

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("UPDATE appointments SET status = ? WHERE id = ?", (new_status, appt_id))
        conn.commit()
        flash("Appointment status updated successfully.", "success")
        logger.info(f"User '{session['username']}' updated status of appointment ID '{appt_id}' to '{new_status}'.")
    except Exception as e:
        flash("Failed to update appointment status.", "danger")
        logger.error(f"Failed to update status for appointment ID '{appt_id}': {e}")
    finally:
        conn.close()

    return redirect(url_for('view_appointments'))

# ------------------------------------------------------
#   Patient Profile Printing Route
# ------------------------------------------------------
@app.route('/print_patient/<int:patient_id>')
def print_patient(patient_id):
    """Provide a print-friendly view of patient details."""
    if not session.get('logged_in'):
        flash("Please log in to print patient profiles.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cur.fetchone()
    conn.close()

    if not patient:
        flash("Patient not found.", "danger")
        logger.warning(f"User '{session.get('username')}' attempted to print non-existent patient ID '{patient_id}'.")
        return redirect(url_for('dashboard'))

    return render_template('print_patient.html', patient=patient)

# ------------------------------------------------------
#   Error Handlers
# ------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors."""
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return render_template('500.html'), 500

# ------------------------------------------------------
#   Run the Flask App
# ------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
