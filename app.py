from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
import sqlite3
import os
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT UNIQUE, 
                 password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_details 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 user_id INTEGER, 
                 aadhar_number TEXT, 
                 aadhar_image TEXT, 
                 voter_id TEXT, 
                 education TEXT,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 filename TEXT,
                 original_filename TEXT,
                 document_type TEXT,
                 upload_date DATETIME,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     (username, password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user[2], password):
        session['user_id'] = user[0]
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    
    flash('Invalid credentials!', 'error')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM user_details WHERE user_id = ?", (session['user_id'],))
    details = c.fetchone()
    
    # Fetch user's documents
    c.execute("SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC", (session['user_id'],))
    documents = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', details=details, documents=documents)

@app.route('/save_details', methods=['POST'])
def save_details():
    if 'user_id' not in session:
        return redirect(url_for('index'))
        
    aadhar_number = request.form['aadhar_number']
    voter_id = request.form['voter_id']
    education = request.form['education']
    aadhar_image = None
    
    # Handle document uploads
    if 'documents[]' in request.files:
        files = request.files.getlist('documents[]')
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        for file in files:
            if file and allowed_file(file.filename):
                original_filename = secure_filename(file.filename)
                # Add user_id prefix to prevent filename conflicts
                filename = f"{session['user_id']}_{original_filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                # Store document info in database
                document_type = original_filename.rsplit('.', 1)[1].lower()
                c.execute('''INSERT INTO documents 
                            (user_id, filename, original_filename, document_type, upload_date)
                            VALUES (?, ?, ?, ?, ?)''',
                         (session['user_id'], filename, original_filename, 
                          document_type, datetime.now()))
        
        conn.commit()
        conn.close()
    
    if 'aadhar_image' in request.files:
        file = request.files['aadhar_image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            aadhar_image = filename
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM user_details WHERE user_id = ?", (session['user_id'],))
    existing_details = c.fetchone()
    
    if existing_details:
        c.execute('''UPDATE user_details 
                    SET aadhar_number = ?, aadhar_image = ?, voter_id = ?, education = ?
                    WHERE user_id = ?''',
                 (aadhar_number, aadhar_image, voter_id, education, session['user_id']))
    else:
        c.execute('''INSERT INTO user_details 
                    (user_id, aadhar_number, aadhar_image, voter_id, education) 
                    VALUES (?, ?, ?, ?, ?)''',
                 (session['user_id'], aadhar_number, aadhar_image, voter_id, education))
    
    conn.commit()
    conn.close()
    
    flash('Details saved successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:doc_id>')
def download_document(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT filename, original_filename FROM documents WHERE id = ? AND user_id = ?", 
             (doc_id, session['user_id']))
    document = c.fetchone()
    conn.close()
    
    if document:
        return send_from_directory(app.config['UPLOAD_FOLDER'],
                                 document[0],
                                 as_attachment=True,
                                 download_name=document[1])
    flash('Document not found!', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:doc_id>', methods=['POST'])
def delete_document(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Get the filename before deleting the record
    c.execute("SELECT filename FROM documents WHERE id = ? AND user_id = ?", 
             (doc_id, session['user_id']))
    document = c.fetchone()
    
    if document:
        # Delete the file from the filesystem
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document[0])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete the record from the database
        c.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", 
                 (doc_id, session['user_id']))
        conn.commit()
        flash('Document deleted successfully!', 'success')
    else:
        flash('Document not found!', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db()
    app.run(debug=True)