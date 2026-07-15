import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key: read from env in production, but fall back to a local file so
# sessions survive a restart during development (os.urandom() on every boot
# silently logs everyone out).
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), '.secret_key')
if 'SECRET_KEY' in os.environ:
    app.secret_key = os.environ['SECRET_KEY']
else:
    if not os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(os.urandom(24))
    with open(SECRET_KEY_FILE, 'rb') as f:
        app.secret_key = f.read()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
PHOTO_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'photos')
# Allowed upload types. Kept as an allow-list on purpose: accepting "any"
# file type would let someone upload something like .html/.svg/.js and have
# it served back from /static, which is a stored-XSS / malware-hosting risk.
# This list already covers everything a portfolio realistically needs -
# widened here to also accept WEBP photos and Word certificates.
ALLOWED_CERT_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'webp', 'doc', 'docx'}
ALLOWED_PHOTO_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB cap on uploads
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PHOTO_FOLDER, exist_ok=True)

# ---------- HTTPS / cookie hardening ----------
# Actual TLS termination has to happen at your host/proxy (Render, Railway,
# Nginx, Cloudflare, etc.) - a Flask app can't create a certificate for you.
# What Flask CAN do is (a) refuse to hand out session cookies over plain
# HTTP, and (b) redirect any stray http:// request to https://. Turn this on
# once your host is actually serving you over https, by setting FORCE_HTTPS=1.
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', '0') == '1'
app.config['SESSION_COOKIE_SECURE'] = FORCE_HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


@app.before_request
def redirect_to_https():
    if FORCE_HTTPS and request.headers.get('X-Forwarded-Proto', request.scheme) != 'https':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)


def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set


def get_db_connection():
    conn = sqlite3.connect(os.path.join(BASE_DIR, 'database.db'))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        security_question TEXT,
        security_answer TEXT,
        last_login TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        full_name TEXT,
        headline TEXT,
        summary TEXT,
        location TEXT,
        email TEXT,
        phone TEXT,
        skills TEXT,
        hobbies TEXT,
        notice_period TEXT,
        languages TEXT,
        linkedin_url TEXT,
        github_url TEXT,
        photo_path TEXT,
        resume_path TEXT,
        view_count INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS experience (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        company TEXT NOT NULL,
        role TEXT NOT NULL,
        timeline TEXT,
        description TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS education (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        degree TEXT NOT NULL,
        institution TEXT NOT NULL,
        timeline TEXT,
        grade TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS certifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        authority TEXT NOT NULL,
        file_path TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        tech_stack TEXT NOT NULL,
        metrics TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')

    # Migration for users table
    existing_users_cols = [row['name'] for row in conn.execute('PRAGMA table_info(users)').fetchall()]
    if 'email' not in existing_users_cols:
        conn.execute('ALTER TABLE users ADD COLUMN email TEXT')
    if 'security_question' not in existing_users_cols:
        conn.execute('ALTER TABLE users ADD COLUMN security_question TEXT')
    if 'security_answer' not in existing_users_cols:
        conn.execute('ALTER TABLE users ADD COLUMN security_answer TEXT')
    if 'last_login' not in existing_users_cols:
        conn.execute('ALTER TABLE users ADD COLUMN last_login TEXT')

    # Migration for profiles table
    existing_profile_cols = [row['name'] for row in conn.execute('PRAGMA table_info(profiles)').fetchall()]
    if 'photo_path' not in existing_profile_cols:
        conn.execute('ALTER TABLE profiles ADD COLUMN photo_path TEXT')
    if 'resume_path' not in existing_profile_cols:
        conn.execute('ALTER TABLE profiles ADD COLUMN resume_path TEXT')
    if 'view_count' not in existing_profile_cols:
        conn.execute('ALTER TABLE profiles ADD COLUMN view_count INTEGER DEFAULT 0')

    conn.commit()
    conn.close()


init_db()


def load_profile_bundle(user_id):
    conn = get_db_connection()
    profile = conn.execute('SELECT * FROM profiles WHERE user_id = ?', (user_id,)).fetchone()
    experience = conn.execute('SELECT * FROM experience WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    certifications = conn.execute('SELECT * FROM certifications WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    projects = conn.execute('SELECT * FROM projects WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    conn.close()
    return profile, experience, certifications, projects


@app.context_processor
def inject_site_globals():
    import datetime
    return {
        'site_name': 'Sridin K R — Portfolio',
        'current_year': datetime.datetime.utcnow().year,
    }


def owns_row(table, row_id, user_id):
    conn = get_db_connection()
    row = conn.execute(f'SELECT user_id FROM {table} WHERE id = ?', (row_id,)).fetchone()
    conn.close()
    return row is not None and row['user_id'] == user_id


@app.route('/')
def index():
    conn = get_db_connection()
    owner = conn.execute(
        "SELECT * FROM profiles WHERE full_name IS NOT NULL AND full_name != '' ORDER BY user_id LIMIT 1"
    ).fetchone()
    if owner:
        conn.execute('UPDATE profiles SET view_count = view_count + 1 WHERE user_id = ?', (owner['user_id'],))
        conn.commit()
    conn.close()

    if not owner:
        return render_template('index.html', owner=None)

    profile, experience, certifications, projects = load_profile_bundle(owner['user_id'])
    return render_template(
        'index.html', owner=owner, profile=profile, experience=experience, certifications=certifications, projects=projects
    )


@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    conn = get_db_connection()
    profile_exists = conn.execute('SELECT 1 FROM profiles WHERE user_id = ?', (user_id,)).fetchone()
    if profile_exists:
        conn.execute('UPDATE profiles SET view_count = view_count + 1 WHERE user_id = ?', (user_id,))
        conn.commit()
    conn.close()

    profile, experience, certifications, projects = load_profile_bundle(user_id)
    if not profile:
        return "Profile not found", 404
    is_owner = session.get('user_id') == user_id
    return render_template(
        'profile.html', profile=profile, experience=experience, certifications=certifications,
        projects=projects, is_owner=is_owner
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '').strip()
        security_question = request.form.get('security_question', '')
        security_answer = request.form.get('security_answer', '').strip().lower()
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, email, security_question, security_answer) VALUES (?, ?, ?, ?, ?)',
                           (username, hashed_password, email, security_question, security_answer))
            user_id = cursor.lastrowid
            conn.execute('INSERT INTO profiles (user_id) VALUES (?)', (user_id,))
            conn.commit()
            flash('Account created. You can now log in.', 'success')
        except sqlite3.IntegrityError:
            flash('That username is already taken.', 'danger')
        finally:
            conn.close()
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            import datetime
            now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (now_str, user['id']))
            conn.commit()
            conn.close()

            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            if conn:
                conn.close()
            flash('Incorrect username or password.', 'danger')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    profile, experience, certifications, projects = load_profile_bundle(session['user_id'])
    return render_template(
        'dashboard.html', profile=profile, experience=experience, certifications=certifications, projects=projects, user=user
    )


@app.route('/dashboard/update/profile', methods=['POST'])
@app.route('/dashboard/update/all', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']

    conn = get_db_connection()

    photo_file = request.files.get('photo')
    if photo_file and photo_file.filename != '':
        if not allowed_file(photo_file.filename, ALLOWED_PHOTO_EXTENSIONS):
            flash('Profile photo must be a PNG, JPG, or WEBP.', 'danger')
            conn.close()
            return redirect(url_for('dashboard'))
        filename = secure_filename(f"user{user_id}_{photo_file.filename}")
        photo_file.save(os.path.join(PHOTO_FOLDER, filename))
        conn.execute('UPDATE profiles SET photo_path = ? WHERE user_id = ?', (filename, user_id))

    resume_file = request.files.get('resume')
    if resume_file and resume_file.filename != '':
        if not resume_file.filename.lower().endswith('.pdf'):
            flash('Resume must be a PDF file.', 'danger')
            conn.close()
            return redirect(url_for('dashboard'))
        resume_filename = secure_filename(f"resume_{user_id}_{resume_file.filename}")
        resume_file.save(os.path.join(app.config['UPLOAD_FOLDER'], resume_filename))
        conn.execute('UPDATE profiles SET resume_path = ? WHERE user_id = ?', (resume_filename, user_id))

    conn.execute('''UPDATE profiles SET
        full_name = ?, headline = ?, summary = ?, location = ?, email = ?, phone = ?,
        skills = ?, hobbies = ?, notice_period = ?, languages = ?, linkedin_url = ?, github_url = ?
        WHERE user_id = ?''', (
            request.form['full_name'], request.form['headline'], request.form['summary'],
            request.form['location'], request.form['email'], request.form['phone'],
            request.form['skills'], request.form['hobbies'], request.form['notice_period'],
            request.form['languages'], request.form['linkedin_url'], request.form['github_url'], user_id
        ))

    # ---- Multiple new projects ----
    titles = request.form.getlist('new_project_title[]')
    descriptions = request.form.getlist('new_project_description[]')
    tech_stacks = request.form.getlist('new_project_tech_stack[]')
    metrics_list = request.form.getlist('new_project_metrics[]')
    for i, title in enumerate(titles):
        if title.strip():
            conn.execute(
                'INSERT INTO projects (user_id, title, description, tech_stack, metrics) VALUES (?, ?, ?, ?, ?)',
                (user_id, title.strip(),
                 descriptions[i].strip() if i < len(descriptions) else '',
                 tech_stacks[i].strip() if i < len(tech_stacks) else '',
                 (metrics_list[i].strip() if i < len(metrics_list) else '') or None)
            )

    # ---- Multiple new experience entries ----
    companies = request.form.getlist('new_exp_company[]')
    roles = request.form.getlist('new_exp_role[]')
    exp_timelines = request.form.getlist('new_exp_timeline[]')
    exp_descriptions = request.form.getlist('new_exp_description[]')
    for i, company in enumerate(companies):
        if company.strip():
            conn.execute(
                'INSERT INTO experience (user_id, company, role, timeline, description) VALUES (?, ?, ?, ?, ?)',
                (user_id, company.strip(),
                 roles[i].strip() if i < len(roles) else '',
                 exp_timelines[i].strip() if i < len(exp_timelines) else '',
                 exp_descriptions[i].strip() if i < len(exp_descriptions) else '')
            )

    # ---- Multiple new certificates ----
    cert_titles = request.form.getlist('new_cert_title[]')
    cert_authorities = request.form.getlist('new_cert_authority[]')
    cert_files = request.files.getlist('new_cert_file[]')
    for i, ct in enumerate(cert_titles):
        if ct.strip():
            cert_filename = None
            if i < len(cert_files) and cert_files[i] and cert_files[i].filename != '':
                if not allowed_file(cert_files[i].filename, ALLOWED_CERT_EXTENSIONS):
                    flash('Certificate file must be a PDF, PNG, JPG, WEBP, DOC, or DOCX.', 'danger')
                    conn.close()
                    return redirect(url_for('dashboard'))
                cert_filename = secure_filename(f"{user_id}_{cert_files[i].filename}")
                cert_files[i].save(os.path.join(app.config['UPLOAD_FOLDER'], cert_filename))
            conn.execute(
                'INSERT INTO certifications (user_id, title, authority, file_path) VALUES (?, ?, ?, ?)',
                (user_id, ct.strip(),
                 cert_authorities[i].strip() if i < len(cert_authorities) else '',
                 cert_filename)
            )

    conn.commit()
    conn.close()
    flash('Profile updated.', 'success')
    return redirect(url_for('dashboard'))


# ---------- Experience: add / edit / delete ----------

@app.route('/dashboard/edit/experience/<int:item_id>', methods=['POST'])
def edit_experience(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('experience', item_id, session['user_id']):
        flash("That item doesn't belong to you.", 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    conn.execute('UPDATE experience SET company = ?, role = ?, timeline = ?, description = ? WHERE id = ?',
                 (request.form['company'], request.form['role'], request.form['timeline'], request.form['description'], item_id))
    conn.commit()
    conn.close()
    flash('Experience updated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard/delete/experience/<int:item_id>', methods=['POST'])
def delete_experience(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('experience', item_id, session['user_id']):
        flash("That item doesn't belong to you.", 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    conn.execute('DELETE FROM experience WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    flash('Experience removed.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard/delete/certification/<int:item_id>', methods=['POST'])
def delete_certification(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('certifications', item_id, session['user_id']):
        flash("That item doesn't belong to you.", 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    conn.execute('DELETE FROM certifications WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    flash('Certificate removed.', 'success')
    return redirect(url_for('dashboard'))



# ---------- Projects: add / edit / delete ----------

@app.route('/dashboard/add/project', methods=['POST'])
def add_project():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute('INSERT INTO projects (user_id, title, description, tech_stack, metrics) VALUES (?, ?, ?, ?, ?)',
                 (session['user_id'], request.form['title'], request.form['description'], request.form['tech_stack'], request.form['metrics']))
    conn.commit()
    conn.close()
    flash('Project added.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard/edit/project/<int:item_id>', methods=['POST'])
def edit_project(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('projects', item_id, session['user_id']):
        flash("That item doesn't belong to you.", 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    conn.execute('UPDATE projects SET title = ?, description = ?, tech_stack = ?, metrics = ? WHERE id = ?',
                 (request.form['title'], request.form['description'], request.form['tech_stack'], request.form['metrics'], item_id))
    conn.commit()
    conn.close()
    flash('Project updated.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/dashboard/delete/project/<int:item_id>', methods=['POST'])
def delete_project(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('projects', item_id, session['user_id']):
        flash("That item doesn't belong to you.", 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    conn.execute('DELETE FROM projects WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    flash('Project removed.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/forgot-username', methods=['GET', 'POST'])
def forgot_username():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        conn = get_db_connection()
        user = conn.execute('SELECT username FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user:
            return render_template('forgot_username.html', username=user['username'])
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('forgot_username.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username', '').strip()
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user:
            conn.close()
            flash('Username not found.', 'danger')
            return render_template('forgot_password.html')

        if action == 'find_user':
            conn.close()
            return render_template('forgot_password.html', user=user, step=2)

        elif action == 'verify_answer':
            answer = request.form.get('security_answer', '').strip().lower()
            if user['security_answer'] == answer:
                conn.close()
                return render_template('forgot_password.html', user=user, step=3)
            else:
                conn.close()
                flash('Incorrect answer to security question.', 'danger')
                return render_template('forgot_password.html', user=user, step=2)

        elif action == 'reset_password':
            new_password = request.form.get('password')
            hashed = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user['id']))
            conn.commit()
            conn.close()
            flash('Password reset successful. You can now log in.', 'success')
            return redirect(url_for('login'))
            
        conn.close()
    return render_template('forgot_password.html', step=1)


@app.route('/dashboard/update/account', methods=['POST'])
def update_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    security_question = request.form.get('security_question', '')
    security_answer = request.form.get('security_answer', '').strip().lower()
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    # Verify current password if changing password or username
    if not check_password_hash(user['password'], current_password):
        conn.close()
        flash('Incorrect current password.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Update username and basic settings
        conn.execute('UPDATE users SET username = ?, email = ?, security_question = ?, security_answer = ? WHERE id = ?',
                     (username, email, security_question, security_answer, user_id))
        
        # If new password is provided, update it
        if new_password:
            hashed = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user_id))
            
        conn.commit()
        session['username'] = username
        flash('Account settings updated.', 'success')
    except sqlite3.IntegrityError:
        flash('Username is already taken by another user.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('dashboard'))


def _delete_user_files(user_id):
    """Remove all uploaded files for a user from disk."""
    conn = get_db_connection()
    profile = conn.execute('SELECT photo_path, resume_path FROM profiles WHERE user_id = ?', (user_id,)).fetchone()
    certs = conn.execute('SELECT file_path FROM certifications WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    if profile:
        if profile['photo_path']:
            try:
                os.remove(os.path.join(PHOTO_FOLDER, profile['photo_path']))
            except OSError:
                pass
        if profile['resume_path']:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, profile['resume_path']))
            except OSError:
                pass
    for cert in certs:
        if cert['file_path']:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, cert['file_path']))
            except OSError:
                pass


@app.route('/dashboard/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    confirm_password = request.form.get('confirm_delete_password', '')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password'], confirm_password):
        flash('Incorrect password. Account not deleted.', 'danger')
        return redirect(url_for('dashboard'))

    # Delete files from disk first, then remove DB record (cascade handles rest)
    _delete_user_files(user_id)
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    session.clear()
    flash('Your account and all associated data have been permanently deleted.', 'success')
    return redirect(url_for('index'))


@app.route('/profile/replace-resume', methods=['POST'])
def replace_resume():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    file = request.files.get('resume')
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('index'))
    if not allowed_file(file.filename, {'pdf'}):
        flash('Only PDF files are accepted for resume.', 'danger')
        return redirect(request.referrer or url_for('index'))

    conn = get_db_connection()
    profile = conn.execute('SELECT resume_path FROM profiles WHERE user_id = ?', (user_id,)).fetchone()

    # Delete old file
    if profile and profile['resume_path']:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, profile['resume_path']))
        except OSError:
            pass

    filename = secure_filename(f"resume_{user_id}_{file.filename}")
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    conn.execute('UPDATE profiles SET resume_path = ? WHERE user_id = ?', (filename, user_id))
    conn.commit()
    conn.close()
    flash('Resume updated successfully!', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/profile/replace-cert/<int:cert_id>', methods=['POST'])
def replace_cert(cert_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not owns_row('certifications', cert_id, session['user_id']):
        flash("That certificate doesn't belong to you.", 'danger')
        return redirect(request.referrer or url_for('index'))

    file = request.files.get('cert_file')
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('index'))
    if not allowed_file(file.filename, ALLOWED_CERT_EXTENSIONS):
        flash('Invalid file type.', 'danger')
        return redirect(request.referrer or url_for('index'))

    conn = get_db_connection()
    cert = conn.execute('SELECT file_path FROM certifications WHERE id = ?', (cert_id,)).fetchone()
    if cert and cert['file_path']:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, cert['file_path']))
        except OSError:
            pass

    filename = secure_filename(f"cert_{session['user_id']}_{cert_id}_{file.filename}")
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    conn.execute('UPDATE certifications SET file_path = ? WHERE id = ?', (filename, cert_id))
    conn.commit()
    conn.close()
    flash('Certificate file updated!', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
