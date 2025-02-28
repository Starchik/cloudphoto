import os
import threading
import zipfile
from io import BytesIO
from datetime import datetime
import requests

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
import exifread
import re
from datetime import datetime, timezone
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100))
    media = db.relationship('Media', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    capture_date = db.Column(db.DateTime)

def parse_date_from_filename(filename):
    match = re.search(r'''
        [A-Za-z]          
        (\d)              
        (\d{2})(\d{2})    
        [-_]?             
        (\d{2})(\d{2})(\d{2})  
    ''', filename, re.VERBOSE | re.IGNORECASE)

    if match:
        try:
            decade_year = int(match.group(1))
            year = 2020 + decade_year
            month = int(match.group(2))
            day = int(match.group(3))
            hour = int(match.group(4))
            minute = int(match.group(5))
            second = int(match.group(6))
            return datetime(year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            pass

    match = re.search(r'''
        (\d{4})           
        (\d{2})(\d{2})    
        [-_]?
        (\d{2})(\d{2})(\d{2})  
    ''', filename, re.VERBOSE)

    if match:
        try:
            year = int(match.group(1))
            month = int(match.group(2))
            day = int(match.group(3))
            hour = int(match.group(4))
            minute = int(match.group(5))
            second = int(match.group(6))
            return datetime(year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            pass

    match = re.search(r'''
        (\d{2})           
        (\d{2})(\d{2})    
        [-_]?
        (\d{2})(\d{2})(\d{2})  
    ''', filename, re.VERBOSE)

    if match:
        try:
            year = int(match.group(1)) + 2000
            month = int(match.group(2))
            day = int(match.group(3))
            hour = int(match.group(4))
            minute = int(match.group(5))
            second = int(match.group(6))
            return datetime(year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            pass

    return None

def get_exif_date(filepath, filename):
    try:
        if filepath.lower().endswith(('.heic', '.heif')):
            with open(filepath, 'rb') as f:
                tags = exifread.process_file(f)
                date_str = tags.get('EXIF DateTimeOriginal', None)
                if date_str:
                    return datetime.strptime(str(date_str), "%Y:%m:%d %H:%M:%S").replace(tzinfo=None)
            return None

        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)
            date_str = tags.get('EXIF DateTimeOriginal', None)
            if date_str:
                return datetime.strptime(str(date_str), "%Y:%m:%d %H:%M:%S").replace(tzinfo=None)

        with Image.open(filepath) as img:
            exif_data = img._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag in ['DateTimeOriginal', 'DateTimeDigitized']:
                        return datetime.strptime(value, "%Y:%m:%d %H:%M:%S").replace(tzinfo=None)
    except Exception as e:
        print("Error reading EXIF:", e)
    return parse_date_from_filename(filename)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('gallery'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('gallery'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/gallery', methods=['GET'])
@login_required
def api_gallery():
    media_list = Media.query.filter_by(user_id=current_user.id).all()
    data = []
    for media in media_list:
        data.append({
            'id': media.id,
            'filename': media.filename,
            'file_type': media.file_type,
            'thumbnail_url': url_for('thumbnail', media_id=media.id, _external=True),
            'image_url': url_for('image', media_id=media.id, _external=True)
        })
    return jsonify(data)

@app.route('/gallery')
@login_required
def gallery():
    order = func.coalesce(Media.capture_date, Media.uploaded_at).desc()
    media_list = Media.query.filter_by(
        user_id=current_user.id
    ).order_by(order).all()
    return render_template('gallery.html', medias=media_list)

def get_file_type(filename):
    if not filename or '.' not in filename:
        return 'unknown'
    ext = filename.rsplit('.', 1)[1].lower()
    image_ext = {'png', 'jpg', 'jpeg', 'gif', 'heic', 'heif', 'webp'}
    video_ext = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
    if ext in image_ext:
        return 'image'
    elif ext in video_ext:
        return 'video'
    return 'unknown'

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in {
        'png', 'jpg', 'jpeg', 'gif', 'heic', 'heif', 'webp',
        'mp4', 'mov', 'avi', 'mkv', 'webm'
    }

def process_upload(files_data, user_id):
    with app.app_context():
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        upload_count = 0
        for filename, file_data in files_data:
            if not filename or '.' not in filename:
                continue
            if not allowed_file(filename):
                continue
            file_type = get_file_type(filename)
            if file_type == 'unknown':
                continue

            filepath = os.path.join(user_folder, filename)
            try:
                with open(filepath, 'wb') as f:
                    f.write(file_data)
            except Exception as e:
                print("Error saving file", filename, e)
                continue

            capture_date = get_exif_date(filepath, filename) if file_type == 'image' else None

            new_media = Media(
                filename=filename,
                file_type=file_type,
                user_id=user_id,
                capture_date=capture_date or datetime.now(timezone.utc).replace(tzinfo=None)
            )
            db.session.add(new_media)
            upload_count += 1

        if upload_count > 0:
            db.session.commit()
        else:
            print("No valid files uploaded")

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file selected", "danger")
            return redirect(request.url)

        files = request.files.getlist('file')
        files_data = []
        for file in files:
            if file.filename == '':
                flash("Empty file name", "warning")
                continue

            filename = secure_filename(file.filename)
            if not filename or '.' not in filename:
                flash("Invalid file name", "warning")
                continue

            if not allowed_file(filename):
                flash("File type not allowed", "warning")
                continue

            file.seek(0)
            file_data = file.read()
            files_data.append((filename, file_data))

        threading.Thread(target=process_upload, args=(files_data, current_user.id)).start()
        flash("Uploading files in the background", "info")
        return redirect(url_for('gallery'))
    return render_template('upload.html')

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    file_type = get_file_type(filename)
    if file_type == 'unknown':
        return jsonify({"error": "Invalid file type"}), 400

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    filepath = os.path.join(user_folder, filename)
    file.save(filepath)
    capture_date = get_exif_date(filepath, filename) if file_type == 'image' else None

    new_media = Media(
        filename=filename,
        file_type=file_type,
        user_id=current_user.id,
        capture_date=capture_date or datetime.now(timezone.utc).replace(tzinfo=None)
    )
    db.session.add(new_media)
    db.session.commit()

    return jsonify({
        "status": "success",
        "filename": filename,
        "file_type": file_type,
        "url": url_for('image', media_id=new_media.id, _external=True)
    }), 201

Image.MAX_IMAGE_PIXELS = None

@app.route('/thumbnail/<int:media_id>')
@login_required
def thumbnail(media_id):
    media = Media.query.get_or_404(media_id)
    if media.user_id != current_user.id:
        abort(403)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    original_path = os.path.join(user_folder, media.filename)
    thumb_filename = f"thumb_{media.filename}"
    thumb_path = os.path.join(user_folder, thumb_filename)

    if not os.path.exists(thumb_path):
        try:
            with Image.open(original_path) as img:
                img.thumbnail((300, 300))
                img.save(thumb_path, quality=45)
        except Exception as e:
            flash("Error creating thumbnail: " + str(e), "danger")
            return redirect(url_for('gallery'))
    return send_from_directory(user_folder, thumb_filename)

@app.route('/image/<int:media_id>')
@login_required
def image(media_id):
    media = Media.query.get_or_404(media_id)
    if media.user_id != current_user.id:
        abort(403)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    return send_from_directory(user_folder, media.filename, as_attachment=False)

@app.route('/delete-selected', methods=['POST'])
@login_required
def delete_selected():
    selected = request.json.get('selected', [])
    for media_id in selected:
        media = Media.query.get(media_id)
        if media and media.user_id == current_user.id:
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
            file_path = os.path.join(user_folder, media.filename)
            thumb_path = os.path.join(user_folder, f"thumb_{media.filename}")
            if os.path.exists(file_path):
                os.remove(file_path)
            if os.path.exists(thumb_path):
                os.remove(thumb_path)
            db.session.delete(media)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/delete/<int:media_id>', methods=['POST'])
@login_required
def delete_media(media_id):
    media = Media.query.get_or_404(media_id)
    if media.user_id != current_user.id:
        abort(403)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    file_path = os.path.join(user_folder, media.filename)
    thumb_path = os.path.join(user_folder, f"thumb_{media.filename}")
    if os.path.exists(file_path):
        os.remove(file_path)
    if os.path.exists(thumb_path):
        os.remove(thumb_path)
    db.session.delete(media)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/download', methods=['POST'])
@login_required
def download():
    selected = request.form.getlist('selected')
    if not selected:
        flash("No files selected", "warning")
        return redirect(url_for('gallery'))

    memory_file = BytesIO()
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
    try:
        with zipfile.ZipFile(memory_file, 'w') as zf:
            for media_id in selected:
                media = Media.query.get(media_id)
                if media and media.user_id == current_user.id:
                    file_path = os.path.join(user_folder, media.filename)
                    if os.path.exists(file_path):
                        zf.write(file_path, media.filename)
                    else:
                        flash(f"File not found: {media.filename}", "warning")
        memory_file.seek(0)
        return send_file(
            memory_file,
            download_name=f"media_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            as_attachment=True,
            mimetype="application/zip"
        )
    except Exception as e:
        flash("Error creating zip file: " + str(e), "danger")
        return redirect(url_for('gallery'))

def create_app():
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=1488, debug=True)