import os
import bcrypt
import string
import random
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import desc

# --- CONFIGURACIÓN DE LA APLICACIÓN ---
app = Flask(__name__)
# Obtenemos la ruta absoluta del directorio del script para que funcione en cualquier sistema
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'una-clave-secreta-muy-dificil-de-adivinar' # ¡Cambia esto en producción!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

# --- MODELOS DE LA BASE DE DATOS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    pastes = db.relationship('Paste', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    slug = db.Column(db.String(10), unique=True, nullable=False)
    views = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Función para cargar un usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Función para generar un slug único
def generate_slug(length=7):
    while True:
        slug = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        if not Paste.query.filter_by(slug=slug).first():
            return slug

# --- RUTAS DE LA APLICACIÓN ---

@app.route('/')
def home():
    latest_pastes = Paste.query.order_by(desc(Paste.id)).limit(10).all()
    return render_template('home.html', pastes=latest_pastes)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Ese nombre de usuario ya está en uso. Por favor, elige otro.', 'error')
            return redirect(url_for('registro'))
            
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Cuenta creada con éxito! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
        
    return render_template('auth_form.html', form_type='registro')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login incorrecto. Verifica tu usuario y contraseña.', 'error')
            
    return render_template('auth_form.html', form_type='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/crear', methods=['GET', 'POST'])
@login_required
def crear_paste():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        if not title or not content:
            flash('El título y el contenido no pueden estar vacíos.', 'error')
            return redirect(url_for('crear_paste'))
            
        slug = generate_slug()
        new_paste = Paste(title=title, content=content, slug=slug, author=current_user)
        db.session.add(new_paste)
        db.session.commit()
        
        return redirect(url_for('ver_paste', slug=new_paste.slug))
        
    return render_template('create_paste.html')

@app.route('/p/<string:slug>')
def ver_paste(slug):
    paste = Paste.query.filter_by(slug=slug).first_or_404()
    
    viewed_pastes = session.get('viewed_pastes', [])
    is_author = current_user.is_authenticated and current_user.id == paste.user_id

    if not is_author and paste.id not in viewed_pastes:
        paste.views += 1
        viewed_pastes.append(paste.id)
        session['viewed_pastes'] = viewed_pastes
        db.session.commit()

    full_url = url_for('ver_paste', slug=paste.slug, _external=True)
    
    return render_template('paste_view.html', paste=paste, full_url=full_url)

# --- INICIALIZACIÓN ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)