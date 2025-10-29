from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo, ValidationError
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib
import os
import secrets
import re
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

'''

# Databaza
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    def __repr__(self):
        return f'<User {self.username}>'


class LoginAttempt(db.Model):
    """
    Tabuľka pre sledovanie pokusov o prihlásenie (brute-force ochrana)
    """
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)

# BEZPEČNOSTNÉ FUNKCIE
# ========================

def generate_salt(length=16):
    """
    Generuje kryptograficky bezpečný salt.
    Salt je náhodný reťazec, ktorý sa pridáva k heslu pred hashovaním.
    """
    return secrets.token_hex(length)


def hash_password_with_salt(password, salt, iterations=100000):
    """
    Hashuje heslo pomocou PBKDF2 (Password-Based Key Derivation Function 2).

    Používame primitívy:
    - PBKDF2 s SHA-256
    - Salt pre každého používateľa
    - Veľký počet iterácií (100 000) pre spomalenie brute-force útokov

    Args:
        password: heslo v plaintext
        salt: salt (hex string)
        iterations: počet iterácií PBKDF2

    Returns:
        hash hesla (hex string)
    """
    # Konvertujeme salt z hex na bytes
    salt_bytes = bytes.fromhex(salt)

    # PBKDF2 s SHA-256
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',  # hash algoritmus
        password.encode('utf-8'),  # heslo ako bytes
        salt_bytes,  # salt
        iterations,  # počet iterácií
        dklen=64  # dĺžka výsledného kľúča v bytoch
    )

    return password_hash.hex()


def verify_password(password, stored_hash, salt):
    """
    Overí, či zadané heslo zodpovedá uloženému hashi.
    """
    computed_hash = hash_password_with_salt(password, salt)
    return computed_hash == stored_hash


def check_password_strength(password):
    """
    Kontroluje zložitosť hesla.

    Kritéria:
    1. Minimálna dĺžka 8 znakov (odporúčaný štandard)
    2. Aspoň jedno veľké písmeno (zvyšuje kombinatorickú zložitosť)
    3. Aspoň jedno malé písmeno
    4. Aspoň jedna číslica
    5. Aspoň jeden špeciálny znak (!@#$%^&*()_+-=[]{}|;:,.<>?)

    Returns:
        (bool, str): (True/False, chybová správa)
    """
    if len(password) < 8:
        return False, "Heslo musí mať aspoň 8 znakov."

    if not re.search(r'[A-Z]', password):
        return False, "Heslo musí obsahovať aspoň jedno veľké písmeno."

    if not re.search(r'[a-z]', password):
        return False, "Heslo musí obsahovať aspoň jedno malé písmeno."

    if not re.search(r'\d', password):
        return False, "Heslo musí obsahovať aspoň jednu číslicu."

    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return False, "Heslo musí obsahovať aspoň jeden špeciálny znak (!@#$%^&* atď.)."

    return True, ""


def is_common_password(password):
    """
    Kontroluje, či heslo nie je v zozname bežných/slovníkových hesiel.

    Pre jednoduchosť máme malý zoznam. V produkčnom systéme by sme použili
    väčšiu databázu (napr. top 10000 hesiel z databázových únikov).
    """
    common_passwords = {
        'password', 'heslo', '123456', '12345678', 'qwerty', 'abc123',
        'password1', 'Password1', 'Password123', '1234567890',
        'admin', 'letmein', 'welcome', 'monkey', '1234', '12345',
        'password123', 'qwerty123', 'admin123', 'root', 'test',
        '111111', '123123', 'dragon', 'master', 'sunshine',
        'princess', 'football', 'iloveyou', 'shadow', 'michael'
    }

    # Kontrolujeme case-insensitive
    return password.lower() in common_passwords


def check_brute_force(username, ip_address, max_attempts=5, window_minutes=15):
    """
    Kontroluje, či používateľ/IP adresa neuskutočňuje brute-force útok.

    Ochrana:
    - Maximálne 5 neúspešných pokusov za 15 minút
    - Sledujeme podľa username aj IP adresy

    Args:
        username: meno používateľa
        ip_address: IP adresa
        max_attempts: maximálny počet pokusov
        window_minutes: časové okno v minútach

    Returns:
        (bool, str): (True ak je blokovaný, chybová správa)
    """
    time_threshold = datetime.utcnow() - timedelta(minutes=window_minutes)

    # Počítame neúspešné pokusy v časovom okne
    recent_attempts = LoginAttempt.query.filter(
        LoginAttempt.username == username,
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp > time_threshold,
        LoginAttempt.success == False
    ).count()

    if recent_attempts >= max_attempts:
        return True, f"Príliš veľa neúspešných pokusov. Skúste znova o {window_minutes} minút."

    return False, ""


def log_login_attempt(username, ip_address, success):
    """
    Zaznamenáva pokus o prihlásenie do databázy.
    """
    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        success=success
    )
    db.session.add(attempt)
    db.session.commit()

# FORMULÁRE
# ========================

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password',
                                    validators=[InputRequired(), EqualTo('password',
                                    message='Heslá sa musia zhodovať.')])
    submit = SubmitField('Register')

# ROUTING
# =================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/login', methods=['GET','POST'])
def login():
    '''
        TODO: doimplementovat
    '''

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        ip_address = request.remote_addr

        # Kontrola brute-force
        is_blocked, error_msg = check_brute_force(username, ip_address)
        if is_blocked:
            flash(error_msg, 'error')
            return render_template('login.html', form=form)

        # Hľadáme používateľa v databáze
        user = User.query.filter_by(username=username).first()

        if user and verify_password(password, user.password_hash, user.salt):
            # Úspešné prihlásenie
            log_login_attempt(username, ip_address, success=True)
            login_user(user)
            return redirect(url_for('home'))
        else:
            # Neúspešné prihlásenie
            log_login_attempt(username, ip_address, success=False)
            flash('Nesprávne meno alebo heslo.', 'error')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])  
def register():
    '''
        TODO: doimplementovat
    '''

    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Kontrola, či používateľ už existuje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Používateľské meno už existuje.', 'error')
            return render_template('register.html', form=form)

        # Kontrola zložitosti hesla
        is_strong, error_msg = check_password_strength(password)
        if not is_strong:
            flash(error_msg, 'error')
            return render_template('register.html', form=form)

        # Kontrola slovníkových hesiel
        if is_common_password(password):
            flash('Toto heslo je príliš bežné. Zvoľte si bezpečnejšie heslo.', 'error')
            return render_template('register.html', form=form)

        # Vytvorenie nového používateľa
        salt = generate_salt()
        password_hash = hash_password_with_salt(password, salt)

        new_user = User(
            username=username,
            password_hash=password_hash,
            salt=salt
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Registrácia úspešná! Môžete sa prihlásiť.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


# INICIALIZÁCIA
# ===================

with app.app_context():
    # Odstránime starú databázu a vytvoríme novú
    db.drop_all()
    db.create_all()

    # Vytvoríme testovacieho používateľa
    salt = generate_salt()
    password_hash = hash_password_with_salt('Test123!', salt)
    test_user = User(username='test', password_hash=password_hash, salt=salt)
    db.session.add(test_user)
    db.session.commit()

    print("Databáza vytvorená!")
    print("Testovací používateľ: username='test', password='Test123!'")

if __name__ == '__main__':
    app.run(port=1337)