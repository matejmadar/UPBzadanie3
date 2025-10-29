from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

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

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()
    
    test_user = User(username='test', password='test')
    db.session.add(test_user)
    db.session.commit()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')


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

        if username == 'test' and password == 'test':
            login_user(User.query.filter_by(username=username).first())
            return redirect(url_for('home'))

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
        
        if username == 'test' and password == 'test':
            return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)