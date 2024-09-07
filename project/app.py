from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import os
from dotenv import load_dotenv
from forms import RegisterForm, LoginForm  
from layers.sanitization import SanitizationManager
from layers.integrity import IntegrityCheckManager
from layers.request_processing import RequestProcessingLayer


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_key')  # Load secret key from .env

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/my_flask_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Home route
@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    errors = []

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

         # Run integrity checks
        try:
            data = {"username": username, "password": password}
            IntegrityCheckManager(data).run_integrity_checks()
        except ValueError as e:
            errors.append(str(e))
            return render_template('login.html', form=form, errors=errors)

        # Detect SQL injection in username and password
        try:
            SanitizationManager(username, is_sensitive=True).detect_sql_injection()
            SanitizationManager(password, is_sensitive=True).detect_sql_injection()
        except ValueError as e:
            errors.append(str(e))

        if errors:
            return render_template('login.html', form=form, errors=errors)

        # Request Processing Layer
        try:
            request_processor = RequestProcessingLayer(db.session)
            user_data = request_processor.process_login(username, password)
            session['username'] = user_data['username']  # Assuming user_data is a dictionary
            return redirect(url_for('home'))
        except ValueError as e:
            print(f"Login error: {e}")  # Debugging output
            errors.append(str(e))
            return render_template('login.html', form=form, errors=errors)

          # Query the database for the user
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            errors.append("Invalid credentials")
            return render_template('login.html', form=form, errors=errors)

    return render_template('login.html', form=form, errors=errors)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    errors = []

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        # Check if passwords match
        if password != confirm_password:
            print(f"Password: {password}, Confirm Password: {confirm_password}")  # Debugging line
            errors.append("Password mismatch")
            return render_template('register.html', form=form, errors=errors)

             # Run integrity checks
        try:
            data = {"username": username, "password": password}
            IntegrityCheckManager(data).run_integrity_checks()
        except ValueError as e:
            errors.append(str(e))
            return render_template('register.html', form=form, errors=errors)

        # Detect SQL injection in username, password and confirm_password
        try:
            SanitizationManager(username, is_sensitive=True).detect_sql_injection()
            SanitizationManager(password, is_sensitive=True).detect_sql_injection()
            SanitizationManager(confirm_password, is_sensitive=True).detect_sql_injection()
        except ValueError as e:
            errors.append(str(e))

        if errors:
            return render_template('register.html', form=form, errors=errors)

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            errors.append("Username already exists.")
            return render_template('register.html', form=form, errors=errors)

        # If no errors, proceed with registration
        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            errors.append("An error occurred while trying to register the user.")
            return render_template('register.html', form=form, errors=errors)

        return redirect(url_for('login'))

    return render_template('register.html', form=form, errors=errors)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
