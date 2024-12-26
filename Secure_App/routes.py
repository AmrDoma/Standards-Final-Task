from flask import Flask, render_template, request, redirect, session
from markupsafe import escape
import sqlite3
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField,TextAreaField,PasswordField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from cryptography.fernet import Fernet
import re

def detect_sql_injection(input_string):
    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
        r"\b(SELECT|UPDATE|DELETE|INSERT|DROP|ALTER|CREATE|REPLACE|TRUNCATE|EXEC)\b",  # SQL keywords
    ]
    for pattern in sql_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# Function to detect XSS patterns
def detect_xss(input_string):
    xss_patterns = [
        r"(<|%3C)([^s]*s)+cript.*(>|%3E)",  # <script> tag
        r"(<|%3C).*iframe.*(>|%3E)",  # <iframe> tag
        r"(<|%3C).*img.*src.*(>|%3E)",  # <img> tag with src attribute
    ]
    for pattern in xss_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False


def load_key():
    return open("secret.key", "rb").read()

# Initialize the cipher suite with the loaded key
logging.basicConfig(filename='app.log', level=logging.INFO)
key = load_key()
logging.info
cipher_suite = Fernet(key)
logging.info('Key loaded')

# Configure the logging module

app = Flask(__name__)
logging.info('App started')
bcrypt=Bcrypt(app)
logging.info('bcrypt started')
app.secret_key = 'hamada'  # Required for session management
logging.info('secret key set')
csrf = CSRFProtect(app)  # Enable CSRF protection
logging.info('csrf enabled')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
)

# Form for transfer (Flask-WTF)
class TransferForm(FlaskForm):
    recipient = StringField('Recipient',validators=[DataRequired()])
    amount = StringField('Amount', validators=[
        DataRequired(),
        Regexp(r'^\d+(\.\d{1,2})?$', message="Amount must be a valid number.")
    ])
    submit = SubmitField('Transfer')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(message="This field is required"), Email(message="Invalid Email address.")])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$', message="Password must contain letters and numbers.")
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message="Invalid Email address.")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment')
    submit = SubmitField('Submit')

logging.info('Forms created')
failed_login_attempts = {}

# Insecure database connection (no parameterization)

def get_user_from_db(username, password):
    # Use parameterized queries to prevent SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Parameterized query with placeholders
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    # Fetch the first matching user
    user = cursor.fetchone()
    
    # Close the connection
    conn.close()
    if not user:
        logging.error("No user found with username: %s", username)
        return None
    if (bcrypt.check_password_hash(user[2], password)):
        logging.info("User %s logged in successfully", username)
        return user
    else:
        return None



@app.route('/')
@limiter.limit("1/second", override_defaults=False)
def home():
    logging.info('Home page accessed')
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
@limiter.limit("1/second", override_defaults=False)
def comment():
    logging.info('Comment page accessed')
    comments = []
    form=CommentForm()
    success=False
    if form.validate_on_submit():
        user_comment = form.comment.data
        sanitized_comment = escape(user_comment)
        logging.info('Comment: %s', sanitized_comment)
        with open('Secure_App/comments.txt', 'a') as f:
            f.write(sanitized_comment + "\n")
        success=True
    with open('Secure_App/comments.txt', 'r') as f:
        comments = [line.strip() for line in f]
    return render_template('comments.html', comments=comments, form=form, success=success)

@app.route('/transactions')
@limiter.limit("1/second", override_defaults=False)
def view_transactions():
    transactions = []
    with open('transactions.txt', 'r') as f:
        for line in f:
            if line.strip():  # Skip empty lines
                try:
                    parts = line.split(", ")
                    encrypted_recipient = parts[0].split(": ")[1]
                    encrypted_amount = parts[1].split(": ")[1]
                    decrypted_recipient = cipher_suite.decrypt(encrypted_recipient.encode()).decode()
                    decrypted_amount = cipher_suite.decrypt(encrypted_amount.encode()).decode()
                    transactions.append({
                        'recipient': decrypted_recipient,
                        'amount': decrypted_amount
                    })
                    logging.info('Transaction: %s', transactions)
                except Exception as e:
                    # Handle decryption errors or malformed lines
                    print(f"Error decrypting line: {line}, error: {e}")
                    continue

    return render_template('transactions.html', transactions=transactions)

@app.route('/transfer', methods=['GET', 'POST'])
@limiter.limit("1/second", override_defaults=False)
def transfer():
    form = TransferForm()
    success = False
    if form.validate_on_submit():  # CSRF token is checked automatically
        recipient = escape(form.recipient.data)
        amount = escape(form.amount.data)
        
        encrypted_recipient = cipher_suite.encrypt(recipient.encode()).decode()
        encrypted_amount = cipher_suite.encrypt(amount.encode()).decode()
        logging.info('Transfer to: %s, Amount: %s', encrypted_recipient, encrypted_amount)
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {encrypted_recipient}, Amount: {encrypted_amount}\n")
        
        success = True

    return render_template('transfer.html', form=form, success=success)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("1/second", override_defaults=False)
def login():
    form = LoginForm()
    success=False
    if form.validate_on_submit():
        username = escape(form.email.data).lower()
        password = escape(form.password.data)

        if detect_sql_injection(username) or detect_sql_injection(password):
            logging.error("SQL Injection attempt detected for user %s from IP %s", username, request.remote_addr)
            return render_template('login.html', form=form, success=success)
        
        if detect_xss(username) or detect_xss(password):
            logging.error("XSS attempt detected for user %s from IP %s", username, request.remote_addr)
            return render_template('login.html', form=form, success=success)

        user = get_user_from_db(username,password)
        if user:
            success=True
            if username in failed_login_attempts:
                del failed_login_attempts[username]
            return redirect('/')
        else:
            success=False
            logging.warning("Failed login attempt for user %s from IP %s", username, request.remote_addr)
            # Increment the failed login attempt counter
            if username not in failed_login_attempts:
                failed_login_attempts[username] = 0
            failed_login_attempts[username] += 1
            
            # Trigger an alert if the threshold is exceeded
            if failed_login_attempts[username] > 5:
                logging.error("Too many failed login attempts for user %s from IP %s", username, request.remote_addr)
                # Optionally, you can take additional actions here, such as blocking the IP or notifying an admin
            return 'Invalid credentials!', 400

    return render_template('login.html',form=form,success=success)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("1/second", override_defaults=False)
def register():
    form = RegisterForm()
    success=False
    if form.validate_on_submit():
        username = escape(form.email.data).lower()
        password = escape(form.password.data)
        hashed_password = bcrypt.generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            logging.info("User already exists: %s", username)
            return 'User already exists!', 400
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        logging.info('Inserting user: %s', username)
        cursor.execute(query, (username, hashed_password))
        conn.commit()
        conn.close()
        success=True

        return redirect('/login')
    return render_template('register.html',form=form, success=success)



if __name__ == "__main__":
    app.run(debug=True)
