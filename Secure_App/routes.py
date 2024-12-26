from flask import Flask, render_template, request, redirect
from markupsafe import escape
import sqlite3
from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
import logging
from cryptography.fernet import Fernet
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
# Form for transfer (Flask-WTF)
class TransferForm(FlaskForm):
    recipient = StringField('Recipient')
    amount = StringField('Amount')
    submit = SubmitField('Transfer')

class RegisterForm(FlaskForm):
    email = StringField('Email')
    password = StringField('Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email')
    password = StringField('Password')
    submit = SubmitField('Login')

logging.info('Forms created')

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
    print(user)
    if not user:
        logging.error("No user found with username: %s", username)
        return None
    if (bcrypt.check_password_hash(user[2], password)):
        logging.info("User %s logged in successfully", username)
        return user



@app.route('/')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']

        # Escape user input to prevent XSS before saving
        sanitized_comment = escape(user_comment)

        # Save the sanitized comment to the file
        with open('Secure_App/comments.txt', 'a') as f:  # Adjusted path to use forward slashes
            f.write(sanitized_comment + "\n")
    
    # Read all comments
    with open('Secure_App/comments.txt', 'r') as f:
        comments = [line.strip() for line in f]  # Strip newline characters
    
    # Render the template with escaped comments
    return render_template('comments.html', comments=comments)

@app.route('/transactions')
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
                except Exception as e:
                    # Handle decryption errors or malformed lines
                    print(f"Error decrypting line: {line}, error: {e}")
                    continue

    return render_template('transactions.html', transactions=transactions)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    form = TransferForm()
    success = False
    if form.validate_on_submit():  # CSRF token is checked automatically
        recipient = form.recipient.data
        amount = form.amount.data
        
        encrypted_recipient = cipher_suite.encrypt(recipient.encode()).decode()
        encrypted_amount = cipher_suite.encrypt(amount.encode()).decode()
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {encrypted_recipient}, Amount: {encrypted_amount}\n")
        
        success = True

    return render_template('transfer.html', form=form, success=success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    success=False
    if form.validate_on_submit():
        username = form.email.data
        password = form.password.data
        user = get_user_from_db(username,password)
        if user:
            success=True
            return redirect('/')
        else:
            success=False
            return 'Invalid credentials!', 400

    return render_template('login.html',form=form,success=success)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    success=False
    if form.validate_on_submit():
        username = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return 'User already exists!', 400
        if len(password) < 8:
            return 'Password must be at least 8 characters!', 400
        if '@' not in username:
            return 'Invalid Email address!', 400
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        cursor.execute(query, (username, hashed_password))
        conn.commit()
        conn.close()
        success=True

        return redirect('/login')
    return render_template('register.html',form=form, success=success)



if __name__ == "__main__":
    app.run(debug=True)
