from flask import Flask, render_template, request, redirect, session
from markupsafe import escape
import sqlite3
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt=Bcrypt(app)
app.secret_key = 'hamada'  # Required for session management
csrf = CSRFProtect(app)  # Enable CSRF protection
# Form for transfer (Flask-WTF)
class TransferForm(FlaskForm):
    recipient = StringField('Recipient',validators=[DataRequired()])
    amount = StringField('Amount', validators=[
        DataRequired(),
        Regexp(r'^\d+(\.\d{1,2})?$', message="Amount must be a valid number.")
    ])
    submit = SubmitField('Transfer')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = StringField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$', message="Password must contain letters and numbers.")
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = StringField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

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
        return None
    if (bcrypt.check_password_hash(user[2], password)):
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

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    form = TransferForm()
    success = False
    if form.validate_on_submit():  # CSRF token is checked automatically
        recipient = escape(form.recipient.data)
        amount = escape(form.amount.data)
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {recipient}, Amount: {amount}\n")
        
        success = True

    return render_template('transfer.html', form=form, success=success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    success=False
    if form.validate_on_submit():
        username = escape(form.email.data)
        password = escape(form.password.data)
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
    print('In register')
    if form.validate_on_submit():
        username = escape(form.email.data)
        password = escape(form.password.data)
        print(f"Registering user: {username}")  # Debugging statement
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
