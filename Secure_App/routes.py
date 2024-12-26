from flask import Flask, render_template, request, redirect
from markupsafe import escape
import sqlite3
from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField
from flask_wtf import FlaskForm

app = Flask(__name__)
app.secret_key = 'hamada'  # Required for session management
csrf = CSRFProtect(app)  # Enable CSRF protection
# Form for transfer (Flask-WTF)
class TransferForm(FlaskForm):
    recipient = StringField('Recipient')
    amount = StringField('Amount')
    submit = SubmitField('Transfer')

# Insecure database connection (no parameterization)

def get_user_from_db(username, password):
    # Use parameterized queries to prevent SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Parameterized query with placeholders
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))

    # Fetch the first matching user
    user = cursor.fetchone()
    
    # Close the connection
    conn.close()
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
        recipient = form.recipient.data
        amount = form.amount.data
        
        with open('transactions.txt', 'a') as f:
            f.write(f"Transfer to: {recipient}, Amount: {amount}\n")
        
        success = True

    return render_template('transfer.html', form=form, success=success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure login logic (No hashing or validation)
        # TODO: Use secure password hashing to store and verify passwords
        # TODO: Validate user input to prevent SQL Injection
        user = get_user_from_db(username,password)
        print(user)
        if user:  # Plaintext password comparison (No hashing)
            # TODO: Replace with secure password validation using hashed passwords
            return redirect('/')
        else:
            return 'Invalid credentials!', 400

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
