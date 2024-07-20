from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@app.route('/')
def home():
    success_message = session.pop('success_message', None)
    error_message = session.pop('error_message', None)
    return render_template('index.html', success_message=success_message, error_message=error_message)

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        session['error_message'] = "Email already registered."
        return redirect(url_for('home'))

    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    session['success_message'] = "Registered successfully. Please login."
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    
    session['error_message'] = "Invalid email or password."
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f'<img src="/static/22.jpg" alt="Welcome Image">'
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
