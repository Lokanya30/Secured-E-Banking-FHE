from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import tenseal as ts

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
db = SQLAlchemy(app)

# Generate encryption context
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.global_scale = 2**40

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    encrypted_balance = db.Column(db.LargeBinary)

    @property
    def balance(self):
        if self.encrypted_balance:
            encrypted = ts.ckks_vector_from(context, self.encrypted_balance)
            return round(encrypted.decrypt()[0], 2)
        return 0.0

    @balance.setter
    def balance(self, value):
        encrypted = ts.ckks_vector(context, [float(value)])
        self.encrypted_balance = encrypted.serialize()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            new_user.balance = 0.0  # This will use the encrypted setter
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        amount = float(request.form['amount'])
        recipient_username = request.form['recipient']
        sender = User.query.get(session['user_id'])
        recipient = User.query.filter_by(username=recipient_username).first()
        if recipient and sender.balance >= amount:
            # Perform homomorphic operations
            sender_balance = ts.ckks_vector_from(context, sender.encrypted_balance)
            recipient_balance = ts.ckks_vector_from(context, recipient.encrypted_balance)
            transfer_amount = ts.ckks_vector(context, [amount])
            
            new_sender_balance = sender_balance - transfer_amount
            new_recipient_balance = recipient_balance + transfer_amount
            
            sender.encrypted_balance = new_sender_balance.serialize()
            recipient.encrypted_balance = new_recipient_balance.serialize()
            
            db.session.commit()
            flash('Transfer successful.', 'success')
        else:
            flash('Transfer failed. Check recipient and balance.', 'error')
    return render_template('transfer.html')

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        amount = float(request.form['amount'])
        user = User.query.get(session['user_id'])
        current_balance = ts.ckks_vector_from(context, user.encrypted_balance)
        deposit_amount = ts.ckks_vector(context, [amount])
        new_balance = current_balance + deposit_amount
        user.encrypted_balance = new_balance.serialize()
        db.session.commit()
        flash(f'Deposited ${amount:.2f} successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('deposit.html')

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        amount = float(request.form['amount'])
        user = User.query.get(session['user_id'])
        if user.balance >= amount:
            current_balance = ts.ckks_vector_from(context, user.encrypted_balance)
            withdraw_amount = ts.ckks_vector(context, [amount])
            new_balance = current_balance - withdraw_amount
            user.encrypted_balance = new_balance.serialize()
            db.session.commit()
            flash(f'Withdrawn ${amount:.2f} successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Insufficient funds.', 'error')
    return render_template('withdraw.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)