from flask import Flask, render_template, session, redirect, request, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

emailRegex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

passwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ThisIsSecret"
mysql = MySQLConnector(app,'login_and_registration')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create():
    if request.form['first_name'] == '':
        flash('First Name cannot be blank', 'error')
        return redirect('/')
    elif any(char.isdigit() for char in request.form['first_name']) == True:
        flash('Name cannot have numbers', 'error')
        return redirect('/')
    elif request.form['last_name'] == '':
        flash('Last Name cannot be blank', 'error')
        return redirect('/')
        return redirect('/')
    elif any(char.isdigit() for char in request.form['last_name']) == True:
         flash('Name cannot have numbers', 'error')
         return redirect('/')
    elif request.form['email'] == '':
        flash('Email cannot be blank', 'error')
        return redirect('/')
    elif not emailRegex.match(request.form['email']):
        flash('Invalid email address', 'error')
        return redirect('/')
    elif request.form['password'] == '':
        flash('Password cannot be blank', 'error')
        return redirect('/')
    elif len(request.form['password']) < 8:
        flash('Password must be greater than 8 characters', 'error')
        return redirect('/')
    elif not passwordRegex.match(request.form['password']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'error')
        return redirect('/')
    elif request.form['password'] != request.form['confirm_password']:
        flash('Password and confirm password must be the same', 'error')
        return redirect('/')
    else:
        email = request.form['email']
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        print pw_hash
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
        data = {'first_name': request.form['first_name'], 'last_name': request.form['last_name'], 'email': request.form['email'], 'pw_hash': pw_hash}
        mysql.query_db(query, data)

        user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
        query_data = { 'email': email }
        user = mysql.query_db(user_query, query_data)
        session['user']=user[0]
        return render_template('welcome.html')

@app.route('/login', methods=['POST'])
def login():
    if request.form['email'] == '':
        flash('Email cannot be blank', 'error')
        return redirect('/')
    elif request.form['password'] == '':
        flash('Password cannot be blank', 'error')
        return redirect('/')
    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = { 'email': email }
    user = mysql.query_db(user_query, query_data)
    if bcrypt.check_password_hash(user[0]['password'], password):
        return render_template('welcome.html')
    else:
        flash('Please make sure the email address matches the password', 'error')
        return redirect('/')

app.run(debug=True)
