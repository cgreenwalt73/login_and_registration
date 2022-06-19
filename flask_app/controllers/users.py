from flask_app import app
from flask import redirect, render_template, request, session
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt= Bcrypt(app)

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register_user():
    if not User.validate_user_registration(request.form):
        return redirect('/')
    else:
        hash_pass = bcrypt.generate_password_hash(request.form['password'])
        data= {
            'first_name' : request.form['first_name'],
            'last_name' : request.form['last_name'],
            'email' : request.form['email'].lower(),
            'password' : hash_pass
        }
        session['user_id'] = User.add_user(data)
        return redirect('/user_page')

@app.route('/user_page')
def show_user_page():
    user_to_display= User.get_user_by_id(session['user_id'])
    return render_template('user_page.html', user_to_display=user_to_display)

@app.route('/login', methods=['POST'])
def user_login():
    if not User.validate_user_login(request.form):
        return redirect('/')
    else:
        return redirect('/user_page')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
