# auth.py

from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User  # importwane na potrebitelite ot models.py
from extensions import db  # importvane na db-to extensions.py
import os

auth = Blueprint('auth', __name__)

# за профилнаснимка
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# регистъра
@auth.route('/register', methods=['POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('homePage'))

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    # валидиране на инпута
    if not username or not email or not password:
        session['show_register_modal'] = True
        session['register_error'] = 'Please fill out all fields.'
        return redirect(url_for('homePage'))

    # чекване дали юзъра и емйела са използвани
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        #фейл
        session['show_register_modal'] = True
        session['register_error'] = 'Username or email already exists.'
        return redirect(url_for('homePage'))

    # създаваен на нов юзър
    new_user = User(username=username, email=email)
    new_user.set_password(password)  # хашване на паролата
    db.session.add(new_user)
    db.session.commit()

    # логване автоматично
    login_user(new_user)

    # успешна регистрация
    session['show_register_modal'] = True
    session['register_message'] = 'Registration successful. You are now logged in.'
    return redirect(url_for('homePage'))

# логина
@auth.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('homePage'))

    username_or_email = request.form.get('username')
    password = request.form.get('password')

    # валидиране
    if not username_or_email or not password:
        session['show_login_modal'] = True
        session['login_error'] = 'Please fill out all fields.'
        return redirect(url_for('homePage'))

    # позволяване да се логне с емейл или юзър с парола
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()

    if user and user.check_password(password):
        login_user(user)

        # успешен логин
        session['show_login_modal'] = True
        session['login_message'] = 'Login successful. You are now logged in.'
        return redirect(url_for('homePage'))
    else:
        # фейл
        session['show_login_modal'] = True
        session['login_error'] = 'Invalid username or password.'
        return redirect(url_for('homePage'))

# логоут
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    #редикрет към хоум пейджа
    return redirect(url_for('homePage'))

# акоунт
@auth.route('/account')
@login_required
def account():
    return render_template('account.html', user=current_user)

# настройки
@auth.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

# история
@auth.route('/history')
@login_required
def history():
    return render_template('history.html', user=current_user)

# любими
@auth.route('/favourites')
@login_required
def favourites():
    return render_template('favourites.html', user=current_user)

# помощ страница
@auth.route('/help')
@login_required
def help():
    return render_template('help.html', user=current_user)

# ъпдейт на акаунта
@auth.route('/update_account', methods=['POST'])
@login_required
def update_account():
    user = current_user
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    profile_picture = request.files.get('profile_picture')

    # Validate input
    if not username or not email:
        flash('Username and Email are required.', 'error')
        return redirect(url_for('auth.account'))

    # чекване дали юзъра или паролата са използвани от друг юзър
    existing_user = User.query.filter(
        ((User.username == username) | (User.email == email)) &
        (User.id != user.id)
    ).first()

    if existing_user:
        flash('Username or email already exists.', 'error')
        return redirect(url_for('auth.account'))

    # ъпдейт на юзър и емйел
    user.username = username
    user.email = email

    # ъпдейт на парола
    if password:
        user.set_password(password)

    # качване на профилна
    if profile_picture and allowed_file(profile_picture.filename):
        filename = secure_filename(profile_picture.filename)
        # промяна на името ако трябва да нямаконфликт
        filename = f"user_{user.id}_{filename}"
        profile_picture_path = os.path.join('static/profile_pictures', filename)
        profile_picture.save(profile_picture_path)
        user.profile_picture = filename

    # комитват се промените в базата
    try:
        db.session.commit()
        flash('Account updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating your account.', 'error')

    return redirect(url_for('auth.account'))
