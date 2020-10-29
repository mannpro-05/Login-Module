import secrets
from PIL import Image
import os
from flask import render_template, url_for, flash, redirect, request
from My_Project import app,db,bcrypt, mail
from My_Project.forms import RegistrationForm, LoginForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm, ResendConfirmationLink
from My_Project.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message


@app.route("/")
@app.route("/home")
def home():
    count = User.query.filter_by(confirm='yes').count()
    return render_template(r'home.html', title='Login Form', count = count)


@app.route("/about")
def about():
    return render_template(r'about.html', title='About')


def send_confirm_email(user):

    token=user.get_reset_token()

    msg=Message('Confirm Your Email',sender='mannprajapati567@gmail.com',
                recipients=[user.email])


    msg.body=f'''To confirm your email click on the link provided below.
{url_for('confirm_email', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        user = User.verify_reset_token(token)
        user.confirm='yes'
        db.session.commit()
        flash('Email has been confirmed!','success')
    except:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('login'))
    return redirect(url_for('login'))

def user_register(user):

    msg=Message('New User',sender='mannprajapati567@gmail.com',
                recipients=['mannprajapati567@gmail.com'])


    msg.body=f'''A new user with Email : { user.email } and Username : { user.username } has registered!
    '''
    mail.send(msg)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        send_confirm_email(user)
        flash('Your account has been created!', 'success')
        user_register(user)
        return redirect(url_for('login'))
    return render_template(r'register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user_email = User.query.filter_by(email=form.email.data).first()
        user_username = User.query.filter_by(username=form.email.data).first()
        if (user_email and bcrypt.check_password_hash(user_email.password, form.password.data)):
            if  user_email.confirm=='yes':
                login_user(user_email)
                return redirect(url_for('account'))
            else:
                flash('Please Confirm Your Email', 'danger')

        elif (user_username and bcrypt.check_password_hash(user_username.password, form.password.data)):
            if user_username.confirm=='yes':
                login_user(user_username)
                return redirect(url_for('account'))
            else:
                flash('Please Confirm Your Email', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template(r'login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    picture_fn = random_hex + '.jpg'
    picture_path = os.path.join(app.root_path, 'static/profiles', picture_fn)
    form_picture.save(picture_path)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)


    return picture_fn

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file= save_picture(form.picture.data)
            current_user.image_file = picture_file

        current_user.username=form.username.data
        current_user.email=form.email.data
        db.session.commit()
        flash('Your account has been updated!','success')
        return redirect(url_for('account'))
    elif request.method=='GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file= url_for('static', filename='profiles/' + current_user.image_file)
    return render_template(r'account.html', title='Account', image_file=image_file, form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='mannprajapati567@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An emal has been send with instructions to reset your password!','success')
        return redirect(url_for('login'))
    return render_template(r'reset_request.html', title='Reset password', form=form, legend='Reset Password')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been Updated!', 'success')
        return redirect(url_for('home'))
    return render_template(r'reset_token.html', title='Reset Password', form=form)

@app.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ResendConfirmationLink()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_confirm_email(user)
        flash('An email has been send with a confirmation link.','success')
        return redirect(url_for('login'))
    return render_template(r'reset_request.html', title='Reset password', form=form, legend='Resend Confirmation Link')

@app.route('/remove_pic', methods=['GET','post'])
def remove_pic():
    form=UpdateAccountForm()
    current_user.image_file = 'default.jpg'
    db.session.commit()
    if request.method=='GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file= url_for('static', filename='profiles/default.jpg')
    return redirect(url_for('account', image_file=image_file))

@app.route('/delete_profile')
def delete_account():
    user=User.query.filter_by(email=current_user.email).first()
    User.query.filter_by(email=user.email).delete()
    db.session.commit()
    flash('Profile has been removed successfully','success')
    return redirect(url_for('logout'))