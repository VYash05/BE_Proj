from flask import render_template, url_for, flash, redirect, request, Flask
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm, PredictionForm
from flaskblog.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
import os


@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
def home():
	form = PredictionForm()
	source = form.s.data
	dest = form.d.data
	airline = form.a.data
	return render_template('home.html',title='Prediction',form=form)


@app.route("/airlines", methods=['GET', 'POST'])
def airlines():
    full_filename1 = os.path.join(app.config['UPLOAD_FOLDER'], 'United-Airlines.jpg')
    full_filename2 = os.path.join(app.config['UPLOAD_FOLDER'], 'american-airlines.jpg')
    full_filename3 = os.path.join(app.config['UPLOAD_FOLDER'], 'US_Airways.jpg')
    full_filename4 = os.path.join(app.config['UPLOAD_FOLDER'], 'jetblue.jpg')
    return render_template("airlines.html", user_image1 = full_filename1, user_image2 = full_filename2, user_image3 = full_filename3, user_image4 = full_filename4)
    

@app.route("/comparison", methods=['GET', 'POST'])
def comparison():
    return render_template('comparison.html')


@app.route("/airport", methods=['GET', 'POST'])
def airport():
    return render_template('airport.html')


@app.route("/origin", methods=['GET', 'POST'])
def origin():
    return render_template('origin.html')
	

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')