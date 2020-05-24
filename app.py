from flask import Flask, render_template, request, session, logging, url_for, redirect
from flask import flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_sqlalchemy import SQLAlchemy

#library for password hashing
# from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from passlib.hash import pbkdf2_sha256
import onetimepass
import pyqrcode
import os
import base64
from io import BytesIO

#creating SQL database
engine = ("mysql+pymysql://root:shreesh@localhost/mydatabase")
                       #(mysql+pymysql://username:password@localhost/databasename)

app = Flask(__name__)
app.config['SECRET_KEY']='1234567shreesh'
app.config['SQLALCHEMY_DATABASE_URI'] = engine
db = SQLAlchemy(app)
lm = LoginManager(app)

class users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    username = db.Column(db.String(255))
    encrytpassword = db.Column(db.String(255))
    otp = db.Column(db.String(255))

    def __init__(self, **kwargs):
        super(users, self).__init__(**kwargs)
        if self.otp is None:
            # generate a random secret
            self.otp = base64.b32encode(os.urandom(10)).decode('utf-8')

    # def password(self,password):
    #     self.encrytpassword = generate_password_hash(password)
    #
    # def verify_password(self, password):
    #     return str(check_password_hash(self.encrytpassword, password))

    def get_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo'.format(self.username, self.otp)


    def verify_totp(self,token):
        return onetimepass.valid_totp(token,self.otp)

@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return users.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("home.html")

#register form
@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('/'))
    if request.method == 'POST':
        name=request.form.get("name")
        username=request.form.get("username")
        password=request.form.get("password")
        confirm=request.form.get("confirm")

        #encrypting password
        secure_password = pbkdf2_sha256.hash(password)
        if password==confirm:
            user = users.query.filter_by(username=username).first()
            if user is not None:
                flash("Already registered","danger")
                return render_template("register.html")
            user = users(name=name, username=username, encrytpassword=secure_password)
            db.session.add(user)
            db.session.commit()

            #redirect to 2FA page, passing username in session
            session['username'] = user.username
            flash("Congrats! You're almost done.","success")
            return redirect(url_for('two_factor'))
        else:
            flash(u"Password does not match.","danger")
            return render_template("register.html")

    #putting values into SQL
    return render_template("register.html")

@app.route('/two_factor', methods=["GET","POST"])
def two_factor():
    if 'username' not in session:
        return redirect(url_for('register'))
    user = users.query.filter_by(username=session['username']).first()
    if user is None:
        flash("No such user exists!","danger")
        return render_template("register.html")
    return render_template("two_factor.html"), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = users.query.filter_by(username=session['username']).first()

    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        token = request.form.get("token")

        user = users.query.filter_by(username=username).first()
        if(user is None):
            flash("No such user exists!","danger")
            return render_template("login.html")
        else:
            if pbkdf2_sha256.verify(password,user.encrytpassword):
                if user.verify_totp(token) :
                    session.log=True
                    login_user(user)
                    flash("You're logged in.","success")
                    return render_template("newworld.html")
                else:
                    return render_template("login.html")
            else:
                flash("Incorrect Paassword","danger")
                return render_template("login.html")

    return render_template("login.html")

@app.route("/logout", methods=["GET","POST"])
def logout():
    logout_user()
    flash("You're logged out","success")
    return render_template("login.html")

db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
