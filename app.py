from datetime import datetime
import os 
import random
import string
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask import request, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


ALLOWED_EXTENSIONS =  set(['png','jpg','jpeg','gif', 'webm'])


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'some_really_long_random_string_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///images.sqlite3'


db = SQLAlchemy(app)
class images(db.Model):
   id = db.Column('image_id', db.Integer, primary_key = True)
   date = db.Column(db.String)
   ipaddr = db.Column(db.String)  
   filename = db.Column(db.String)

class users(db.Model):
    __tablename__ = 'users'
    id        = db.Column(db.Integer, primary_key = True)
    username   = db.Column(db.String)
    pw_hash   = db.Column(db.String)


class banned(db.Model):
   id = db.Column('banned', db.Integer, primary_key = True)
   date = db.Column(db.String)
   ip = db.Column(db.String)
db.create_all()


def check_auth(username, password):
    if (db.session.query(users).filter_by(username=username).all()):
        usersce = db.session.query(users).filter_by(username=username).first()
        pw_hash = usersce.pw_hash
        if (check_password_hash(pw_hash, password)):
            return True
        else:
            return False
    else:
        return False


@app.route('/login', methods=['GET', 'POST'])

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def show_frontpage():
        return render_template('index.html')

@app.route('/add_image', methods = ['GET', 'POST'])
def add_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
		# if user does not select file, browser also
		# submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            ipaddr = request.environ['REMOTE_ADDR']
            if db.session.query(banned).filter_by(ip=ipaddr).all():
               flash('You are banned, fuck off')
            else:   
               extension = os.path.splitext(file.filename)[1]
               filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
               ffile = filename + extension
               postdate = datetime.now()
               flname= str(ffile)
               pdate = str(postdate)
               ipdr = str(ipaddr)
               newImg = images(date = pdate, ipaddr = ipdr, filename = flname)
               db.session.add(newImg)
               db.session.commit()
               file.save(os.path.join("static/useruploads/", ffile))
               flash('/content/' + ffile)
               return redirect(request.url)
    return render_template('index.html')


@app.route('/content/<variable>', methods=['GET'])
def getfile(variable):
    print variable
    ext = os.path.splitext(variable)[1]
    print ext
    if ext == ".webm":
            return render_template("sfile-webm.html",getfile=variable)
    else:
        return render_template("sfile.html",getfile=variable)


@app.route('/admin', methods=['GET','POST'])
@requires_auth
def showposts():
	posts = get_posts()
	posts = reversed(posts)

	return render_template('admin.html', posts = posts)

@app.route('/bans', methods=['GET','POST'])
@requires_auth
def showbans():
   bans = get_bans()
   bans = reversed(bans)

   return render_template('bans.html', bans = bans)

@app.route('/delete/<variable>', methods=['GET'])
@requires_auth
def delfile(variable):
    os.remove("static/useruploads/" + variable)
    images.query.filter_by(filename=variable).delete()
    db.session.commit()
    return redirect("/admin")

@app.route('/ban/<variable>', methods=['GET'])
@requires_auth
def banip(variable):
   date=datetime.now()
   ip=variable
   ban=banned(date=date, ip=ip)
   db.session.add(ban)
   db.session.commit()
   return redirect("/admin")

@app.route('/unban/<variable>', methods=['GET'])
@requires_auth
def unban(variable):
   ip=str(variable)
   banned.query.filter_by(ip=ip).delete()
   db.session.commit()
   return redirect("/bans")

@app.route('/changepassword', methods = ['GET', 'POST'])
@requires_auth
def changepassword():
    if request.method == 'POST':
        if not request.form['name'] or not request.form['password1'] or not request.form['password2'] or not request.form['oldpassword']:
            flash('Please enter all the fields', 'error')
        else:
            oldpassword = request.form['oldpassword']
            username = request.form['name']
            password1 = request.form['password1']
            password2 = request.form['password2']
            if (password1 == password2):
                password = password1

                if check_auth(username, oldpassword):
                    change_password(username, password)
                    flash("Record successfully updated!")
                else:
                    flash("wrong username or password")
            else:
                flash('Passwords must match')
    return render_template('changepassword.html')

    


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def get_posts():
    return db.session.query(images).all()
def get_bans():
   return db.session.query(banned).all()

def usercreate(name, password):
	pw_hash = generate_password_hash(password)
	user = users(username=name, pw_hash=pw_hash)
	db.session.add(user)
	db.session.commit()

def change_password(username, password):
    name=username
    db.session.query(users).filter_by(username=username).delete()
    db.session.commit()
    usercreate(name, password)

if __name__ == '__main__':
    app.run()



