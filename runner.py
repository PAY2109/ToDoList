import os

from flask import Flask
from flask_script import Manager, Shell
from flask_migrate import MigrateCommand
from flask import render_template, request, redirect, url_for, flash, make_response, session
from flask_login import login_required, login_user,current_user, logout_user
from forms import ContactForm, LoginForm, RegisterForm, DeleteForm, NewNoteForm
from datetime import datetime
from flask_login import (LoginManager, UserMixin, login_required,
                         login_user, current_user, logout_user)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
manager = Manager(app)
db = SQLAlchemy(app)

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    slug = db.Column(db.String(255), nullable=False, unique=True)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    posts = db.relationship('Post', backref='category', cascade='all,delete-orphan')

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.name)


post_tags = db.Table('post_tags',
                     db.Column('post_id', db.Integer, db.ForeignKey('posts.id')),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'))
                     )


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow)
    category_id = db.Column(db.Integer(), db.ForeignKey('categories.id'))

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.title[:10])


class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    posts = db.relationship('Post', secondary=post_tags, backref='tags')
    def __repr__(self):
        return "<{}:{}>".format(self.id, self.name)


class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(1000), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.name)


class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    designation = db.Column(db.String(255), nullable=False)
    doj = db.Column(db.Date(), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, name, username, email, password_hash):
        self.name = name
        self.username = username
        self.email = email
        self.password_hash = password_hash

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer(), primary_key=True)
    owner = db.Column(db.String(50))
    data = db.Column(db.JSON)



def make_shell_context():
    return dict(app=app,  User=User, Post=Post, Tag=Tag, Category=Category,
                Employee=Employee, Feedback=Feedback)

manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@app.route('/')
def index():
    return render_template('index.html', name='Jerry')


@app.route('/user/<int:user_id>/')
def user_profile(user_id):
    return "Profile page of user #{}".format(user_id)


@app.route('/books/<genre>/')
def books(genre):
    return "All Books in {} category".format(genre)


@app.route('/login/', methods=['post', 'get'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('profile'))
        flash("Invalid username/password", 'error')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/register/', methods=['get', 'post'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = RegisterForm()
    if form.validate_on_submit():

        if form.password.data != form.repeat_password.data:
            flash("Passwords do not match", 'error')
            return redirect(url_for('register'))

        user_in_db = db.session.query(User).filter(User.username == form.username.data).first()
        if user_in_db:
            flash("User with this username already exists", 'error')
            return redirect(url_for('register'))

        name = form.name.data
        email = form.email.data
        password_hash = generate_password_hash(form.password.data)
        username = form.username.data
        user = User(name=name, email=email, password_hash = password_hash, username = username)
        db.session.add(user)
        db.session.commit()
        flash("Success", 'error')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/contact/', methods=['get', 'post'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data

        feedback = Feedback(name=name, email=email, message=message)
        db.session.add(feedback)
        db.session.commit()

        flash("Message Received", "success")
        return redirect(url_for('contact'))

    return render_template('contact.html', form=form)


@app.route('/cookie/')
def cookie():
    if not request.cookies.get('foo'):
        res = make_response("Setting a cookie")
        res.set_cookie('foo', 'bar', max_age=60*60*24*365*2)
    else:
        res = make_response("Value of cookie foo is {}".format(request.cookies.get('foo')))
    return res


@app.route('/delete-cookie/')
def delete_cookie():
    res = make_response("Cookie Removed")
    res.set_cookie('foo', 'bar', max_age=0)
    return res


@app.route('/article', methods=['POST', 'GET'])
def article():
    if request.method == 'POST':
        res = make_response("")
        res.set_cookie("font", request.form.get('font'), 60*60*24*15)
        res.headers['location'] = url_for('article')
        return res, 302

    return render_template('article.html')


@app.route('/visits-counter/')
def visits():
    if 'visits' in session:
        session['visits'] = session.get('visits') + 1
    else:
        session['visits'] = 1
    return "Total visits: {}".format(session.get('visits'))


@app.route('/delete-visits/')
def delete_visits():
    session.pop('visits', None)  # удаление посещений
    return 'Visits deleted'


@app.route('/session/')
def updating_session():
    res = str(session.items())

    cart_item = {'pineapples': '10', 'apples': '20', 'mangoes': '30'}
    if 'cart_item' in session:
        session['cart_item']['pineapples'] = '100'
        session.modified = True
    else:
        session['cart_item'] = cart_item
    return res


from flask_table import Table, Col
class ItemTable(Table):
    title = Col('Title')
    description = Col('Description')

@app.route('/profile/', methods=['GET'])
@login_required
def profile():
    notes = db.session.query(Note).filter(Note.owner == current_user.username).first()
    delete_form = DeleteForm()
    table_rows = []
    if notes and notes.data is not None:
        items = notes.data
        for key in items:
            table_rows.append(dict(title=key, description = items[key]))
    table = ItemTable(table_rows)
    return render_template('profile.html', note_table = table, delete_form = delete_form)

@app.route('/profile/', methods=['POST'])
@login_required
def delete_note():
    notes = db.session.query(Note).filter(Note.owner == current_user.username).first()
    delete_form = DeleteForm()
    if delete_form.validate_on_submit():
        if notes and notes.data is not None:
            items = notes.data
            title = delete_form.title.data
            del items[title]
            new_notes = Note(owner=current_user.username, data=items)
            db.session.delete(notes)
            db.session.add(new_notes)
            db.session.commit()
            flash("Successfully deleted", 'error')
            return redirect(url_for('profile'))
    return redirect(url_for('profile'))

@app.route('/new_note/', methods=['GET','POST'])
@login_required
def new_note():
    notes = db.session.query(Note).filter(Note.owner == current_user.username).first()
    new_note_form = NewNoteForm()
    if new_note_form.validate_on_submit():
        if notes and notes.data is not None:
            items = notes.data
            db.session.delete(notes)
        else:
            items = {}
        title = new_note_form.title.data
        description = new_note_form.description.data
        items[title] = description
        new_notes = Note(owner=current_user.username, data=items)
        db.session.add(new_notes)
        db.session.commit()
        flash("Successfully saved new note", 'error')
        return redirect(url_for('profile'))
    return render_template('new_note.html', add_form = new_note_form)

db.create_all()
if __name__ == '__main__':
    manager.run()