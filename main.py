#encoding: utf-8

from datetime import datetime
import json
import os
import sys
import time
from threading import Thread

from flask import abort
from flask import flash
from flask import Flask
from flask import jsonify
from flask import make_response
from flask import request
from flask import render_template
from flask import send_file
from flask import send_from_directory
from flask import url_for
from flask import Response
from flask_mail import Mail
from flask_mail import Message
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired

import util


app = Flask(__name__)
app.secret_key = os.urandom(32)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'files')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
dbfile = 'mysql://dbuser@127.0.0.1:3306/database?charset=utf8'
app.config['SQLALCHEMY_DATABASE_URI'] = dbfile

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True

#app.config['SECRET_KEY'] = 'a!@#$%^z'

app.config.update(
    DEBUG=True,
    MAIL_DEBUG = True,
    MAIL_SERVER = 'smtp.example.com',
    MAIL_PORT = 465,
    MAIL_USE_SSL = True,
    MAIL_USERNAME = 'mailuser',
    MAIL_PASSWORD = 'mailpass',
    MAIL_DEFAULT_SENDER = 'admin@daoliname.com'
)
mail = Mail(app)
db = SQLAlchemy(app)


class TimeModel(object):
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)

    def __init__(self, **kwargs):
        if kwargs.get('created_at') is None:
            self.created_at = datetime.utcnow()


class User(db.Model, TimeModel):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    identities = db.relationship('Identity', backref='user', lazy=True)

    def __init__(self, username=None, **kwargs):
        if username is not None:
            self.username = username
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username

    def generate_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def check_token(token, email):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except BadSignature:
            return False
        except SignatureExpired:
            return False
        except Exception:
            return False

        user = User.query.get(data["id"])
        if not user:
            return False

        if not user.enabled:
            user.enabled = True
            user.updated_at = datetime.utcnow()
            db.session.commit()

        idt = id_manager.get_email(user.id)
        if not idt.app_activated:
            idt.app_activated = True
            idt.updated_at = datetime.utcnow()
            db.session.commit()

        return True


class Application(db.Model, TimeModel):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    master = db.Column(db.Boolean, default=False, nullable=False)

    @classmethod
    def get(cls, id):
        app = cls.query.filter_by(id=id).first()
        if not app:
            raise AppNotFound()
        return app


class Identity(db.Model, TimeModel):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    app_id = db.Column(db.Integer,
        db.ForeignKey('application.id'), nullable=False)
    app = db.relationship('Application', lazy='select')
    app_value = db.Column(db.String(255), nullable=False)
    app_pubp = db.Column(db.Text, nullable=False)
    app_pubap = db.Column(db.Text, nullable=False)
    app_pubq = db.Column(db.Text, nullable=False)
    app_pubqq = db.Column(db.Text, nullable=False)
    app_key = db.Column(db.Text, nullable=False)
    app_activated = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route("/")
def index():
    return "DaoliName Main Page!"


@app.route("/app")
def app_list():
    return app_manager.get_all()


class AppManager(object):

    EMAIL = 'email'

    def get_all(self, filter=None):
        if filter is None:
            filter = {}

        query = Application.query.filter_by(deleted=False)
        if 'master' in filter:
            query = query.filter_by(master=filter['master'])

        return query.all()


class IdentityManager(object):

    def get_by_filter(self, filters=None):
        if filters is None:
            filters = {}

        query = Identity.query.filter_by(**filters)
        return query.first()

    def get_all_by_filter(self, filters=None):
        if filters is None:
            filters = {}

        query = Identity.query.filter_by(**filters)
        return query.all()

    def get_email(self, user_id, active=None):
        query = Identity.query.filter_by(user_id=user_id)
        if active is not None:
            query = query.filter_by(app_activated=active)
        query = query.join(Application)
        result = query.filter(Application.name == AppManager.EMAIL).\
            first()
        if not result:
            raise UserNotFound()
        return result

    @staticmethod
    def to_primitive(body, **kwargs):
        idt = None
        if body:
            idt = Identity()
            idt.app_id = body["app_id"]
            for name in ("app_value", "app_pubp", "app_pubq",
                         "app_pubqq", "app_pubap", "app_key"):
                setattr(idt, name, body.get(name, ""))

            user_id = kwargs.get("user_id")
            if user_id:
                idt.user_id = user_id

        return idt


class UserNotFound(Exception): pass


class UserExists(Exception): pass


class NoAuthentication(Exception): pass


class NoActivated(Exception): pass


class AppNotFound(Exception): pass


class GenerateKeyFailure(Exception): pass


def get_cache_key(key, value, app_id):
    return '#'.join(map(str, [value, key, app_id]))


class UserManager(object):

    def _parse_user(self, body):
        user = UserManager.to_primitive(body)
        apps = []
        for app in body.get('apps', []):
            app_obj = IdentityManager.to_primitive(app)
            if app_obj is not None:
                apps.append(app_obj)
 
        if not user or not apps:
            raise UserNotFound()

        if not user.username:
            user.username = apps[0].app_value

        return user, apps

    def _validate(self, user, apps):
        db_user = User.query.filter_by(
            username=user.username, deleted=False).first()
        if db_user:
            raise UserExists()
        for app in apps:
            db_app = Application.get(app.app_id)
            if db_app.master:
                query = Identity.query.filter_by(
                    app_id=db_app.id, app_value=app.app_value)
                if query.first():
                    raise IdentityExists()

    def register(self, body):
        app_list = app_manager.get_all(filter={'master': True})
        user, apps = self._parse_user(body)
        self._validate(user, apps)
        try:
            db.session.add(user)
            db.session.flush()
        except Exception as e:
            db.session.rollback()
            raise
        try:
            for app in apps:
                app.user_id = user.id
                db.session.add(app)
            db.session.flush()
            db.session.commit()
        except Exception as e:
            db.session.delete(user)
            db.session.rollback()
            raise
        return user

    def authenticate(self, body):
        user, apps = self._parse_user(body)
        query = User.query.filter_by(password=user.password, deleted=False)
        query = query.join(Identity).filter(
                Identity.app_id == apps[0].app_id,
                Identity.app_value == apps[0].app_value,
                Identity.app_activated == True).\
                join(Application).filter(Application.master == True)
        result = query.first()
        if result is None:
            raise NoAuthentication()
        elif not result.enabled:
            raise NoActivated()

        return result


    @staticmethod
    def to_primitive(body):
        user = None
        username = body.get("username")
        password = body.get("password")
        if body and username and password:
            user = User()
            user.username = username
            user.password = util.hash256(password)
            # Set user deactivated
            user.enabled = False
        return user

    @staticmethod
    def to_json(user):
        apps = []
        for idt in user.identities:
            app = {}
            app['id'] = idt.id
            app['app_id'] = idt.app_id
            app['app_value'] = idt.app_value
            apps.append(app)
        return {"id": user.id, "username": user.username, "apps": apps}


user_manager = UserManager()

id_manager = IdentityManager()

app_manager = AppManager()


@app.route("/login", methods=['POST'])
def login():
    body = request.get_json()
    try:
        user = user_manager.authenticate(body)
    except NoAuthentication as e:
        return jsonify({'errno': 401, 'errmsg': 'User or Password Error!'})
    except NoActivated as e:
        return jsonify({'errno': 403, 'errmsg': 'Email not activated!'})
    else:
        return jsonify({'errno': 0, 'body': {
            'user': json.dumps(user_manager.to_json(user))}})


def send_mail_async(msg):
    with app.app_context():
        mail.send(msg)


def send_mail(idt, user):
    msg = Message("DaoliName Activate")
    msg.recipients = [idt.app_value]
    token = user.generate_token()
    msg.html = render_template("activate.html",
                               email=idt.app_value,
                               token=token)
    Thread(target=send_mail_async, args=[msg]).start()


@app.route("/register", methods=['POST'])
def register():
    body = request.get_json()
    try:
        user = user_manager.register(body)
        send_mail(id_manager.get_email(user.id), user)
    except UserExists, IdentityExists:
        return jsonify({'errno': 409,
                        'errmsg': "User or Identity already exists!"})
    except UserNotFound:
        return jsonify({'errno': 404,
                        'errmsg': "User or Identity required!"})
    except Exception as e:
        return jsonify({'errno': 501, 'errmsg': str(e)})
    else:
        return jsonify({'errno': 0, 'body': {
            'user': json.dumps(user_manager.to_json(user))}})


@app.route("/activate/<token>")
def activate(token):
    email = request.args.get('email')
    if not email:
        return 'Invalid URL!'

    if User.check_token(token, email):
        return render_template("confirm.html", email=email)
    else:
        return 'Activate Failed: url not found or already expired.'


@app.route("/ibc", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        user = request.headers.get('X-Auth-User')
        if not user:
            return jsonify({'errno': 401, 'errmsg': 'No Authentication.'})

        f = request.files['file']
        if not f or f.filename == '':
            return jsonify({'errno': 1, 'errmsg': 'File could not empty.'})

        secure_name = str(int(time.time() * 1000)) + "-"
        secure_name += util.secure_filename(f.filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))

        return jsonify({'errno': 0, 'url': url_for('get', name=secure_name)})

    return render_template('upload.html')


@app.route("/ibc/<name>", methods=['GET', 'POST'])
def get(name):
    if request.method == 'POST':
        user = request.headers.get('X-Auth-User')
        if not user:
            return jsonify({'errno': 401, 'errmsg': 'No Authentication.'})

        path = os.path.join(app.config['UPLOAD_FOLDER'], name)
        if os.path.exists(path):
            return send_from_directory(app.config['UPLOAD_FOLDER'],
                                       name, as_attachment=True)
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], name)
        if os.path.exists(path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], name)

    abort(404)


@app.route("/pubkey/<name>")
def getpubkey(name):
    auth_id = request.headers.get('X-Auth-ID', 1)
    idt = id_manager.get_by_filter({'app_id': auth_id, 'app_value': name})
    if not idt or not idt.app_pubq or not idt.app_pubp:
        return jsonify({'errno': 404,
                        'errmsg': "User Identity not register!"})
    return jsonify({'errno': 0, 'body': {
        'pubp': idt.app_pubp, 'pubap': idt.app_pubap,
        'pubq': idt.app_pubq, 'pubaq': idt.app_pubaq
    }})


@app.errorhandler(404)
def page_not_found(error):
    return jsonify({'errno': 404, 'errmsg': str(error)})


@app.errorhandler(405)
def page_not_allowed(error):
    return jsonify({'errno': 405, 'errmsg': str(error)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
