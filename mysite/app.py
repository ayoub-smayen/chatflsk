
# A very simple Flask Hello World app for you to get started with...

"""

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(userid):
	try:
		return models.User.get(models.User.id == userid)
	except models.DoesNotExist:
		return None
@app.before_request
def before_request():

	g.db1 = models.DATABASE
	g.db1.connect()
	g.user = current_user


@app.after_request
def after_request(response):

	g.db1.close()
	return response


@app.route('/register', methods = ('GET','POST'))
def register():
	form = forms.RegisterForm()
	if form.validate_on_submit():
		flash("Congrats, Registered Successfully!", "success")
		models.User.create_user(
			username = form.username.data,
			email = form.email.data,
			password = form.password.data
		)
		return redirect(url_for('index'))
	return render_template('register.html', form = form)


@app.route('/login', methods = ('GET', 'POST'))
def login():
	form = forms.LoginForm()
	if form.validate_on_submit():
		try:
			user = models.User.get(models.User.email == form.email.data)
		except models.DoesNotExist:
			flash("Your email or password does not match", "error")
		else:
			if check_password_hash(user.password, form.password.data):
				login_user(user)

				flash("You have been logged in", "success")
				return redirect(url_for('index'))
			else:
				flash("Your email or password does not match", "error")
	return render_template('login.html', form = form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash("You have been logged out.")
	return redirect(url_for('login'))


@app.route('/new_post', methods = ('GET', 'POST'))
@login_required
def post():
	form = forms.PostForm()
	if form.validate_on_submit():
		models.Post.create(user = g.user.id,
							content = form.content.data.strip())
		flash("Message Posted: Thanks!", "success")
		return redirect(url_for('index'))
	return render_template('post.html', form = form)



@app.route('/')
def index():
	stream = models.Post.select().limit(100)
	return render_template('stream.html', stream = stream)

@app.route('/stream')
@app.route('/stream/<username>')
def stream(username = None):
	template = 'stream.html'
	if username and (current_user.is_anonymous or username != current_user.username):
		try:
			user = models.User.select().where(models.User.username**username).get()
		except models.DoesNotExist:
			abort(404)
		else:
			stream = user.posts.limit(100)
	else:
		stream = current_user.get_stream().limit(100)
		user = current_user
	if username:
		template = 'user_stream.html'
	return render_template(template, stream = stream, user = user)

@app.route('/post/<int:post_id>')
def view_post(post_id):
	posts = models.Post.select().where(models.Post.id == post_id)
	if posts.count() == 0:
		abort(404)
	return render_template('stream.html', stream = posts)

@app.route('/follow/<username>')
@login_required
def follow(username):
	try:
		to_user = models.User.get(models.User.username**username)
	except models.DoesNotExist:
		abort(404)
	else:
		try:
			models.Relationship.create(
				from_user = g.user._get_current_object(),
				to_user = to_user
				)
		except models.IntegrityError:
			pass
		else:
			flash("You are now following {}".format(to_user.username), "success")
	return redirect(url_for('stream', username=to_user.username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
	try:
		to_user = models.User.get(models.User.username**username)
	except models.DoesNotExist:
		abort(404)
	else:
		try:
			models.Relationship.get(
				from_user = g.user._get_current_object(),
				to_user = to_user
				).delete_instance()
		except models.IntegrityError:
			pass
		else:
			flash("You have unfollowed {}".format(to_user.username), "success")
	return redirect(url_for('stream', username=to_user.username))

@app.errorhandler(404)
def not_found(error):
	return render_template('404.html'), 404

"""




from flask import Flask, redirect, render_template, request, url_for, jsonify, make_response,flash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
#from marshmallow_sqlalchemy import ModelSchema
from marshmallow import fields
from flask import ( g,abort)
from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, login_user, logout_user,
							login_required, current_user)


from flask import request
from flask import abort
from flask import redirect, url_for
from flask import session
from flask import jsonify
from flask import make_response, request, current_app, g
from flask_socketio import SocketIO, send, emit, disconnect
from datetime import datetime
from datetime import timedelta
from functools import update_wrapper
from sqlalchemy import *
from sqlalchemy.sql import func
from passlib.hash import sha256_crypt
import boto3
import requests
import json

from flask_session import Session
#from app import db
from sqlalchemy.inspection import inspect
#import forms
#import models

#app = Flask(__name__)
app = Flask(__name__)
app.config["DEBUG"] = True
ma= Marshmallow(app)
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="phpfayoub",
    password="123456789az",
    hostname="phpfayoub.mysql.pythonanywhere-services.com",
    databasename="phpfayoub$chatapp",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
socketio = SocketIO(app)
Session(app)

def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, str):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, str):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

class Comment(db.Model):

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))


@app.route('/test')
def hello_world():
    return 'Hello from Flask!'

@app.route("/c", methods=["GET", "POST"])
def index1():
    if request.method == "GET":
        return render_template("main_page.html", comments=Comment.query.all())

    comment = Comment(content=request.form["contents"])
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('index1'))









class Serializer(object):

    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]

class User(db.Model, Serializer):
    __tablename__ = 'users2'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True, nullable=False)
    username = db.Column(db.String(25), index=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    pic_path = db.Column(db.String(150), nullable=True)

    def __init__(self, email, username, password, pic_path):
        self.email = email
        self.username = username
        self.password = password
        self.pic_path = pic_path

class Message(db.Model, Serializer):
    __tablename__ = 'messages'
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    messageTxt = db.Column(db.Text, nullable=False)
    dateTime = db.Column(db.DateTime, index=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, messageTxt, dateTime, sender_id):
        self.messageTxt = messageTxt
        self.dateTime = dateTime
        self.sender_id = sender_id








class Product(db.Model):
    __tablename__ = "products"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20))
    productDescription = db.Column(db.String(100))
    productBrand = db.Column(db.String(20))
    price = db.Column(db.Integer)

    def create(self):
      db.session.add(self)
      db.session.commit()
      return self
    def __init__(self,title,productDescription,productBrand,price):
        self.title = title
        self.productDescription = productDescription
        self.productBrand = productBrand
        self.price = price
    def __repr__(self):
        return '' % self.id

class ProductSchema(ma.Schema):
    class Meta:
        model = Product
        sqla_session = db.session
    id = fields.Number(dump_only=True)
    title = fields.String(required=True)
    productDescription = fields.String(required=True)
    productBrand = fields.String(required=True)
    price = fields.Number(required=True)

@app.route('/products', methods = ['GET'])
def index2():
    get_products = Product.query.all()
    product_schema = ProductSchema(many=True)
    products = product_schema.dump(get_products)
    return make_response(jsonify({"product": products}))
@app.route('/products/<id>', methods = ['GET'])
def get_product_by_id(id):
    get_product = Product.query.get(id)
    product_schema = ProductSchema()
    product = product_schema.dump(get_product)
    return make_response(jsonify({"product": product}))
@app.route('/products/<id>', methods = ['PUT'])
def update_product_by_id(id):
    data = request.get_json()
    get_product = Product.query.get(id)
    if data.get('title'):
        get_product.title = data['title']
    if data.get('productDescription'):
        get_product.productDescription = data['productDescription']
    if data.get('productBrand'):
        get_product.productBrand = data['productBrand']
    if data.get('price'):
        get_product.price= data['price']
    db.session.add(get_product)
    db.session.commit()
    product_schema = ProductSchema(only=['id', 'title', 'productDescription','productBrand','price'])
    product = product_schema.dump(get_product)
    return make_response(jsonify({"product": product}))
@app.route('/products/<id>', methods = ['DELETE'])
def delete_product_by_id(id):
    get_product = Product.query.get(id)
    db.session.delete(get_product)
    db.session.commit()
    return make_response("",204)
@app.route('/products', methods = ['POST'])
def create_product():
    data = request.get_json()
    product_schema = ProductSchema()
    product = product_schema.load(data)
    result = product_schema.dump(product.create())
    return make_response(jsonify({"product": result}),200)












@app.route('/', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        session.pop('theUser', None)
        user = User.query.filter_by(username=request.form['username']).first()
        if user is not None:
            if sha256_crypt.verify(request.form['password'], user.password):
                session['theUser'] = request.form['username']
                return redirect(url_for('chat_view'))
    return render_template('/home/login.html')


@app.before_request
def before_request():
    g.user = None
    if 'theUser' in session:
        g.user = session['theUser']


@app.route('/getsession')
def getsession():
    if 'theUser' in session:
        return session['theUser']

    return 'Not logged in!'

'''
Description: Pops user from the session, logging them out
Input: None
Return Type: Redirects user to login page
'''
@app.route('/logout')
def dropsession():
    session.pop('theUser', None)
    return redirect(url_for('login_view'))

'''
Description: Render the main chat view here from templates, if a user is logged in
Input: None
Return Type: HTML, a view generated by render_template()
'''
@app.route('/chat')
def chat_view():
    if g.user:
        users = User.query.all()
        query = db.session.query(Message, User).filter(Message.sender_id==User.id)
        return render_template('/home/index.html', currUser=g.user, users=users, query=query)
    return redirect(url_for('login_view'))

'''
Description: Renders the API view from template, if a user is logged in
Input: None
Return Type: HTML, a view generated by render_template()
'''
@app.route('/api')
def api_view():
    if g.user:
        loginURL = 'http://smartplug.host/api/v1/auth/login'
        loginData = {'email': SMARTPLUG_API_EMAIL, 'password': SMARTPLUG_API_PASSWORD}
        tokenResponse = requests.post(loginURL, data=loginData)
        token = tokenResponse.json().get('token')

        lightURL = 'http://smartplug.host/api/v1/devices/%s/light' % SMARTPLUG_MAC
        headers = {'Token-Authorization': token}
        lightResponse = requests.get(lightURL, headers = headers)
        lightData = lightResponse.json()

        return render_template('/home/api.html', lightData=lightData, currUser=g.user)
    return redirect(url_for('login_view'))

'''
Description: Render the user profile here from templates
Input: user_id
Return Type: HTML, a view generated by render_template()
'''
@app.route('/user/<string:username>')
def user_profile(username):
    if g.user:
        user = User.query.filter_by(username=username).first()
        return render_template('/home/userprofile.html', user=user)
    return redirect(url_for('login_view'))

'''
Description: Retrieve a collection of users from the database, if the user is logged in
Input: None
Return Type: JSON, a JSON object containing the list of users
'''
@app.route('/users')
def getUsers():
    if g.user:
        usersList = User.query.all()
        return jsonify(User.serialize_list(usersList))
    return redirect(url_for('login_view'))

'''
Description: API method that allows logged in users to post message via API call at this route
Input: None
Return Type: JSON, a JSON object containing the message that was POST'ed
'''
@app.route('/message', methods=['POST'])
def postMessage():
    if g.user:
        if not request.json or not 'username' in request.json or not 'messageText' in request.json:
            abort(400)
        messageData = request.json
        username = messageData['username']
        messageText = messageData['messageText']
        timeStamp = datetime.now()

        sender = User.query.filter_by(username=username).first()
        if sender is not None:
            message = Message(messageTxt=messageText, dateTime=timeStamp, sender_id=sender.id)

        msg = {}
        msg['timeStamp'] = timeStamp.strftime('%Y-%m-%d %H:%M:%S')
        msg['user'] = username
        msg['txt'] = messageText
        db.session.add(message)
        db.session.commit()
        socketio.emit('json_msg_response', msg, broadcast=True)
        return json.dumps(request.json)
    return redirect(url_for('login_view'))

'''
Description: Retrieve a collection of messages from the database
Input: None
Return Type: JSON, a JSON object containing the list of messages
'''
@app.route('/messages')
def flutter():
    if g.user:
        messageList = Message.query.all()
        return jsonify(Message.serialize_list(messageList))
    return redirect(url_for('login_view'))


'''
Description: Returns presigned POST url for AWS S3 Bucket upload
Input: URL Arguments for filename and filetype
Return Type: Presigned AWS S3 POST URL
'''
@app.route('/sign_s3/', methods=['GET','POST','OPTIONS'])
@crossdomain(origin='https://phpfayoub.pythonanywhere.com')
def sign_s3():

    file_name = request.args.get('file_name')
    file_type = request.args.get('file_type')

    s3 = boto3.client('s3')

    presigned_post = s3.generate_presigned_post(
        Bucket = S3_BUCKET,
        Key = file_name,
        Fields = {"acl": "public-read", "Content-Type": file_type},
        Conditions = [
            {"acl": "public-read"},
            {"Content-Type": file_type}
        ],
        ExpiresIn = 3600
    )

    return json.dumps({
        'data': presigned_post,
        'url': 'https://%s.s3.amazonaws.com/%s' % (S3_BUCKET, file_name)
    })

'''
Description: Returns presigned POST url for AWS S3 Bucket upload
Input: URL Arguments for username and S3 image path to their uploaded image
Return Type: JSON showing username and image path for uploaded URL (not needed)
             by client side, but works this way.
'''
@app.route('/update_img/', methods=['GET','POST','OPTIONS'])
def updateProfileImg():
    theUser = request.args.get('user')
    theImgPath = request.args.get('imgPath')
    print (theUser)
    print (theImgPath)

    user = User.query.filter_by(username=theUser).first()
    user.pic_path = theImgPath
    db.session.commit()

    return json.dumps({
        'user': theUser,
        'url': theImgPath
    })

'''
Description: SocketIO method that handles messages sent by a user
Input: None
Return Type: None, emits the message sent by a user to the channel 'json_msg_response'
'''
@socketio.on('json_msg')
def handleMessage(msg):
    receiveMessageDateTime = datetime.now()
    msg['timeStamp'] = receiveMessageDateTime.strftime("%Y-%m-%d %H:%M:%S")
    sender = User.query.filter_by(username=msg['user']).first()
    message = Message(messageTxt=msg['txt'], dateTime=receiveMessageDateTime, sender_id=sender.id)
    db.session.add(message)
    db.session.commit()
    emit('json_msg_response', msg, broadcast=True)

'''
Description: SocketIO method that disconnects a user from SocketIO server connection
Input: None
Return Type: Prints statement on server side that user logged out
'''
@socketio.on('disconnect')
def socketio_disconnect():
    print ('A user has disconnected')

''' =========================================================================================== '''
# run the app
if __name__ == '__main__':
    socketio.run(app)

"""
if __name__ == '__main__':
    app.run(debug=False)
"""