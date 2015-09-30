from flask import Flask, render_template, request, redirect, url_for
from flask import flash, jsonify
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Store, Toy, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

import os
from werkzeug import secure_filename
from flask import send_from_directory
from flask import g
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Toy Store"
UPLOAD_FOLDER = os.path.realpath('.') + '/static'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

engine = create_engine('sqlite:///toystores.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# keep the stores as a global variable for the sidebar
@app.before_request
def load_stores():
    stores = session.query(Store).all()
    g.stores = stores


# Display by default the latest toys
@app.route('/')
def index():
    return redirect(url_for('latestToys'))


# Latest toys, sorted (not ideally) by id number
@app.route('/stores/latest/')
def latestToys():
    toys = session.query(Toy).order_by(desc(Toy.id)).limit(5)
    return render_template('recenttoys.html', toys=toys)


# Display stores
@app.route('/stores/')
def showStores():
    stores = session.query(Store).all()
    if 'username' not in login_session:
        return render_template('publicstores.html', stores=stores)
    else:
        return render_template('stores.html', stores=stores)


# Decorator used for routes that require authentication, such as edit
def login_required(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
        else:
            return func(args, kwargs)
    return wrap

# Add a new store if logged in
@app.route('/stores/new/', methods=['GET', 'POST'])
@login_required
def newStore():
    if request.method == 'POST':
        newStore = Store(name=request.form['name'],
                         user_id=login_session['user_id'],
                         url=request.form['url'],
                         address=request.form['address'])
        session.add(newStore)
        session.commit()
        flash("New store %s successfully created" % newStore.name)
        return redirect(url_for('showStores'))
    else:
        return render_template('newstore.html')


# Edit a store's details if store creator
@app.route('/stores/<int:store_id>/edit/', methods=['GET', 'POST'])
@login_required
def editStore(store_id):
    store = session.query(Store).filter_by(id=store_id).one()
    if store.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert(\
          'You are not authorized to edit this store. \
          Please create your own store in order to edit.');\
          }</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            store.name = request.form['name']
        if request.form['url']:
            store.url = request.form['url']
        if request.form['address']:
            store.address = request.form['address']
        session.add(store)
        session.commit()
        flash("Store successfully edited")
        return redirect(url_for('showStores'))
    else:
        return render_template('editstore.html', store=store)


# Delete a store if store creator
@app.route('/stores/<int:store_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteStore(store_id):
    store = session.query(Store).filter_by(id=store_id).one()
    if store.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert(\
          'You are not authorized to delete this store. \
          Please create your own store in order to delete.');\
          }</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(store)
        session.commit()
        flash("Store successfully deleted")
        return redirect(url_for('showStores'))
    else:
        return render_template('deletestore.html', store=store)


# Display toys for store <store_id>
@app.route('/stores/<int:store_id>/')
def storeToys(store_id):
    store = session.query(Store).filter_by(id=store_id).one()
    creator = getUserInfo(store.user_id)
    toys = session.query(Toy).filter_by(store_id=store.id).all()
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('publicstoretoys.html', store=store, toys=toys)
    else:
        return render_template('storetoys.html', store=store, toys=toys)


# Add a new toy to a certain store, including image
# Image can be given in 2 ways:
# - textbox 'img_text', for web link, in which case this link is stored
# - upload button, for local file, in which case the file is saved to
#   local static folder, and then local path is stored
@app.route('/stores/<int:store_id>/new/', methods=['GET', 'POST'])
@login_required
def newStoreToy(store_id):
    store = session.query(Store).filter_by(id=store_id).one()
    if store.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert(\
                'You are not authorized to add toys to this store. \
                Please create your own store in order to add toys.');\
                }</script><body onload='myFunction()''>"
    if request.method == 'POST':
        fprice = None
        if request.form['price']:
            if float(request.form['price']):
                fprice = float(request.form['price'])
        img_url = ""
        if request.form['img_text']:
            img_url = request.form['img_text']
        else:
            file = request.files['img_file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                img_url = "/static/" + filename
        newToy = Toy(
            name=request.form['name'], description=request.form['description'],
            price=fprice,
            age_min=request.form['age_min'],
            img_url=img_url,
            url=request.form['url'],
            store_id=store_id, user_id=store.user_id)
        session.add(newToy)
        session.commit()
        flash("New toy %s created" % newToy.name)
        return redirect(url_for('storeToys', store_id=store_id))
    else:
        return render_template('newstoretoy.html', store_id=store_id)


# Edit a toy's details, if toy creator. Image is handled similarly to 
# previous route: newStoreToy (can be web link or local file)
@app.route('/stores/<int:store_id>/<int:toy_id>/edit/',
           methods=['GET', 'POST'])
@login_required
def editStoreToy(store_id, toy_id):
    toy = session.query(Toy).filter_by(id=toy_id).one()
    if toy.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert(\
                'You are not authorized to edit toys to this store. \
                Please create your own store in order to edit toys.'\
                );}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            toy.name = request.form['name']
        if request.form['description']:
            toy.description = request.form['description']
        if request.form['price']:
            toy.price = request.form['price']
        if request.form['age_min']:
            toy.age_min = request.form['age_min']
        file = request.files['img_file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            toy.img_url = "/static/" + filename
        elif request.form['img_text']:
            toy.img_url = request.form['img_text']
        if request.form['url']:
            toy.url = request.form['url']
        session.add(toy)
        session.commit()
        flash("Toy successfully edited")
        return redirect(url_for('showToy', store_id=store_id, toy_id=toy_id))
    else:
        return render_template(
            'editstoretoy.html', store_id=store_id, toy_id=toy_id, toy=toy)


# Delete a toy if toy creator
@app.route('/stores/<int:store_id>/<int:toy_id>/delete/',
           methods=['GET', 'POST'])
@login_required
def deleteStoreToy(store_id, toy_id):
    toy = session.query(Toy).filter_by(id=toy_id).one()
    if toy.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('\
            You are not authorized to delete toys at this store. \
            Please create your own store in order to edit items.');\
            }</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(toy)
        session.commit()
        flash("Toy successfully deleted")
        return redirect(url_for('storeToys', store_id=store_id))
    else:
        return render_template('deletestoretoy.html', toy=toy)


# Display details for a certain toy
@app.route('/stores/<int:store_id>/<int:toy_id>/')
def showToy(store_id, toy_id):
    toy = session.query(Toy).filter_by(id=toy_id).one()
    creator = getUserInfo(toy.user_id)
    if 'username' not in login_session or \
            creator.id != login_session['user_id']:
        return render_template('publictoy.html', store_id=store_id, toy=toy)
    else:
        return render_template('toy.html', store_id=store_id, toy=toy)


# Create anti-forgery state token
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# FB log in
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    # Let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
                -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# FB log out
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % \
          (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# G+ log in
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # submit request, parse response
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
               -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


# G+ logout - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Helper function for image upload
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# JSON endpoints
@app.route('/stores/JSON/')
def storesJSON():
    stores = session.query(Store).all()
    return jsonify(rlist=[r.serialize for r in stores])


@app.route('/stores/<int:store_id>/toys/JSON/')
def storeToysJSON(store_id):
    store = session.query(Store).filter_by(id=store_id).one()
    toys = session.query(Toy).filter_by(
        store_id=store_id).all()
    return jsonify(Toys=[i.serialize for i in toys])


@app.route('/stores/<int:store_id>/toy/<int:toy_id>/JSON/')
def storeToyJSON(store_id, toy_id):
    toy = session.query(Toy).filter_by(id=toy_id).one()
    return jsonify(toy.serialize)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('latestToys'))
    else:
        flash("You were not logged in")
        return redirect(url_for('latestToys'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
