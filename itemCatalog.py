import random
import string

import httplib2
import os
import requests
from flask import Flask, request, jsonify, render_template, json, make_response, flash, redirect
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy.orm import sessionmaker
from flask import session as login_session

from models import Base, engine, Category, Item

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
json_url = os.path.join(SITE_ROOT, "client_secret.json")
data = json.load(open(json_url))
CLIENT_ID = data['web']['client_id']


def request_wants_json():
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
           request.accept_mimetypes[best] > \
           request.accept_mimetypes['text/html']

def no_authentication():
    return make_response(json.dumps("You're not logged in"), 401)


@app.route('/', methods=['GET'])
@app.route('/categories', methods=['GET'])
def read_categories():
    categories = session.query(Category).all()

    if request_wants_json():
        return jsonify(categories=[c.serialize for c in categories])

    return render_template('categories.html', categories=categories, session=login_session)


@app.route('/categories', methods=['POST'])
def cud_categories():
    data = request.form
    method = data['_method']
    if 'username' not in login_session:
        no_authentication()

    if method == 'POST':
        category = Category(name=data['name'],created_by=login_session['gplus_id'])
        session.add(category)
        session.commit()
    if method == 'PUT':
        category = session.query(Category).filter_by(id=data['id']).one()
        category.name = data['name']
        session.add(category)
        session.commit()
    if method == 'DELETE':
        category = session.query(Category).filter_by(id=data['id']).one()
        # first delete all items in that category
        for item in category.items:
            session.delete(item)
        session.delete(category)
        session.commit()
    return redirect('/')


@app.route('/categories/<int:cat_id>/items/create', methods=['GET'])
def create_item(cat_id):
    category = session.query(Category).filter_by(id=cat_id).one()

    return render_template('create_item.html', category=category, session=login_session)

@app.route('/categories/<int:id>/delete', methods=['GET'])
def delete_category(id):
    category = session.query(Category).filter_by(id=id).one()

    return render_template('delete_category.html', category=category, session=login_session)

@app.route('/categories/create', methods=['GET'])
def create_category():
    return render_template('create_category.html', session=login_session)

@app.route('/items/<int:id>', methods=['GET'])
def edit_item(id):
    item = session.query(Item).filter_by(id=id).one()
    categories = session.query(Category).all()

    return render_template('edit_Item.html', item=item, session=login_session, categories=categories)

@app.route('/items/<int:id>/delete', methods=['GET'])
def delete_item(id):
    item = session.query(Item).filter_by(id=id).one()
    categories = session.query(Category).all()

    return render_template('delete_item.html', item=item, session=login_session, categories=categories)

@app.route('/items', methods=['POST'])
def cud_items():
    data = request.form
    method = data['_method']
    if 'username' not in login_session:
        no_authentication()

    if method == 'POST':
        item = Item(name=data['name'],
                    description=data['description'],
                    category_id=data['cat_id'],
                    created_by=login_session['gplus_id'])
        session.add(item)
        session.commit()
        return redirect('/')

    if method == 'PUT':
        item = session.query(Item).filter_by(id=data['id']).one()
        item.name = data['name']
        item.description = data['description']
        item.category_id = data['cat_id']

        session.add(item)
        session.commit()
        return redirect('/')
    if method == 'DELETE':
        item = session.query(Item).filter_by(id=data['id']).one()
        session.delete(item)
        session.commit()
        return redirect('/')


@app.route('/login', methods=['GET'])
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid State'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets(os.path.join(SITE_ROOT, "client_secret.json"), scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response('Failed to upgrade the auth code', 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Handle errors
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps('Token\'s user ID doesn\'t match given user Id'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps('Token\'s client ID doesn\'t match app\'s'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    # Is the user already logged in?
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already logged in'), 200)
        response.headers['Content-Type'] = 'application/json'
    login_session['credentials'] = credentials.get_access_token()
    login_session['gplus_id'] = gplus_id
    # Get additional data from the user
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    data = requests.get(user_info_url, params=params).json()
    # save data to session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    flash("You're now logged in {}".format(data['name']))

    return redirect('/')


@app.route('/logout', methods=['POST'])
def logout():
    login_session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.secret_key = 'somethingUltraSecret'
    app.run()
