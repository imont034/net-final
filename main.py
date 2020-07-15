import os, json, threading, datetime, time, threading

from socket import *

from functools import wraps
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv

from flask import Flask, jsonify, redirect, render_template, session, url_for, request, Response
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

AUTH0_CALLBACK_URL = os.environ.get('AUTH0_CALLBACK_URL')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')

app = Flask(__name__)
app.secret_key = os.environ.get('KEY')

bytes = None
lock = threading.Lock()

#####################################################################################################
### Auth0
#####################################################################################################
@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile',
    },
)

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)

  return decorated

# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/menu')

#####################################################################################################
### Routing
#####################################################################################################

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route('/static')
@requires_auth
def play():
    return render_template('static.html')

def get_bytes():
    global bytes, lock

    addr = os.environ.get('MY_IP')
    port = int(os.environ.get('MY_PORT'))

    client = socket(AF_INET, SOCK_STREAM)
    client.connect((addr, port))
    
    while True:        
        length = int(client.recv(2048).decode('utf-8'))
        #with lock:
        bytes = client.recv(length)
        yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + 
		    bytearray(bytes) + b'\r\n')
        #client.close()

def get_feed():
    global bytes, lock

    while True:
        with lock:
            if bytes is None:
                continue
            yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + 
		    bytearray(bytes) + b'\r\n')

@app.route('/feed')
@requires_auth
def feed():
    #t = threading.Thread(target=get_bytes)
    #t.daemon = True
    #t.start()
    return Response(get_bytes(), mimetype = "multipart/x-mixed-replace; boundary=frame")
   
@app.route('/live')
@requires_auth
def live():
    return render_template('live.html')
    
@app.route('/menu')
@requires_auth
def dashboard():
    return render_template('menu.html')

@app.route('/')
def home():    
    return redirect("/login", code=302)    

if __name__ == '__main__':
    app.run(threaded=True, use_reloader=False)