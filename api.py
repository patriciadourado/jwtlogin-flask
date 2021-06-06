import os
import flask
from flask.wrappers import Request
import flask_sqlalchemy
import flask_praetorian
import flask_cors

db = flask_sqlalchemy.SQLAlchemy()
guard = flask_praetorian.Praetorian()
cors = flask_cors.CORS()


# A simple model that might be used by an app powered by flask-praetorian
class User(db.Model):
    
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    roles = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, server_default='true')

    @property
    def rolenames(self):
        try:
            return self.roles.split(',')
        except Exception:
            return []

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    @property
    def identity(self):
        return self.id

    def is_valid(self):
        return self.is_active


# Initialize flask app
app = flask.Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'my secret key'
app.config['JWT_ACCESS_LIFESPAN'] = {'hours': 24}
app.config['JWT_REFRESH_LIFESPAN'] = {'days': 30}

# Initialize the flask-praetorian instance for the app
guard.init_app(app, User)

# Initialize a local database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user_database:password@hostname:5432/database_name'

db.init_app(app)

# Initializes CORS so that the api_tool can talk to app
cors.init_app(app)

# Set up the routes
@app.route('/api/')
def home():
    return {"JWT Server Application":"Running!"}, 200

  
@app.route('/api/login', methods=['POST'])
def login():
    """
    Logs a user in by parsing a POST request containing user credentials and
    issuing a JWT token.
    .. example::
       $ curl http://localhost:5000/api/login -X POST \
         -d '{"username":"myusername","password":"mypassword"}'
    """
    req = flask.request.get_json(force=True)
    username = req.get('username', None)
    password = req.get('password', None)
    user = guard.authenticate(username, password)
    ret = {'access_token': guard.encode_jwt_token(user)}
    return ret, 200

  
@app.route('/api/refresh', methods=['POST'])
def refresh():
    """
    Refreshes an existing JWT by creating a new one that is a copy of the old
    except that it has a refreshed access expiration.
    .. example::
       $ curl http://localhost:5000/api/refresh -X GET \
         -H "Authorization: Bearer <your_token>"
    """
    print("refresh request")
    old_token = Request.get_data()
    new_token = guard.refresh_jwt_token(old_token)
    ret = {'access_token': new_token}
    return ret, 200
  
  
@app.route('/api/protected')
@flask_praetorian.auth_required
def protected():
    """
    A protected endpoint. The auth_required decorator will require a header
    containing a valid JWT
    .. example::
       $ curl http://localhost:5000/api/protected -X GET \
         -H "Authorization: Bearer <your_token>"
    """
    return {'message': 'protected endpoint (allowed usr {})'.format(flask_praetorian.current_user().username)}

@app.route('/api/registration', methods=['POST'])
def registration():
    
    """Register user without validation email, only for test"""

    req = flask.request.get_json(force=True)
    username = req.get('username', None)
    password = req.get('password', None)
    
    with app.app_context():
        db.create_all()
        if db.session.query(User).filter_by(username=username).count() < 1:
            db.session.add(User(
                username=username,
                password=guard.hash_password(password),
                roles='user'
            ))
        db.session.commit()
    
    user = guard.authenticate(username, password)
    ret = {'access_token': guard.encode_jwt_token(user)}

    return ret,200
    
# Run the example
if __name__ == '__main__':
    app.run()