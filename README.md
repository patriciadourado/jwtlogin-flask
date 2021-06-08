# JWT Login Flask

This is a Flask API JWT based login authentication. 

You can check my [blog post](https://patriciadourado.com/frompat/jwt-login-flask/) of this project if you need more details about Python Virtual Environment setup or other stuffs. I will try to update it as often as possible.

## Requirements

Before running API you need to install the packages in the requirements.txt file and create a database and ```user``` table. I used virtual environment so packages didn't need to be installed globally;

If you also user virtual environment, activate it and them run on CLI: 

`pip install -r requirements.txt`

```Gunicorn``` package was required as the Python HTTP server for WSGI because the API was deployed at **Heroku** and it can support concurrent request processing, but if you will running it locally its not necessary;

## SQLAlchemy

SQLAlchemy was used as the Python ORM for accessing data from the database and facilitate the communication between app and db converting function calls to SQL statements;

Do not forget to change ***'SQLALCHEMY_DATABASE_URI'*** to your own here:

**api.py**
```
app.config['SQLALCHEMY_DATABASE_URI'] = postgresql://user_database:password@hostname:5432/database_name'
```

## PostgreSQL

The database used was PostgreSQL (before being deployed it was modeled through *pgAdmin 4* interface) and the SQL for the created users table is the following:

```
CREATE TABLE public.users
(
    id integer NOT NULL DEFAULT nextval('users_id_seq'::regclass),
    username text COLLATE pg_catalog."default" NOT NULL,
    password text COLLATE pg_catalog."default" NOT NULL,
    roles text COLLATE pg_catalog."default",
    is_active boolean,
    CONSTRAINT users_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE public.users
    OWNER to (insert here your user_database)
```
Make sure to create the database before running the ```api.py``` 

## Endpoints

Some endpoints were defined to be consumed by the frontend application, they are:

**1. /api/**

The first endpoint is the confirmation our API is up running!

```python
@app.route('/api/')
def home():
    return {"JWT Server Application":"Running!"}, 200
```
**2. /api/login**

The second endpoint receives the user credentials (by POST request) and authenticates/logs it with flask-praetorian 'authenticate' method issuing a user JWT access token and returning a 200 code with the token;

```python
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
```

**3. /api/refresh**

The third endpoint refreshes (by POST request) an existing JWT creating a new one with a new access expiration, returning a 200 code with the new token;

```python
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
```
**4. /api/protected**

The fourth endpoint is a protected endpoint which requires a header with a valid JWT using the ```@flask_praetorian.auth_required``` decorator. The endpoint returns a message with the current user username as a secret message;

```python
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
```

**5. /api/registration**

The fifth endpoint is a simple user registration without requiring user email (for now), with the password hash method being invoked only to demonstrate insertion into database if its a new user;

```python
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
```

## Flask-praetorian

To let the things easier Flask-praetorian was used to handle the hard logic by itself. Among the advantages of using Flask-praetorian in this API (where the most important is undoubtedly allowing to use JWT token for authentication) are:

* Hash passwords for storing in database;
* Verify plaintext passwords against the hashed, stored versions;
* Generate authorization tokens upon verification of passwords;
* Check requests to secured endpoints for authorized tokens;
* Supply expiration of tokens and mechanisms for refreshing them;
* Ensure that the users associated with tokens have necessary roles for access;

You can check Flask-praetorian documentation here: [Flask-praetorian](https://flask-praetorian.readthedocs.io/en/latest/index.html#table-of-contents)


## Frontend Application

For now the ReactJS application (check the other repository) that consumes this Flask API provides three different pages:

1. The ```Home page``` with the login button (if the user isn't logged) and with the secret button and the logout button (assuming the user is logged);
2. The ```Login Page``` where the user can log-in;
3. The ```Protected page``` with a content message that only the logged user can view;


You can check the full application with database and frontend (ReactJS) running and deployed on the description link! :)