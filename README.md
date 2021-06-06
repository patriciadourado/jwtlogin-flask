# JWT Login Flask

This is a Flask API JWT based login authentication.

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
  id integer NOT NULL,
  username text COLLATE pg_catalog."default" NOT NULL,
  password text COLLATE pg_catalog."default" NOT NULL,
  roles text COLLATE pg_catalog."default",
  is_active boolean,
  CONSTRAINT id PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE public.users
    OWNER to (insert here your user_database)
```
Make sure to create the database before running the ```api.py``` and insert at least one user, if you prefer to insert it by python you can add the following lines after ```cors.init_app(app)``` line:

**api.py**
```
# Add user
with app.app_context():
  db.create_all()
  if db.session.query(User).filter_by(username='myusername').count() < 1:
      db.session.add(User(
        id=1,
        username='my',
        password=guard.hash_password('mypassword'),
        roles='admin'
          ))
  db.session.commit()
```

## Endpoints

Some endpoints were defined to be consumed by the frontend application, they are:

**1. /api/**

The first endpoint is the confirmation our API is up running!

**2. /api/login**

The second endpoint receives the user credentials (by POST request) and authenticates/logs it with flask-praetorian 'authenticate' method issuing a user JWT access token and returning a 200 code with the token;

**3. /api/refresh**

The third endpoint refreshes (by POST request) an existing JWT creating a new one with a new access expiration, returning a 200 code with the new token;

**4. /api/protected**

The fourth endpoint is a protected endpoint which requires a header with a valid JWT using the ```@flask_praetorian.auth_required``` decorator. The endpoint returns a message with the current user username as a secret message;

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