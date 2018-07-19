import re
import datetime
import calendar
import time
import os
from flask import Flask, request, make_response
#from mysqlconnection import MySQLConnector
from psqlconnection import PSQLConnector
import bcrypt
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
app.secret_key = "key"
psql = PSQLConnector(app,'users')


with open("ssh_keys/jwt_key.pem","r") as private_key, open ("ssh_keys/jwt_key.pub","r") as public_key:
    
    jwt = JwtHandler(private_key,public_key,os.environ['JWT_KEY'])


def auth_token(token):

    try:

        decoded = jwt.decode_crypto_jwt(token)
        # if it decodes successfully, check if user is in the DB and return true to client if so
        print decoded
        # jwt_id is the user id from the users table
        user = psql.query_db("SELECT * FROM users WHERE id='{}'".format(decoded.jwt_id))
        if (len(user) > 0):
        	return True
        else:
        	return False

    except:

    	return False


def all_users():

	return psql.query_db("SELECT users.id,users.email,users.created_at FROM users")
    






@app.route('/auth/user')

def auth_user():

    status = auth_token(request.headers['x-access-token']);

    if (status == True):
        return make_response(jsonify({'authenticated':True}), 200)
    else:
        return make_response(jsonify({'authenticated': False}), 200)


@app.route('/api/login', methods=['POST'])

def login():

    try:
        print request.form
        '''
        users = psql.query_db("SELECT * FROM users WHERE email='{}'".format(request.form['email']))
        
        if bcrypt.checkpw(request.form['password'].encode(), users[0]['password'].encode()):
            
            # -- make JWT token using id from table and send it back to client
            token = jwt.encode_crypto_jwt(users.id)
            return make_response(jsonify({'jwt_id':token}),200)

        else:
           
            return make_response(jsonify({'error': 'not found'}), 404)
        '''    
    except:

        return make_response(jsonify({'error': 'not found'}), 404)

@app.route('/api/register', methods=['POST'])

def register():

    proceed = True
    
    if not re.match("^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$",request.form['email']):
        flash("Not valid email")
        proceed = False

    if len(request.form['password']) < 9:
        flash("Password is not long enough")
        proceed = False

    if request.form['password'] != request.form['confirm_password']:
        flash("Confirm password is not the same as password")
        proceed = False

    if proceed:

        password_hashed = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())
        
        now = datetime.datetime.utcnow()
        query = "INSERT INTO users (email, password, created_at, updated_at)\
                 VALUES (:email, :password, :created_at, :updated_at)"

        data = {
                'email': request.form['email'],
                'password': password_hashed,
	            'created_at':now,
	            'updated_at':now
                }

        good_register = psql.query_db(query, data)

        if type(good_register) == long:

            # get the id for the new user, make jwt and send it back to client
            name_query = "SELECT id FROM users WHERE email = '{}'".format(request.form['email'])
            person = psql.query_db(name_query)
            jwt_payload = person[0].get('id')
            token = jwt.encode_crypto_jwt(jwt_payload);
            return make_response(jsonify({'jwt_id': token}), 200)

        else:

            return make_response(jsonify({'error': 'not found'}), 404)

    else:
        return make_response(jsonify({'error': 'not found'}), 404)


@app.route('/api/users')

def users():

	status = auth_token(request.headers['x-access-token'])
    
    if (status == True):

        return make_response(jsonify({'users': all_users()}))
    
    else:

       return make_response(jsonify({'error': 'not found'}), 404)


@app.route('/api/users/<int:user_id>', methods=['DEL'])

def remove_user(user_id):

	status = auth_token(request.headers['x-access-token'])
    
    if (status == True):

        query = "DELETE FROM users WHERE id=:user_id"
        psql.query_db(query)
        return make_response(jsonify({'users': all_users()}))
    
    else:

       return make_response(jsonify({'error': 'not found'}), 404)
    

@app.route('/<path:path>')

def catch_all(path):

    return make_response(jsonify({'error': 'not found'}), 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)      

    