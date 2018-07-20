import re
import datetime
import calendar
import time
import os
import json
import pem
from flask import Flask, request, make_response,jsonify
from flask_bcrypt import Bcrypt
import hashlib
#from mysqlconnection import MySQLConnector
from psqlconnection import PSQLConnector
from jwt_state import JwtHandler

from flask_cors import CORS


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.secret_key = "key"
psql = PSQLConnector(app,'users')

'''
private_key = pem.parse_file("ssh_keys/jwt_key_private.pem")
with open("ssh_keys/jwt_key_public.pub","r") as public_key:
    print public_key
'''

pemfile = open("ssh_keys/jwt_key_private.pem", 'r')
private_key = pemfile.read()
pemfile.close()
pubfile = open("ssh_keys/jwt_key_public.pub", 'r')
public_key = pubfile.read()
pubfile.close()    
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
    






@app.route('/auth/user', methods=['GET'])

def auth_user():

    status = auth_token(request.headers['x-access-token']);

    if (status == True):
        return make_response(jsonify({'authenticated':True}), 200)
    else:
        return make_response(jsonify({'authenticated': False}), 200)


@app.route('/api/login', methods=['POST'])

def login():
    
    users = psql.query_db("SELECT * FROM users WHERE email='{}'".format(request.json['email']))
    user = users[0]
    if (bcrypt.check_password_hash(user['password'],request.json['password'] )):
        
        # -- make JWT token using id from table and send it back to client
        token = jwt.encode_crypto_jwt({'jwt_id':user['id']})
        return make_response(jsonify({'jwt_id':token}),200)
        #return jsonify({"hello":"good password"})

    else:
       
        return make_response(jsonify({'error': 'not found'}), 404)
          


@app.route('/api/register', methods=['POST'])

def register():
    
    #return jsonify({"hello":request.json['email']})
    
    proceed = True
    
    if not re.match("^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$",request.json['email']):
        
        proceed = False

    if len(request.json['password']) < 9:
        
        proceed = False

    if request.json['password'] != request.json['confirm_password']:
    
        proceed = False

    if proceed:

        password_hashed = bcrypt.generate_password_hash(request.json['password'])
        #password_hashed = hashlib.sha256(request.json['password']).hexdigest()
        
        now = datetime.datetime.utcnow()
        query = "INSERT INTO users (email, password, created_at, updated_at)\
                 VALUES ('{}','{}','{}','{}')".format(request.json['email'],password_hashed,now,now)
        
        '''
        data = {
                'email': request.form['email'],
                'password': password_hashed,
	            'created_at':now,
	            'updated_at':now
                }
        '''
        psql.query_db(query)
        #return jsonify({"hello":good_register})
        # get the id for the new user, make jwt and send it back to client
        name_query = "SELECT * FROM users WHERE email='{}'".format(request.json['email'])
        person = psql.query_db(name_query)
        #return jsonify({"hello":good_register})
        #jwt_payload = person[0].get('id')
        #token = jwt.encode_crypto_jwt(jwt_payload);
        #return jsonify({'jwt_id': token})

    else:
        return make_response(jsonify({'error': 'not found'}), 404)
    
    
@app.route('/api/users', methods=['GET'])

def users():
    return jsonify({"hello":"there"})
    '''
	status = auth_token(request.headers['x-access-token'])
    
    if status:

        return make_response(jsonify({'users': all_users()}))
    
    else:

        return make_response(jsonify({'error': 'not found'}), 404)
    '''

@app.route('/api/users/<int:user_id>', methods=['DEL'])

def remove_user(user_id):

    pass
    '''
	status = auth_token(request.headers['x-access-token'])
    
    if status:

        query = "DELETE FROM users WHERE id=:user_id"
        psql.query_db(query)
        return make_response(jsonify({'users': all_users()}))
    
    else:

       return make_response(jsonify({'error': 'not found'}), 404)
    '''

@app.route('/<path:path>')

def catch_all(path):

    return make_response(jsonify({'error': 'not found'}), 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)      

    