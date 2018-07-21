import re,datetime,calendar,time,os,json,pem,hashlib
from flask import Flask, request, make_response,jsonify
from flask_bcrypt import Bcrypt
#from mysqlconnection import MySQLConnector
from psqlconnection import PSQLConnector
from jwt_state import JwtHandler
from flask_cors import CORS


# make Flask object and DB object
app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.secret_key = "key"
psql = PSQLConnector(app,'users')

# make json web token object
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
        user = psql.query_db("SELECT * FROM users WHERE id='{}'".format(decoded.get('jwt_id')))
        if (len(user) > 0):
        	return True
        else:
        	return False

    except:

    	return False


def all_users():

	return psql.query_db("SELECT users.id,users.email,users.created_at FROM users")


@app.route('/api/auth/user', methods=['GET'])

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
        
        token = jwt.encode_crypto_jwt({'jwt_id':user['id']})
        print token
        return make_response(jsonify({'jwt_id':token}),200)

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
        
        psql.query_db(query)
        
        name_query = "SELECT * FROM users WHERE email='{}'".format(request.json['email'])
        person = psql.query_db(name_query)
        
        jwt_payload = person[0].get('id')
        token = jwt.encode_crypto_jwt({'jwt_id':person[0].get('id')})
        return jsonify({'jwt_id': token})

    else:
        return make_response(jsonify({'error': 'there was a problem with your registration'}), 404)
    
    
@app.route('/api/users', methods=['GET'])

def users():
    
	status = auth_token(request.headers['x-access-token'])

	if (status):

		return make_response(jsonify({'users': all_users()}))

	else:

		return make_response(jsonify({'error': 'not found'}), 404)


@app.route('/api/users/<user_id>', methods=['DELETE'])

def remove_user(user_id):

	status = auth_token(request.headers['x-access-token'])

	if (status):

		query = "DELETE FROM users WHERE id='{}'".format(user_id)
		psql.query_db(query)
		return make_response(jsonify({'users': all_users()}))

	else:

		return make_response(jsonify({'error': 'not found'}), 404)
    

@app.route('/<path:path>')

def catch_all(path):

    return make_response(jsonify({'error': 'not found'}), 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)      

    
