import jwt


# make class which can encode or decode 
class JwtHandler():

	def __init__(self,private_key,public_key,secret):
		
		self.private_key = private_key
		self.public_key = public_key

    def sign_jwt(payload):

    	# stuff

    def read_jwt(jwt):

    	# stuff

	def encode_crypto_jwt(payload):

		# do the encoding
		# payload is dict
        encoded = jwt.encode(payload, private_key, algorithm='RS256')
		return encoded_jwt

	def decode_crypto_jwt(encoded):

		# decode the jwt
        decoded_payload = jwt.decode(encoded, public_key, algorithms='RS256')
		return decoded_payload


#private_key = b'-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBS...'
#public_key = b'-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEAC...'


