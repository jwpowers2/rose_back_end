import jwt


class JwtHandler():

    def __init__(self,private_key,public_key,secret):
        
        self.private_key = private_key
        self.public_key = public_key

    def sign_jwt(self,payload):

        # stuff
        pass

    def read_jwt(self,jwt):

        # stuff
        pass

    def encode_crypto_jwt(self,payload):

        encoded = jwt.encode(payload, self.private_key, algorithm='RS256')
        return encoded

    def decode_crypto_jwt(self,encoded):

        decoded_payload = jwt.decode(encoded, self.public_key, algorithms='RS256')
        return decoded_payload





