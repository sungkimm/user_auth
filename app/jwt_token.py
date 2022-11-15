import os
import yaml
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization


class JWTTokenEncrypter():

    def __init__(self, cfg_path):
        self.set_config(cfg_path)
        self.encode_key, self.decode_key = self._get_token_secret_keys()

    def set_config(self, cfg_path):
        with open(cfg_path) as f:
            self.config = yaml.load(f, Loader=yaml.FullLoader)
            self.encryption_type = self.config['algo_types'][self.config['algo']]

    def set_default_payload(self):

        # TODO: Timezone
        # TODO: issuer

        exp_claim_sec = self.config['token_exp_claim']
        issuer = self.config['token_issuer']

        payload =  {'exp' : datetime.now(tz=timezone.utc) + timedelta(hours=exp_claim_sec),
                    'iss': issuer,
                    'iat': datetime.now(tz=timezone.utc)
                    }
        
        return payload
    

    def create_payload(self, payload:dict = {}):

        default_payload = self.set_default_payload()

        return {**default_payload, **payload}

    
    def _get_token_secret_keys(self):

        #TODO: exception and set default value

        if self.encryption_type == 'asymm':
            private_key = open(self.config['private_key_path'], 'r').read()
            encode_key = serialization.load_ssh_private_key(private_key.encode(), password=b'')

            public_key = open(self.config['public_key_path'], 'r').read()
            decode_key = serialization.load_ssh_public_key(public_key.encode())

        else:
            secret_key = os.getenv(self.config['secret_key'])
            encode_key, decode_key = secret_key, secret_key
        
        return encode_key, decode_key


    def encode_token(self, payload):

        encoded = jwt.encode( payload=payload, 
                            key=self.encode_key, 
                            algorithm=self.config['algo'] )
        
        return encoded


    def decode_token(self, encoded_token):
        

        header_data = jwt.get_unverified_header(encoded_token)   # {'alg': 'RS256', 'typ': 'JWT'}

        decoded = jwt.api_jwt.decode_complete( encoded_token, 
                                            self.decode_key,
                                            algorithms=[header_data['alg'], ], 
                                            issuer=self.config['token_issuer'], 
                                            options={'require': ['exp', 'iss', 'iat'], 
                                                        'verify_iss': True
                                                    }
                                            )
        
        return decoded['payload'], decoded['header'],decoded['signature']



def encode_decode_test_case():
    
    access_cfg_path = 'config/access_token_cfg.yml'
    access = JWTTokenEncrypter(access_cfg_path)

    payload = access.create_payload()
    encoded_token = access.encode_token(payload)
    print(encoded_token)

    decoded_token = access.decode_token(encoded_token)
    print(decoded_token[:2])


    # refresh_cfg_path = 'config/refresh_token_cfg.yml'
    # refresh = JWTTokenEncrypter(refresh_cfg_path)

    # payload = refresh.create_payload()
    # encoded_token = refresh.encode_token(payload)
    # print(encoded_token)



def add_additional_info_to_payload():

    access_cfg_path = 'config/access_token_cfg.yml'
    access = JWTTokenEncrypter(access_cfg_path)
    payload = access.create_payload()
    encoded_token = access.encode_token(payload)
    print(type(encoded_token))

    # add more info
    payload['userID'] = 'ss1r2d32dw5wr3'
    payload['role'] = 'admin'
    new_encoded_token = access.encode_token(payload)

    decoded_token = access.decode_token(encoded_token)
    new_decoded_token = access.decode_token(new_encoded_token)
    print(decoded_token[:2])
    print(new_decoded_token[:2])



if __name__ == "__main__":

    encode_decode_test_case()
    # add_additional_info_to_payload()
