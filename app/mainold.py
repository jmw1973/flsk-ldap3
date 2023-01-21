from flask import Flask, request
import jwt
import requests
import base64
import json

app = Flask(__name__)

@app.route('/')
def auth():
  headers_dict = request.__dict__
  region = 'eu-west-2'

  # step 1: get key id from JWT header (kid field)
  # print(headers_dict)
  print("user agent: " + request.headers['User-Agent'])
  return "201"
  # encoded_jwt = request.headers.get('HTTP_USER_AGENT')
  # print("encoded_jwt: " + str(encoded_jwt))
                  # encoded_jwt = headers.dict['x-amzn-oidc-data']

                    #jwt_headers = encoded_jwt.split('.')[0]
                      #decoded_jwt_headers = base64.b64decode(jwt_headers)
                        #decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
                          #decoded_json = json.loads(decoded_jwt_headers)
                            #kid = decoded_json['kid']
                              #print("kid = " + kid)

                                # step 2: get the public key from regional endpoint
                                  #url = 'https://public-keys.auth.elb.' + region + '.amazonaws.com/' + kid
                                    #req = requests.get(url)
                                      #pub_key = req.text
                                        #print(pub_key)
                                          # step 3: Get the payload
                                            #payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])
                                              #print("payload = " + payload)
