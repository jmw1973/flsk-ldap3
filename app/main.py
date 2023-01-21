from flask import Flask, request
from app import app
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL
import jwt, requests, base64, json, getpass, sys
import logging, secrets, string

sys.path.append('/usr/local/lib/python3.9/site-packages')

app = Flask(__name__)

if not app.debug:
  # In production mode, add log handler to sys.stderr.
  app.logger.addHandler(logging.StreamHandler())
  app.logger.setLevel(logging.INFO)

app.config['LDAPserver'] = '192.168.1.78'
app.config['LDAPuser'] = "samdom\\administrator"
app.config['LDAPpassword'] = "Yi1se@i^h0"
app.config['baseDN'] = "cn=users,dc=samdom,dc=example,dc=com"
app.config['baseDom'] = "dc=samdom,dc=example,dc=com"

DEBUG_LOGGING = 1

# LDAP userAcoountControl properties
ADS_UF_ACCOUNT_DISABLE = 2
ADS_UF_HOMEDIR_REQUIRED = 8
ADS_UF_LOCKOUT = 16
ADS_UF_PASSWD_NOTREQD = 32
ADS_UF_PASSWD_CANT_CHANGE = 64
ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
ADS_UF_NORMAL_ACCOUNT = 512
ADS_UF_DONT_EXPIRE_PASSWD = 65536
ADS_UF_PASSWORD_EXPIRED = 8388608

def connect_ldap():
    server = Server(app.config.get('LDAPserver'), get_info=ALL)
    conn = Connection(server, user=app.config.get('LDAPuser'), password=app.config.get('LDAPpassword'), authentication=SIMPLE)
    conn.bind()
    return conn

def generate_password():
  # define the alphabet
  letters = string.ascii_letters
  digits = string.digits
  special_chars = string.punctuation

  alphabet = letters + digits + special_chars

  # fix password length
  pwd_length = 12

  # generate a password string
  pwd = ''
  for i in range(pwd_length):
    pwd += ''.join(secrets.choice(alphabet))
    # print(pwd)

    # generate password meeting constraints
  while True:
    pwd = ''
    for i in range(pwd_length):
      pwd += ''.join(secrets.choice(alphabet))

    if (any(char in special_chars for char in pwd) and 
      sum(char in digits for char in pwd)>=2):
        break
  print(pwd)
  return pwd

@app.route('/healthz')
def healtcheck():
  return "200"

@app.route('/')
def auth():
  headers_dict = request.__dict__
  region = 'eu-west-2'
  jwt_token = "787655" # dummy for now
  user_account_name = "testuser2"

  if jwt_token:
    app.logger.info(user_account_name + ": user has authenticated ok: now checking if they have an existing account")
    checkUserAccount = search_user(user_account_name)
    app.logger.info(checkUserAccount)

  if checkUserAccount == "ACCOUNT_DISABLED":
    app.logger.info(user_account_name + ": user has existing account, enabling account and returning new password")
    newpassword = generate_password()
    return newpassword
  else:
    app.logger.info(user_account_name + ": user has no existing account, going to run through account provisioning workflow")
    newpassword = generate_password() 
    return newpassword #todo

def search_user(userid):
  conn = connect_ldap()
  search_filter_user = "(sAMAccountName=" + userid + ")"
  # print(search_filter_user)
  conn.search(
            search_base = app.config.get('baseDom'),
            search_filter = search_filter_user,
            search_scope = SUBTREE,
            attributes=['*']
            )
  # print(usersearch)
  # print(conn.entries)

  if conn.entries:
    for entry in conn.entries:
      userdn = entry.entry_dn
      userAccountControl = entry['userAccountControl']
    
    if DEBUG_LOGGING == 1:
        app.logger.info(userdn)
        app.logger.info(userAccountControl)

    result = ""

    match userAccountControl:
      case 514:
        return "ACCOUNT_DISABLED"
      case 528:
        return "ACCOUNT_LOCKED"
      case 530:
        return "ACCOUNT_LOCKED_DISABLED"
  else:
    return "ACCOUNT_NOTEXISTS"

def add_user(userid, sAMAccountName, givenName, sn):
  conn = connect_ldap()
  object_class = 'user'
  
  attr = {
          'sAMAccountName': sAMAccountName,
          'givenName': givenName,
          'sn': sn
         }
         
  userdn = "cn=" + userid + "," + app.config.get('baseDN')
  conn.add(userdn, object_class, attr)
  print(conn.response)

print(app.config.get('LDAPserver'))
print(app.config.get('LDAPuser'))
print(app.config.get('LDAPpassword'))
# add_user('mytestuser', 'mytestuser', 'John', 'Doe')





