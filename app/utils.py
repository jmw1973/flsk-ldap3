import yaml
from app import app
from yaml.loader import SafeLoader
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL, MODIFY_REPLACE, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
import logging, secrets, string

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

def getEzmeralSourceData():
  # Open the file and load the file
  with open('ezmeral.yaml') as f:
    data = yaml.safe_load(f)
  return data

def print_values():
  data = getEzmeralSourceData()

  # iterate through data structure
  for key, value in data["environment"].items():
    print(key)
    for key, value in value.items():
      print(key) # we have the group
      for user in value:
        print(user) # we have the user



# test output
print_values()

def process_data():
      data = getEzmeralSourceData()

      # iterate through data structure
      for key, value in data["environment"].items():
        print(key)
        for key, value in value.items():
          print(key) # we have the group
          for user in value:
            print(user) # we have the user


def connect_ldap():
  server = Server(app.config.get('LDAPserver'), get_info=ALL)
  conn = Connection(server, user=app.config.get('LDAPuser'), password="Yi1se@i^h0", authentication=SIMPLE)
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

    # generate password meeting constraints
    while True:
      pwd = ''
      for i in range(pwd_length):
        pwd += ''.join(secrets.choice(alphabet))

      if (any(char in special_chars for char in pwd) and
        sum(char in digits for char in pwd)>=2):
          break
    # print(pwd)
    return pwd

def process_user(userid):
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
      #  print(conn.entries)

      if conn.entries:
        for entry in conn.entries:
          userdn = entry.entry_dn
          userAccountControl = entry['userAccountControl']

        # if DEBUG_LOGGING == 1:
          app.logger.info(userdn)
          app.logger.info(userAccountControl)

        result = ""

        match userAccountControl:
          case "512": #normal, unlocked, enabled
            return "ACCOUNT_NORMAL"

          case 514: #"ACCOUNT_DISABLED"
            newpassword = generate_password()
            changeuserpassword = modify_user_password(userdn, newpassword)
            app.logger.info("result of password change: " + str(changeuserpassword))
            if changeuserpassword == 0:
              enableaccount = modify_user_attribute(userdn, 'userAccountControl', 512)
              app.logger.info("result of enable user account: " + str(enableaccount))
              if enableaccount == 0:
                app.logger.info("account enabled successfully")
                return newpassword

          case 528:
            return "ACCOUNT_LOCKED"

          case 530:
            return "ACCOUNT_LOCKED_DISABLED"
          case _:
            newpassword = generate_password()
            changeuserpassword = modify_user_password(userdn, newpassword)
            app.logger.info("result of password change: " + str(changeuserpassword))
            if changeuserpassword == 0:
              enableaccount = modify_user_attribute(userdn, 'userAccountControl', 512)
              app.logger.info("result of enable user account: " + str(enableaccount))
              if enableaccount == 0:
                app.logger.info("account enabled successfully")
                return newpassword

      else:
        return "ACCOUNT_NOT_EXISTS"

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

def modify_user_password(userdn, password):
  # dn = user.entry_get_dn()
  conn = connect_ldap()
  hashed_password = hashed(HASHED_SALTED_SHA, password)
  changes = {'userPassword': [(MODIFY_REPLACE, [hashed_password])]}
  success = conn.modify(userdn, changes=changes)
  if not success:
    print('Unable to change password for %s' % dn)
    #print(conn.connection.result)
    raise ValueError('Unable to change password')
    return 1
  return 0

def modify_user_attribute(userdn, attribute, newattributevalue):
  conn = connect_ldap()
  # perform the Modify operation
  conn.modify(userdn,{attribute: [(MODIFY_REPLACE, [newattributevalue])]})
  app.logger.info(conn.result)
  return 0
