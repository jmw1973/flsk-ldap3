import yaml
from main import app
from yaml.loader import SafeLoader
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, HASHED_SALTED_SHA
from ldap3.utils.hashed import hashed
import logging, secrets, string

# LDAP userAccountControl properties
ADS_UF_ACCOUNT_DISABLE = 2
ADS_UF_HOMEDIR_REQUIRED = 8
ADS_UF_LOCKOUT = 16
ADS_UF_PASSWD_NOTREQD = 32
ADS_UF_PASSWD_CANT_CHANGE = 64
ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
ADS_UF_NORMAL_ACCOUNT = 512
ADS_UF_DONT_EXPIRE_PASSWD = 65536
ADS_UF_PASSWORD_EXPIRED = 8388608

user_exceptions = ['Administrator', 'jmwall', 'krbtgt', 'gogo', 'DC6F8A3E844D$', 'Guest', 'dns-dc6f8a3e844d', 'gogo2', 'gogo3', 'gogo4', '$15AFADE1-79E3750BCF8BFC18']

group_exceptions =['Account Operators', 'Administrators', 'Allowed RODC Password Replication Group', 'Backup Operators', 'CSC-ADMIN', 'CSC-AGENT', 'CSC-COMPLIANCE', 'CSC-MANAGER', 'Cert Publishers', 'Certificate Service DCOM Access', 'Cryptographic Operators', 'Denied RODC Password Replication Group', 'Distributed COM Users', 'DnsAdmins', 'DnsUpdateProxy', 'Domain Admins', 'Domain Computers', 'Domain Controllers', 'Domain Guests', 'Domain Users', 'Enterprise Admins', 'Enterprise Read-Only Domain Controllers', 'Event Log Readers', 'Group Policy Creator Owners', 'Guests', 'IIS_IUSRS', 'Incoming Forest Trust Builders', 'Network Configuration Operators', 'Performance Log Users', 'Performance Monitor Users', 'Pre-Windows 2000 Compatible Access', 'Print Operators', 'RAS and IAS Servers', 'Read-Only Domain Controllers', 'Remote Desktop Users', 'Replicator', 'Schema Admins', 'Server Operators', 'Terminal Server License Servers', 'Users', 'Windows Authorization Access Group']

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



def process_data_file():
      data = getEzmeralSourceData()
      allUsersFile = []
      allGroupsFile = []
      allUsersLDAP = get_all_ldap_objects('user')
      allGroupsLDAP = get_all_ldap_objects('group')

      app.logger.info("------- STARTING input file processing ------")
      app.logger.info("existing groups in LDAP are: "+str(allGroupsLDAP))
      app.logger.info("existing users in LDAP are: "+str(allUsersLDAP))
      
      # iterate through data structure
      for key, value in data["environment"].items():
        print(key)
        # process groups from file
        for key, value in value.items():
          allGroupsFile.append(key)
          print(key) # we have the group
          # checkExistingGroup = search_group(key)
          if key in allGroupsLDAP:
            checkExistingGroup = "GROUP_EXISTS"
            app.logger.info(key + ": is an existing Group")
          else:
            checkExistingGroup = "GROUP_NOT_EXISTS"
            app.logger.info(key + ": is NOT an existing Group in LDAP")
            app.logger.info(key + ": attempting to add group to LDAP")
            addgroup_result = add_object(key, key, 'group')
            app.logger.info(addgroup_result)
            print(addgroup_result)
               

          # process users from file
          for user in value:
            allUsersFile.append(user)
            print(user) # we have a user
            #checkExistingUser = search_user(user)
            if user in allUsersLDAP:
              checkExistingUser = "USER_EXISTS"
              app.logger.info(user + ": is an existing user")
            else:
              checkExistingUser = "USER_NOT_EXISTS"
              app.logger.info(user + ": is NOT an existing user in LDAP")
              #print(user + ": is NOT an existing user")
              app.logger.info(user + ": attempting to add user to LDAP")
              adduser_result = add_object(user, user, 'user')
              app.logger.info(adduser_result)
              print(adduser_result)
            
            # now we need to add user to group
            checkuseringroup = checkUserInGroup(user, key)
            if checkuseringroup == "USER_NOT_IN_GROUP":
              app.logger.info(user + ": is NOT an existing member of: "+key)
              app.logger.info(user + ": attempting to add user to: "+key)
              addusertogroupresult = addUserToGroup(user, key)
              print(addusertogroupresult)
              app.logger.info(addusertogroupresult)
            
      print("allGroupsFile: "+str(allGroupsFile))
      print("allUsersFile: "+str(allUsersFile))
      app.logger.info("existing groups in input file are: "+str(allGroupsFile))
      app.logger.info("existing users in input file are: "+str(allUsersFile))

      # we now have alist of all users\groups in file and LDAP, going to compare to see if we need to delete any users\groups

      for user in allUsersLDAP:
        if user not in allUsersFile:
          #del user
          app.logger.info(user + ": is an existing user in LDAP but not in input file")
          app.logger.info(user + ": attempting to delete user from LDAP")
          deluser_result = delete_object(user)
          print(deluser_result)
          app.logger.info(deluser_result)

      for group in allGroupsLDAP:
        if group not in allGroupsFile:
          #del user
          app.logger.info(group + ": is an existing group in LDAP but not in input file")
          app.logger.info(group + ": attempting to delete group from LDAP")
          delgroup_result = delete_object(group)
          print(delgroup_result)
          app.logger.info(delgroup_result)

      
      app.logger.info("------- input file processing COMPLETE ------")
      return "201"



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

      if conn.entries:
        for entry in conn.entries:
          userdn = entry.entry_dn
          userAccountControl = entry['userAccountControl']

        # if DEBUG_LOGGING == 1:
          #app.logger.info(userdn)
          #app.logger.info(userAccountControl)
          conn.unbind()
          return "USER_EXISTS"
      else:
        conn.unbind()
        return "USER_NOT_EXIST"


def search_group(groupid):
      conn = connect_ldap()
      search_filter_group = "(sAMAccountName=" + groupid + ")"
      # print(search_filter_user)
      conn.search(
                search_base = app.config.get('baseDom'),
                search_filter = search_filter_group,
                search_scope = SUBTREE,
                attributes=['*']
                )

      if conn.entries:
        for entry in conn.entries:
          groupdn = entry.entry_dn
          #userAccountControl = entry['userAccountControl']

          conn.unbind()
          return "GROUP_EXISTS"
      else:
        conn.unbind()
        return "GROUP_NOT_EXIST"




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
            conn.unbind()
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
                conn.unbind()
                return newpassword

          case 528:
            conn.unbind()
            return "ACCOUNT_LOCKED"

          case 530:
            conn.unbind()
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
                conn.unbind()
                return newpassword

      else:
        conn.unbind()
        return "ACCOUNT_NOT_EXISTS"

def add_object(id, sAMAccountName, objclass):
      conn = connect_ldap()
      object_class = objclass
      attr = {
              'sAMAccountName': sAMAccountName,
              #'givenName': givenName,
              #'sn': sn
              }

      dn = "cn=" + id + "," + app.config.get('baseDN')
      conn.add(dn, object_class, attr)
      # add_user('mytestuser', 'mytestuser', 'John', 'Doe')
      result = conn.result
      conn.unbind()
      return result

def delete_object(objid):
      conn = connect_ldap()

      dn = "cn=" + objid + "," + app.config.get('baseDN')
      conn.delete(dn)
      # add_user('mytestuser', 'mytestuser', 'John', 'Doe')
      result = conn.result
      conn.unbind()
      return result

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
    conn.unbind()
    return 1
  conn.unbind()
  return 0
  

def modify_user_attribute(userdn, attribute, newattributevalue):
  conn = connect_ldap()
  # perform the Modify operation
  conn.modify(userdn,{attribute: [(MODIFY_REPLACE, [newattributevalue])]})
  app.logger.info(conn.result)
  conn.unbind()
  return 0


def listUsersInGroup(groupName):
  groupmembers = []
  conn = connect_ldap()
  conn.search('cn='+groupName+','+app.config.get('baseDom'), '(objectClass=group)', 'SUBTREE', attributes = ['member'])
  result = conn.entries
  print('The ' + groupName + ' Member Lists:')
  for en in result:
    for member in en.member.values:
      member = member.split(',')
      print(member[0].replace('CN=',''))
      groupmembers.append(member[0].replace('CN=',''))
  print(groupmembers)
  conn.unbind()
  return groupmembers


def addUserToGroup(userName, groupName):
  conn = connect_ldap()
  response = ''
  conn.search(search_base = app.config.get('baseDom'), search_filter = '(&(objectclass=person)(cn=' + userName + '*))', search_scope='SUBTREE', attributes = ['*'])
  result = conn.entries
  getDn = result[0].distinguishedName
  getDn = str(getDn)
  group = 'CN='+groupName+','+app.config.get('baseDN')
  conn.modify(dn=group, changes={'member': [(MODIFY_ADD, [getDn])]})
  addResult = conn.entries
  if addResult == [ ]:
    print('Successfully added: ' + userName + ' To ' + groupName)
    response = conn.result
  else:
    print('Add Error')
    response = 'Error adding: ' + userName + ' To ' + groupName
  return response
  conn.unbind()

def delUserFromGroup(self, userName, groupName):
  conn = connect_ldap()
  response = ''
  conn.search(search_base = app.config.get('baseDom'), search_filter = '(&(objectclass=person)(cn=' + userName + '*))', search_scope='SUBTREE', attributes = ['*'])
  result = conn.entries
  getDn = result[0].distinguishedName
  getDn = str(getDn)
  group = 'CN='+groupName+','+app.config.get('baseDN')
  conn.modify(dn=group, changes={'member': [(MODIFY_DELETE, [getDn])]})
  delResult = conn.entries
  print(delResult)
  if delResult == [ ]:
    print('Successfully Deleted: ' + userName + ' From ' + groupName + ' !')
    response = ('Success Deleted ' + userName + ' From ' + groupName + ' !')
  else:
    print('Delete Error')
    response = 'Delete Error'
  return response
  conn.unbind()

def checkUserInGroup(userName, groupName):
  conn = connect_ldap()
  user_group_dn = 'CN='+groupName+',CN=Users,DC=samdom,DC=example,DC=com'
  search_filter = "(cn="+userName+")"
  search_attribute =['memberOf']
  conn.search(search_base=app.config.get('baseDN'),
         search_scope=SUBTREE,
         search_filter=search_filter,
         attributes=search_attribute)

  #print('conn.response',conn.response)
  #email = l.response[0]['attributes']['mail']
  memberOf = conn.response[0]['attributes']['memberOf'] #This is the key
  #print(memberOf)

  if user_group_dn in memberOf:
      return "USER_IN_GROUP"
  else:
      return "USER_NOT_IN_GROUP"
  conn.unbind()

def get_all_ldap_objects(objclass):
    
    # Provide a search base to search for.
    search_base = app.config.get('baseDom')
    print(search_base)
    # provide a uidNumber to search for. '*" to fetch all users/groups
    search_filter = '(objectClass='+objclass+')'
    allobjects = []

    # Establish connection to the server
    conn = connect_ldap()
    print(conn)
        
    # only the attributes specified will be returned
    conn.search(search_base=search_base,       
                       search_filter=search_filter,
                       search_scope=SUBTREE, 
                       attributes=['samAccountName', 'cn'])
    # search will not return any values.
    # the entries method in connection object returns the results 
    results = conn.entries
    if results:
      for obj in sorted(results):
        match objclass:
          case 'user':
            if obj.samAccountName.value not in user_exceptions:
              allobjects.append(obj.samAccountName.value)
          case 'group':
            if obj.samAccountName.value not in group_exceptions:
              allobjects.append(obj.cn.value)
      print(allobjects)
      return allobjects
    else:
      return "none"

