from flask import Flask, request, redirect, render_template, url_for
from app import app
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL, MODIFY_REPLACE
import jwt, requests, base64, json, getpass, sys
import logging, secrets, string
from ldap3 import (HASHED_SALTED_SHA, MODIFY_REPLACE)
from ldap3.utils.hashed import hashed
import forms, utils

sys.path.append('/usr/local/lib/python3.9/site-packages')

app = Flask(__name__)

if not app.debug:
  # In production mode, add log handler to sys.stderr.
  app.logger.addHandler(logging.StreamHandler())
  app.logger.setLevel(logging.INFO)

#app.config['SECRET_KEY'] = "hjjlkJJHIGIH6glHGGF"
#app.config['LDAPserver'] = "192.168.0.20"
#app.config['LDAPuser'] = "samdom\\administrator"
#app.config['LDAPpassword'] = "Yi1se@i^h0"
#app.config['baseDN'] = "cn=users,dc=samdom,dc=example,dc=com"
#app.config['baseDom'] = "dc=samdom,dc=example,dc=com"
#app.config['DEBUG_LOGGING'] = 1


@app.route('/healthz')
def healtcheck():
  return "200"

@app.route('/')
def auth():
  headers_dict = request.__dict__
  region = 'eu-west-2'
  jwt_token = "787655" # dummy for now
  user_account_name = "testuser2" # test for now

  if jwt_token:
    app.logger.info(user_account_name + ": user has authenticated ok: now checking if they have an existing account")
    checkUserAccount = utils.process_user(user_account_name)
    app.logger.info(checkUserAccount)

    match checkUserAccount:
      case "ACCOUNT_NORMAL":
        app.logger.info(user_account_name + ": user account is in normal state, no action required")
        return checkUserAccount

      case "ACCOUNT_NOT_EXISTS": 
        app.logger.info(user_account_name + ": user has no existing account, going to run through account provisioning workflow")
        return redirect(url_for('requestAccount'))

      case _:
        app.logger.info(user_account_name + ": user has an existing account, going to run through account provisioning workflow")
        return checkUserAccount
  else:
    app.logger.info("user was not authenticated!")
    return "User was not authenticated!"


@app.route('/requestAccount',methods=['GET', 'POST'])
def requestAccount():
    # todo check jwt token is valid and extract username
    form = forms.SignupForm()
    return render_template('requestAccount.jinja2', form=form, title="Request Account")

@app.route('/processDataFile')
def processDataFile():
    processedDataFile = utils.process_data_file()
    return processedDataFile

@app.route('/checkuseringroup')
def checkusergroups():
    check = utils.checkUserInGroup('gogo3', 'CSC-AGENT')
    #app.logger.info(check)
    return(check)

if __name__ == '__main__':
        app.run(host='0.0.0.0', debug=True)
