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

app.config['SECRET_KEY'] = 'hjjlkJJHIGIH6glHGGF'
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
    checkUserAccount = utils.process_user(user_account_name)
    app.logger.info(checkUserAccount)

  if checkUserAccount != "ACCOUNT_NOT_EXISTS":
    app.logger.info(user_account_name + ": user has existing account, enabling account and returning new password")
    # newpassword = generate_password()
    return checkUserAccount
  else:
    app.logger.info(user_account_name + ": user has no existing account, going to run through account provisioning workflow")
    return redirect(url_for('requestAccount'))

@app.route('/requestAccount',methods=['GET', 'POST'])
def requestAccount():
    # todo check jwt token is valid and extract username
    form = forms.SignupForm()
    return render_template('requestAccount.jinja2', form=form, title="Request Account")
