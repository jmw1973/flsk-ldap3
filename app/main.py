from flask import Flask, request, redirect, render_template, url_for, session
from app import app
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL, MODIFY_REPLACE
import jwt
import requests, base64, json, getpass, sys, os
import logging, secrets, string
from ldap3 import (HASHED_SALTED_SHA, MODIFY_REPLACE)
from ldap3.utils.hashed import hashed
import forms, utils
from flask_wtf.csrf import CSRFProtect
import uuid
import git

sys.path.append('/usr/local/lib/python3.9/site-packages')

app = Flask(__name__)
csrf = CSRFProtect(app)
requestNumber = 0

if not app.debug:
  # In production mode, add log handler to sys.stderr.
  app.logger.addHandler(logging.StreamHandler())
  app.logger.setLevel(logging.INFO)

SECRET_KEY = os.urandom(32)

app.config['SECRET_KEY'] = SECRET_KEY

user_account_name = "testuser2" # test for now

gitSourceFileURL = "git@github.com:jmw1973/gy_user_control.git"
region = 'eu-west-2'
jwt_token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTAxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJqb2huMTU5OTlAdGVzdC5jb20iLCJpYXQiOjE1MTYyMzkwMjJ9.sscGxWF8WncETBGsACLFvJwDhbWHr0Z3la3Be3VP1uGwh1w76-ho2JkH2nG0KnVSm-sPMRDmVghP_S26vpfSiQ" # test

     #
# setup ssh
#if not os.path.exists("~/.ssh"):
#     os.makedirs("~/.ssh")

os.system('ssh-keyscan github.com > ~/.ssh/known_hosts')
#setup git
os.system('git config --global user.email "gy@test.com"')
os.system('git config --global user.name "gy"')

@app.route('/healthz')
def healtcheck():
  return "200"

@app.route('/')
def auth():

  headers_dict = request.__dict__

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


@app.route('/closePage', methods=['GET'])
def closepage():
    form = forms.closePage()
    return render_template('closepage.jinja2', form=form, title="Close Page")


@app.route('/requestAccount', methods=['GET', 'POST'])
def requestAccount():
    # todo check jwt token is valid and extract username
    form = forms.SignupForm()
    return render_template('requestAccount.jinja2', form=form, userlogonname=user_account_name, title="Request Account")

@app.route('/submitRequestAccountForm', methods=['POST'])
@csrf.exempt
def submitRequestAccountForm():
   from git import Repo

   global requestNumber
   logonName = request.form['logonName']
   tenantName = request.form['tenantName']
   otherInfo = request.form['otherInfo']

   # first check if session has already made a request
   #logonnamecheck = session['logonname']
   #session['tenant']

   if requestNumber > 0:
     # request already submitted for this user and tenant during this session
     return "", 410
     
   # clone repo into random uuid name
   repo_uuid = uuid.uuid4()
   repo_path = "/tmp/"+str(repo_uuid)+"/"
   repo_name = "gy_user_control"
   repoSourceFile = "sourceData.yaml"

   if not os.path.exists(repo_path):
     os.makedirs(repo_path)
     app.logger.info("Created folder: "+repo_path+" for local repo")
     app.logger.info("Cloning from repo: "+gitSourceFileURL)

   #git.Git(repo_path).clone(gitSourceFileURL)
   #repo = git.Repo(repo_path+repo_name)
   #repo.git.checkout('-b', str(repo_uuid))

   # make change to file
   #updateyamlfile = utils.update_yaml_file(repo_path+repo_name+"/"+repoSourceFile, tenantName, logonName)
   updateyamlfile = utils.update_yaml_file('ezmeral.yaml', tenantName, logonName)

   try:
     #repo.git.add('--all')
     #repo.git.commit('-m', 'commit for: '+str(repo_uuid))#, author='gy@test.com')
     #origin = repo.remote(name='origin')
     #push_res = origin.push(str(repo_uuid))[0]
     app.logger.info("ACCOUNT REQUEST SUBMITTED: LogonName: " +logonName+" Tenant: "+tenantName+" OtherInfo: "+otherInfo)
     # set session variables for current request
     requestNumber += 1
     return "201"
   except:
     app.logger.error("Push for Branch: "+str(repo_uuid)+" Failed!")
     return False

@app.route('/processDataFile')
def processDataFile():
    processedDataFile = utils.process_data_file()
    return processedDataFile

@app.route('/checkuseringroup')
def checkusergroups():
    check = utils.checkUserInGroup('tg3user1', 'tg3_users')
    #app.logger.info(check)
    return(check)

@app.route('/getallusers') #test
def getallusers():
    allusers = utils.get_all_ldap_objects('user')
    return allusers

@app.route('/getallgroups') #test
def getallgroups():
    allgroups = utils.get_all_ldap_objects('group')
    return allgroups

@app.route('/getallusersingroup') #test
def getallusersingroup():
    allusersingroup = utils.listUsersInGroup('tg3_users')
    return allusersingroup

@app.route('/getkid') #test
def getkid():
  kid = utils.get_kid(jwt_token)
  return kid

@app.route('/testpayload') #test
def testpayload():
  payload = utils.test_payload(jwt_token)
  return payload


if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True)



