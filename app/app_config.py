# Flask cobfig

from app import app

app.config['LDAPserver'] = "192.168.0.20"
app.config['LDAPuser'] = "samdom\\administrator"
#app.config['LDAPpassword'] = "5ambaPwd@"
app.config['LDAPpassword'] = "Yi1se@i^h0"
app.config['baseDN'] = "cn=users,dc=samdom,dc=example,dc=com"
app.config['baseDom'] = "dc=samdom,dc=example,dc=com"
app.config['SECRET_KEY'] = 'hjjlkJJHIGIH6glHGGF'
app.config['DEBUG_LOGGING'] = 1
