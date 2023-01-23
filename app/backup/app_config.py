# Flask cobfig

from app import app

app.config['LDAPserver'] = '192.168.1.78'
app.config['LDAPuser'] = "samdom\\administrator"
app.config['LDAPpassword'] = "5ambaPwd@"
app.config['baseDN'] = "cn=users,dc=samdom,dc=example,dc=com"
app.config['baseDom'] = "dc=samdom,dc=example,dc=com"
