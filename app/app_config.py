# Flask cobfig

from app import app

app.config['LDAPserver'] = "192.168.1.78"
app.config['LDAPuser'] = "samdom\\administrator"
#app.config['LDAPpassword'] = "5ambaPwd@"
app.config['LDAPpassword'] = "Yi1se@i^h0"
app.config['baseDN'] = "CN=users,DC=samdom,DC=example,DC=com"
app.config['baseDom'] = "DC=samdom,DC=example,DC=com"
#app.config['SECRET_KEY'] = 'hjjlkJJHIGIH6glHGGF'
app.config['DEBUG_LOGGING'] = 1
