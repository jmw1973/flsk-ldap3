from flask import Flask


app = Flask(__name__)
app.config.from_pyfile('app_config.py')

if __name__ == '__main__':
  app.run()
