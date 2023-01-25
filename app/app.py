from flask import Flask
import logging

app = Flask(__name__)
app.config.from_pyfile('app_config.py')


logging.basicConfig(filename='record.log',
        level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
#if __name__ == '__main__':
#  app.run(debug=True)
