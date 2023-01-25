from main import app
import logging

logging.basicConfig(filename='record.log',
                        level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# app.config.from_pyfile('app_config.py')

if __name__ == '__main__':
      app.run(debug=True)
