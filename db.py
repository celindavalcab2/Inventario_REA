import os
from flask_mysqldb import MySQL
from dotenv import load_dotenv

load_dotenv()

mysql = MySQL()

def init_db(app):
    app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost').strip()
    app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root').strip()
    app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
    app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 3306))
    app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'railway').strip()
    app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

    mysql.init_app(app)