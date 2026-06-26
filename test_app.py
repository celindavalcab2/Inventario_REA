from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "FUNCIONA BASE"

@app.route('/login')
def login():
    return "LOGIN OK"

if __name__ == '__main__':
    app.run(debug=True)