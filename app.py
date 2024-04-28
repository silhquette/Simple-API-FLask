from flask import Flask, request, jsonify, session
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config['SECRET_KEY'] = "asd"

# Database config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskdb_product'
__mysql = MySQL(app)

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        # Cek apakah token ada dalam header Authorization
        if 'Authorization' in request.headers:
            # Token di header dimulai dengan "Bearer "
            token = request.headers.get('Authorization').split(' ')[1]
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Token is missing',
                'mimetype': 'application/json'
            }), 403

        try:
            # Mendekode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Meneruskan data token ke fungsi yang didekorasi
            return func(data, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({
                'success': False,
                'message': 'Token is expired',
                'mimetype': 'application/json'
            }), 403
        except jwt.InvalidTokenError:
            return jsonify({
                'success': False,
                'message': 'Invalid token',
                'mimetype': 'application/json'
            }), 403

    return decorated

@app.route('/product', methods = ["GET"])
@token_required
def productIndex(data):
    cur = __mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    data = cur.fetchall()
    cur.close()

    return jsonify(
        {
            'data': data,
            'status': 200,
            'mimetype': 'application/json'
        }
    )

@app.route('/product', methods = ['POST'])
@token_required
def productStore(data):
    try:
        # catch data
        name = request.json['name']
        price = request.json['price']
        unit = request.json['unit']

        # Input data
        cur = __mysql.connection.cursor()
        cur.execute("INSERT INTO products (name, price, unit) VALUES (%s, %s, %s)", (name, price, unit))
        __mysql.connection.commit()
        return jsonify(
            {
                'success': True,
                'message': 'Data successfully stored to the database',
                'status': 201,
                'mimetype': 'application/json'
            }
        )
    except Exception as e:
        # Jika terjadi kesalahan, rollback perubahan dan kirim respons yang sesuai
        __mysql.connection.rollback()
        return jsonify(
            {
                'success': False, 
                'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
                'status' : 400,
                'mimetype': 'application/json'
            }
        )

@app.route('/product/<id>', methods = ['DELETE'])
@token_required
def productDestroy(data, id):
    try:
        cur = __mysql.connection.cursor()
        cur.execute("DELETE FROM products WHERE id = %s", (id))
        __mysql.connection.commit()

        if cur.rowcount > 0:
            return jsonify(
                {
                    'success': True,
                    'message': 'Data successfully deleted from the database',
                    'status': 200,
                    'mimetype': 'application/json'
                }
            )
        else:
            return jsonify(
                {
                    'success': False, 
                    'message': 'Data with the specified ID not found',
                    'status' : 404,
                    'mimetype': 'application/json'
                }
            )
    except Exception as e:
        # Jika terjadi kesalahan, rollback perubahan dan kirim respons yang sesuai
        __mysql.connection.rollback()
        return jsonify(
            {
                'success': False, 
                'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
                'status' : 400,
                'mimetype': 'application/json'
            }
        )

@app.route('/product/<id>', methods = ['PATCH', 'PUT'])
@token_required
def updateProduct(data, id):
    try:
        # Ambil data yang ingin diupdate dari request JSON
        name = request.json['name']
        price = request.json['price']
        unit = request.json['unit']

        # Perbarui data dalam database
        cur = __mysql.connection.cursor()
        cur.execute("UPDATE products SET name = %s, price = %s, unit = %s WHERE id = %s", (name, price, unit, id))
        __mysql.connection.commit()

        # Periksa apakah ada baris yang terpengaruh (update berhasil)
        if cur.rowcount > 0:
            return jsonify(
                {
                    'success': True,
                    'message': 'Data successfully updated from the database',
                    'mimetype': 'application/json'
                }
            ), 200
        else:
            return jsonify(
                {
                    'success': False, 
                    'message': 'Data with the specified ID not found',
                    'mimetype': 'application/json'
                }
            ), 404
    except Exception as e:
        # Jika terjadi kesalahan, rollback perubahan dan kirim respons yang sesuai
        __mysql.connection.rollback()
        return jsonify(
            {
                'success': False, 
                'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
                'mimetype': 'application/json'
            }
        ), 400

@app.route('/user', methods = ['POST'])
def userStore():
    try:
        # catch data
        username = request.json['username']
        password = request.json['password']

        # Input data
        cur = __mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        __mysql.connection.commit()
        return jsonify(
            {
                'success': True,
                'message': "User's data successfully stored to the database",
                'mimetype': 'application/json'
            }
        ), 201
    except Exception as e:
        # Jika terjadi kesalahan, rollback perubahan dan kirim respons yang sesuai
        __mysql.connection.rollback()
        return jsonify(
            {
                'success': False, 
                'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
                'mimetype': 'application/json'
            }
        ), 400
    
@app.route('/login', methods = ['POST'])
def login():
    try:
        # catch data
        username = request.json['username']
        password = request.json['password']

        # check user
        cur = __mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        data = cur.fetchall()
        cur.close()

        if data:
            session['logged_in'] = True
            token = jwt.encode({
                'user': username,
                'expiration': str(datetime.utcnow() + timedelta(seconds = 120))
            }, app.config['SECRET_KEY'])

            return jsonify(
                {
                    'success': True,
                    'token': token,
                    'message': "Log in successful",
                    'status': 200,
                    'mimetype': 'application/json'
                }
            )
        else : 
            return jsonify(
                {
                    'success': False, 
                    'message': 'Unable to verify',
                    'mimetype': 'application/json'
                }
            ), 403

    except Exception as e:
        # Jika terjadi kesalahan, rollback perubahan dan kirim respons yang sesuai
        __mysql.connection.rollback()
        return jsonify(
            {
                'success': False, 
                'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
                'status' : 400,
                'mimetype': 'application/json'
            }
        )

if __name__ == '__main__':
    app.run(debug=True)