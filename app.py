from flask import Flask, request, jsonify, session, render_template
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config['SECRET_KEY'] = "asd"

# Database configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskdb_product'
__mysql = MySQL(app)

# List to store invalidated tokens
invalidated_tokens = []

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        # Check if token is in the Authorization header
        if 'Authorization' in request.headers:
            # Token in header starts with "Bearer "
            token = request.headers.get('Authorization').split(' ')[1]
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Token is missing',
                'mimetype': 'application/json'
            }), 403

        if token in invalidated_tokens:
            return jsonify({
                'success': False,
                'message': 'Token has been invalidated',
                'mimetype': 'application/json'
            }), 403

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Pass the token data to the decorated function
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
    cur.execute("SELECT * FROM products")
    data = cur.fetchall()
    cur.close()

    return jsonify(
        {
            'data': data,
            'status': 200,
            'success': True,
            'mimetype': 'application/json'
        }
    )

@app.route('/product/<id>', methods=["GET"])
@token_required
def getProductById(data, id):
    cur = __mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE id = %s", (id))
    product = cur.fetchone()
    cur.close()

    if product:
        return jsonify(
            {
                'data': {
                    'id': product[0],
                    'name': product[1],
                    'price': product[2],
                    'unit': product[3]
                },
                'status': 200,
                'success': True,
                'mimetype': 'application/json'
            }
        )
    else:
        return jsonify(
            {
                'message': 'Product not found',
                'status': 404,
                'success': False,
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
        cur.execute("DELETE FROM products WHERE id = %s", (id,))
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

@app.route('/register', methods=['POST'])
def userStore():
    try:
        # catch data
        username = request.json['username']
        password = request.json['password']

        # Encrypt password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Input data
        cur = __mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password.decode('utf-8')))
        __mysql.connection.commit()
        cur.close()

        return jsonify({
            'success': True,
            'message': "User's data successfully stored to the database",
            'mimetype': 'application/json'
        }), 201
    except Exception as e:
        __mysql.connection.rollback()
        return jsonify({
            'success': False, 
            'message': 'Error occurred while storing data to the database: {}'.format(str(e)),
            'mimetype': 'application/json'
        }), 400
    
@app.route('/login', methods=['POST'])
def login():
    try:
        # Catch data
        username = request.json['username']
        password = request.json['password']

        # Check user
        cur = __mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['logged_in'] = True
            token = jwt.encode({
                'user': username,
                'expiration': str(datetime.utcnow() + timedelta(seconds=120))
            }, app.config['SECRET_KEY'])

            return jsonify({
                'success': True,
                'token': token,
                'message': "Login successful",
                'status': 200,
                'mimetype': 'application/json'
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'Unable to verify',
                'mimetype': 'application/json'
            }), 403

    except Exception as e:
        return jsonify({
            'success': False, 
            'message': f'Error occurred while storing data to the database: {str(e)}',
            'status': 400,
            'mimetype': 'application/json'
        })  

@app.route('/app/login', methods=['GET'])
def appLogin(): 
    return render_template('login.html')

@app.route('/app/product-read', methods=['GET'])
def ReadProduct(): 
    return render_template('readProduct.html')

@app.route('/app/product-create', methods=['GET'])
def CreateProduct(): 
    return render_template('createProduct.html')

@app.route('/app/product-edit/<id>', methods=['GET'])
def editProductPage(id): 
    return render_template('editProduct.html', product_id=id)

@app.route('/app/predict-food', methods=['GET'])
def predictFood():
    return render_template('predictFood.html')


@app.route('/logout', methods=['POST'])
@token_required
def logout(decoded_token):
    try:
        token = request.headers.get('Authorization').split(' ')[1]
        invalidated_tokens.append(token)
        session.pop('logged_in', None)
        return jsonify({
            'success': True,
            'message': 'Logged out successfully',
            'status': 200,
            'mimetype': 'application/json'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error occurred while logging out: {str(e)}',
            'status': 400,
            'mimetype': 'application/json'
        })

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))