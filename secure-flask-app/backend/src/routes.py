import time

from flask import jsonify, request
from flask_jwt_extended import create_access_token, jwt_required
from passlib.hash import pbkdf2_sha256

from backend.src.config import login_attempts, ATTEMPT_LIMIT, BLOCK_TIME

# Mock database (Pode ser alterado por algum outro valor)
mock_db = {
    'username': {'password': pbkdf2_sha256.hash('password123')}  # Example user
}


def create_routes(app):
    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify(message="usuario e senhas requeridos"), 400

        if username in mock_db:
            return jsonify(message="Usuario já existe"), 409

        hashed_password = pbkdf2_sha256.hash(password)
        mock_db[username] = {'password': hashed_password}

        return jsonify(message="Usuario cadastrado com sucesso"), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify(message="Username and password are required"), 400

        user = mock_db.get(username)
        current_time = time.time()
        attempt_info = login_attempts[username]

        # Check if the user is currently blocked
        if attempt_info['attempts'] >= ATTEMPT_LIMIT:
            if current_time - attempt_info['timestamp'] < BLOCK_TIME:
                return jsonify(message="Too many login attempts. Please try again later."), 429
            else:
                # Reset attempt count after block time
                attempt_info['attempts'] = 0
                attempt_info['timestamp'] = current_time

        if user and pbkdf2_sha256.verify(password, user['password']):
            # Reset attempt count on successful login
            attempt_info['attempts'] = 0
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200

        # Increment attempt count on failure
        attempt_info['attempts'] += 1
        attempt_info['timestamp'] = current_time

        return jsonify(message="Invalid credentials"), 401

    @app.route('/secure-data', methods=['GET'])
    @jwt_required()
    def secure_data():
        return jsonify(data="This is secured data"), 200
