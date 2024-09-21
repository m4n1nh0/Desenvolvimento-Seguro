from flask import Flask, request
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import re

from backend.src.config import SECRET_KEY
from backend.src.routes import create_routes

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = SECRET_KEY
jwt = JWTManager(app)

CORS(app, resources={r"/*": {"origins": "http://localhost"}})


def sanitize_header_value(value):
    """Sanitiza o valor do cabeçalho para evitar injeção de cabeçalhos."""
    if not value:
        return value
    # Remove caracteres de nova linha e outros caracteres potencialmente perigosos
    return re.sub(r'[\r\n]', '', value)


@app.before_request
def sanitize_request_headers():
    """Sanitiza cabeçalhos específicos de requisições."""
    user_agent = request.headers.get('User-Agent')
    if user_agent:
        sanitized_user_agent = sanitize_header_value(user_agent)
        request.headers.environ['HTTP_USER_AGENT'] = sanitized_user_agent


create_routes(app)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
