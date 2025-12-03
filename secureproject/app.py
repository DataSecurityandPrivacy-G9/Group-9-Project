# app.py
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS

from auth import auth_bp
from patients import patients_bp

app = Flask(__name__)

# SECRET
app.config["JWT_SECRET_KEY"] = "super-secret-change-me"

# JWT CONFIG — HEADERS ONLY
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_HEADER_NAME"] = "Authorization"
app.config["JWT_HEADER_TYPE"] = "Bearer"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

# --- CORS CONFIG ---

# For development, just allow everything from anywhere.
# This guarantees the React dev server at 127.0.0.1:5173 can talk to 127.0.0.1:5000.
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
)

jwt = JWTManager(app)

# --------- ERROR HANDLERS ---------


@jwt.invalid_token_loader
def invalid_token_callback(msg):
    return jsonify({"msg": f"Invalid token: {msg}"}), 422


@jwt.unauthorized_loader
def missing_token_callback(msg):
    return jsonify({"msg": f"Missing token: {msg}"}), 401


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"msg": "Token expired"}), 401


@app.errorhandler(422)
def handle_422(e):
    return jsonify({"msg": "Unprocessable", "details": str(e)}), 422


# --------- BLUEPRINTS ---------

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(patients_bp, url_prefix="/patients")


if __name__ == "__main__":
    # host="0.0.0.0" makes it reachable from Windows browser via localhost when running in WSL
    app.run(debug=True, host="0.0.0.0", port=5000)
