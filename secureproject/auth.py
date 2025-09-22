from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from app import get_db

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username, password, role = data["username"], data["password"], data["role"]

    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, pw_hash, role) VALUES (%s, %s, %s)",
                (username, pw_hash, role))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"msg": "User created"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, pw_hash, role FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row: return jsonify({"msg": "Bad credentials"}), 401
    user_id, pw_hash, role = row

    if not bcrypt.check_password_hash(pw_hash, password):
        return jsonify({"msg": "Bad credentials"}), 401

    token = create_access_token(identity={"id": user_id, "role": role})
    return jsonify(access_token=token)
