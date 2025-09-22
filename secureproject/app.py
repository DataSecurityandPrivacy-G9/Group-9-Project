# app.py
from flask import Flask
from flask_jwt_extended import JWTManager
import psycopg2

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)

def get_db():
    return psycopg2.connect(
        dbname="securedb",
        user="secureuser",
        password="securepass",
        host="localhost"
    )

# import blueprints
from auth import auth_bp
from patients import patients_bp

app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(patients_bp, url_prefix="/patients")

if __name__ == "__main__":
    app.run(debug=True)
