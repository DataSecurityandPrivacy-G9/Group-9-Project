# db.py
import psycopg2

def get_db():
    return psycopg2.connect(
        dbname="securedb",
        user="secureuser",
        password="securepass",
        host="localhost"
    )
