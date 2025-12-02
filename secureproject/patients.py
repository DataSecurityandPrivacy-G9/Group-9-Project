# patients.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from db import get_db
from utils import canonical_row, row_hmac, merkle_root_from_leaves, K_MAC

patients_bp = Blueprint("patients", __name__)


@patients_bp.route("/", methods=["GET"])
@jwt_required()
def get_patients():
    claims = get_jwt()
    role = claims["role"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, first_name, last_name,
               gender_ct, gender_nonce,
               age_ct, age_nonce,
               weight, height, health_history,
               row_mac, leaf_hash
        FROM patients
        ORDER BY id ASC
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    result = []
    for r in rows:
        row_id = r[0]
        fn, ln = r[1], r[2]
        gender_ct, gender_nonce = r[3], r[4]
        age_ct, age_nonce = r[5], r[6]
        weight, height = r[7], r[8]
        history = r[9]
        stored_mac = bytes(r[10])  # memoryview -> bytes
        leaf = bytes(r[11])        # currently unused here, but kept

        # Recompute MAC using SAME canonical_row and K_MAC as seed.py
        msg = canonical_row(row_id, fn, ln, weight, height, history)
        recomputed = row_hmac(K_MAC, msg)

        if recomputed != stored_mac:
            return jsonify({"msg": "Signature verification failed"}), 422

        row_obj = {
            "id": row_id,
            "gender_ct": gender_ct.hex(),
            "gender_nonce": gender_nonce.hex(),
            "age_ct": age_ct.hex(),
            "age_nonce": age_nonce.hex(),
            "weight": weight,
            "height": height,
            "health_history": history,
        }

        if role == "H":
            row_obj["first_name"] = fn
            row_obj["last_name"] = ln

        result.append(row_obj)

    return jsonify(result)


@patients_bp.route("/", methods=["POST"])
@jwt_required()
def add_patient():
    claims = get_jwt()
    if claims["role"] != "H":
        return jsonify({"msg": "Forbidden"}), 403

    data = request.json or {}
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO patients
        (first_name,last_name,
         gender_ct,gender_nonce,
         age_ct,age_nonce,
         weight,height,health_history,
         row_mac,leaf_hash)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            data["first_name"],
            data["last_name"],
            bytes.fromhex(data["gender_ct"]),
            bytes.fromhex(data["gender_nonce"]),
            bytes.fromhex(data["age_ct"]),
            bytes.fromhex(data["age_nonce"]),
            data["weight"],
            data["height"],
            data["health_history"],
            bytes.fromhex(data["row_mac"]),
            bytes.fromhex(data["leaf_hash"]),
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"msg": "Inserted"}), 201


@patients_bp.route("/merkle_root", methods=["GET"])
@jwt_required()
def get_merkle_root():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT leaf_hash FROM patients ORDER BY id")
    leaves = [bytes(row[0]) for row in cur.fetchall()]
    cur.close()
    conn.close()

    if not leaves:
        return jsonify({"merkle_root": None})

    root = merkle_root_from_leaves(leaves)
    return jsonify({"merkle_root": root.hex()})
