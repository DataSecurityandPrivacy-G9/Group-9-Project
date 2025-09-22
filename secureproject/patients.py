from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import get_db
from utils import build_merkle_tree  # import Merkle helper

patients_bp = Blueprint("patients", __name__)

# =========================
# GET all patients (role-based view)
# =========================
@patients_bp.route("/", methods=["GET"])
@jwt_required()
def get_patients():
    user = get_jwt_identity()
    role = user["role"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT id, first_name, last_name, gender_ct, age_ct,
                          weight, height, health_history, row_mac, leaf_hash
                   FROM patients ORDER BY id ASC""")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    result = []
    for r in rows:
        row = {
            "id": r[0],
            "gender_ct": r[3].hex(),
            "age_ct": r[4].hex(),
            "weight": r[5],
            "height": r[6],
            "health_history": r[7],
            "row_mac": r[8].hex(),
            "leaf_hash": r[9].hex()
        }
        if role == "H":
            row["first_name"], row["last_name"] = r[1], r[2]
        result.append(row)

    return jsonify(result)

# =========================
# POST add new patient (H only)
# =========================
@patients_bp.route("/", methods=["POST"])
@jwt_required()
def add_patient():
    user = get_jwt_identity()
    if user["role"] != "H":
        return jsonify({"msg": "Forbidden"}), 403

    data = request.json
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""INSERT INTO patients
                   (first_name,last_name,gender_ct,gender_nonce,
                    age_ct,age_nonce,weight,height,health_history,row_mac,leaf_hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (data["first_name"], data["last_name"],
                 bytes.fromhex(data["gender_ct"]), bytes.fromhex(data["gender_nonce"]),
                 bytes.fromhex(data["age_ct"]), bytes.fromhex(data["age_nonce"]),
                 data["weight"], data["height"], data["health_history"],
                 bytes.fromhex(data["row_mac"]), bytes.fromhex(data["leaf_hash"])))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"msg": "Inserted"}), 201

# =========================
# GET patients with Merkle proofs
# =========================
@patients_bp.route("/with_proofs", methods=["GET"])
@jwt_required()
def get_patients_with_proofs():
    user = get_jwt_identity()
    role = user["role"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT id, first_name, last_name, gender_ct, age_ct,
                          weight, height, health_history, row_mac, leaf_hash
                   FROM patients ORDER BY id ASC""")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Leaves = leaf_hashes from DB
    leaves = [r[9] for r in rows]
    if not leaves:
        return jsonify({"root": None, "patients": []})

    root, levels = build_merkle_tree(leaves)

    result = []
    for idx, r in enumerate(rows):
        row = {
            "id": r[0],
            "gender_ct": r[3].hex(),
            "age_ct": r[4].hex(),
            "weight": r[5],
            "height": r[6],
            "health_history": r[7],
            "row_mac": r[8].hex(),
            "leaf_hash": r[9].hex(),
            # simple proof: sibling at each tree level
            "proof": []
        }
        for level in levels[:-1]:  # skip the root level
            sib_index = idx ^ 1 if idx ^ 1 < len(level) else idx
            row["proof"].append(level[sib_index].hex())
            idx //= 2
        if role == "H":
            row["first_name"], row["last_name"] = r[1], r[2]
        result.append(row)

    return jsonify({"root": root.hex(), "patients": result})

# =========================
# GET current Merkle root
# =========================
@patients_bp.route("/merkle_root", methods=["GET"])
@jwt_required()
def get_merkle_root():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT leaf_hash FROM patients ORDER BY id ASC")
    leaves = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()

    if not leaves:
        return jsonify({"root": None})

    root, _ = build_merkle_tree(leaves)
    return jsonify({"root": root.hex()})
