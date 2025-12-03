# seed.py
# -*- coding: utf-8 -*-

import random
import psycopg2

from utils import aes_gcm_encrypt, canonical_row, row_hmac, merkle_leaf, K_ENC, K_MAC

DB = dict(dbname="securedb", user="secureuser", password="securepass", host="localhost")

first_names = ["Alice", "Bob", "Carol", "David", "Eve"]
last_names = ["Smith", "Johnson", "Lee", "Brown", "Taylor"]
histories = ["healthy", "diabetic", "asthma", "hypertension", "smoker"]


def main():
    conn = psycopg2.connect(**DB)
    cur = conn.cursor()

    # wipe existing patients
    cur.execute("DELETE FROM patients")

    for _ in range(100):
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        gender = random.choice([0, 1])
        age = random.randint(18, 90)
        wt = round(random.uniform(50, 100), 1)
        ht = round(random.uniform(150, 200), 1)
        hist = random.choice(histories)

        # Encrypt sensitive fields
        nonce_g, ct_g = aes_gcm_encrypt(K_ENC, gender.to_bytes(1, "big"))
        nonce_a, ct_a = aes_gcm_encrypt(K_ENC, age.to_bytes(2, "big"))

        # Insert first to get real DB id
        cur.execute(
            """
            INSERT INTO patients
            (first_name,last_name,
             gender_ct,gender_nonce,
             age_ct,age_nonce,
             weight,height,health_history,
             row_mac,leaf_hash)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'','')
            RETURNING id
            """,
            (fn, ln, ct_g, nonce_g, ct_a, nonce_a, wt, ht, hist),
        )
        row_id = cur.fetchone()[0]

        # Compute MAC + leaf using EXACT same canonical_row as verification
        msg = canonical_row(row_id, fn, ln, wt, ht, hist)
        mac = row_hmac(K_MAC, msg)
        leaf = merkle_leaf(mac, row_id)

        cur.execute(
            "UPDATE patients SET row_mac=%s, leaf_hash=%s WHERE id=%s",
            (mac, leaf, row_id),
        )

    conn.commit()
    cur.close()
    conn.close()
    print("✓ Seed complete")


if __name__ == "__main__":
    main()
