# seed.py
import random, psycopg2
from utils import aes_gcm_encrypt, row_hmac, merkle_leaf

DB = dict(dbname="securedb", user="secureuser", password="securepass", host="localhost")

# Demo keys (in practice keep safe!)
K_ENC = b"0"*32   # 32 bytes AES key
K_MAC = b"1"*32

first_names = ["Alice", "Bob", "Carol", "David", "Eve"]
last_names  = ["Smith", "Johnson", "Lee", "Brown", "Taylor"]
histories   = ["healthy", "diabetic", "asthma", "hypertension", "smoker"]

def canonical_row(row_id, fn, ln, gender, age, wt, ht, hist):
    return f"{row_id}|{fn}|{ln}|{gender}|{age}|{wt}|{ht}|{hist}".encode()

def main():
    conn = psycopg2.connect(**DB)
    cur = conn.cursor()

    for i in range(100):
        fn = random.choice(first_names)
        ln = random.choice(last_names)
        gender = random.choice([0,1])
        age = random.randint(18, 90)
        wt = round(random.uniform(50, 100), 1)
        ht = round(random.uniform(150, 200), 1)
        hist = random.choice(histories)

        # encrypt sensitive fields
        nonce_g, ct_g = aes_gcm_encrypt(K_ENC, gender.to_bytes(1,"big"))
        nonce_a, ct_a = aes_gcm_encrypt(K_ENC, age.to_bytes(2,"big"))

        # compute MAC + leaf
        mac = row_hmac(K_MAC, canonical_row(i, fn, ln, gender, age, wt, ht, hist))
        leaf = merkle_leaf(mac, i)

        cur.execute("""
        INSERT INTO patients (first_name,last_name,gender_ct,gender_nonce,
                              age_ct,age_nonce,weight,height,health_history,
                              row_mac,leaf_hash)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (fn, ln, ct_g, nonce_g, ct_a, nonce_a, wt, ht, hist, mac, leaf))

    conn.commit()
    cur.close(); conn.close()

if __name__ == "__main__":
    main()
