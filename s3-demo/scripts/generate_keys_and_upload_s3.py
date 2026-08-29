#!/usr/bin/env python3
import os
import json
import base64
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def int_to_base64url(val: int) -> str:
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('=')

def main():
    kid = "demo-auth-key-1"
    bucket_name = "auth-bucket"
    s3_key = "jwks.json"
    endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")

    print(f"[*] Generating RSA 2048 Key Pair for kid: '{kid}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Export private key in PKCS#8 PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Paths for resources
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    main_res_dir = os.path.join(base_dir, "src", "main", "resources")
    test_res_dir = os.path.join(base_dir, "src", "test", "resources")
    os.makedirs(main_res_dir, exist_ok=True)
    os.makedirs(test_res_dir, exist_ok=True)

    pem_main_path = os.path.join(main_res_dir, "private_key.pem")
    pem_test_path = os.path.join(test_res_dir, "private_key.pem")

    with open(pem_main_path, "wb") as f:
        f.write(private_pem)
    with open(pem_test_path, "wb") as f:
        f.write(private_pem)

    print(f"[+] Private key saved to: {pem_main_path}")

    # Build JWKS JSON from public key numbers
    public_numbers = private_key.public_key().public_numbers()
    n_b64 = int_to_base64url(public_numbers.n)
    e_b64 = int_to_base64url(public_numbers.e)

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n_b64,
        "e": e_b64
    }

    jwks = {
        "keys": [jwk]
    }
    jwks_json = json.dumps(jwks, indent=2).encode('utf-8')

    print(f"[*] Generated JWKS:\n{jwks_json.decode('utf-8')}")

    # Create bucket and upload to LocalStack S3 using S3 REST API (works without boto3)
    bucket_url = f"{endpoint_url}/{bucket_name}"
    object_url = f"{endpoint_url}/{bucket_name}/{s3_key}"

    print(f"[*] Creating bucket '{bucket_name}' on LocalStack: {bucket_url}...")
    create_bucket_req = urllib.request.Request(bucket_url, method="PUT")
    try:
        with urllib.request.urlopen(create_bucket_req) as resp:
            print(f"[+] Bucket created/verified (status {resp.status})")
    except urllib.error.HTTPError as err:
        if err.code in (200, 409):
            print(f"[+] Bucket already exists (status {err.code})")
        else:
            print(f"[-] HTTP Error creating bucket: {err}")
    except Exception as e:
        print(f"[-] Could not connect to LocalStack at {endpoint_url}: {e}")
        print("[!] Note: Start LocalStack via docker-compose up -d before running upload")

    print(f"[*] Uploading '{s3_key}' to {object_url}...")
    upload_req = urllib.request.Request(
        object_url,
        data=jwks_json,
        headers={"Content-Type": "application/json"},
        method="PUT"
    )
    try:
        with urllib.request.urlopen(upload_req) as resp:
            print(f"[+] Successfully uploaded JWKS to S3! (status {resp.status})")
    except Exception as e:
        print(f"[-] Upload failed: {e}")

if __name__ == "__main__":
    main()
