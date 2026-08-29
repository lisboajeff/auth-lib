#!/usr/bin/env python3
import os
import json
import time
import datetime
import base64
import hashlib
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def int_to_base64url(val: int) -> str:
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('=')

def compute_rsa_jwk_thumbprint(e_b64: str, n_b64: str) -> str:
    """
    Computes the RFC 7638 JSON Web Key (JWK) Thumbprint (SHA-256)
    using canonical JSON with required members: e, kty, n in lexicographical order.
    """
    canonical_dict = {
        "e": e_b64,
        "kty": "RSA",
        "n": n_b64
    }
    canonical_json = json.dumps(canonical_dict, separators=(',', ':'), sort_keys=True).encode('utf-8')
    sha256_digest = hashlib.sha256(canonical_json).digest()
    return base64.urlsafe_b64encode(sha256_digest).rstrip(b'=').decode('utf-8')

def fetch_existing_jwks(endpoint_url: str, bucket_name: str, s3_key: str) -> list:
    """
    Fetches existing JWKS from S3/LocalStack if it exists.
    """
    object_url = f"{endpoint_url}/{bucket_name}/{s3_key}"
    try:
        req = urllib.request.Request(object_url, method="GET")
        with urllib.request.urlopen(req) as resp:
            if resp.status == 200:
                body = resp.read().decode('utf-8')
                data = json.loads(body)
                return data.get("keys", [])
    except urllib.error.HTTPError as err:
        if err.code != 404:
            print(f"[*] Note: HTTP {err.code} while fetching existing JWKS.")
    except Exception:
        pass
    return []

def main():
    bucket_name = "auth-bucket"
    s3_key = "jwks.json"
    endpoint_url = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")

    print("[*] Checking for existing JWKS in S3 for rotation...")
    existing_keys = fetch_existing_jwks(endpoint_url, bucket_name, s3_key)
    if existing_keys:
        print(f"[+] Found {len(existing_keys)} existing key(s) in S3 JWKS:")
        for idx, k in enumerate(existing_keys, 1):
            created_str = k.get("created_at", "N/A")
            print(f"    - Key {idx}: kid='{k.get('kid')}', created_at={created_str}")
    else:
        print("[*] No existing JWKS found in S3 (initiating fresh JWKS set).")

    print("\n[*] Generating new RSA 2048 Key Pair for rotation...")
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

    # Paths for secret folder and resources
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    secrets_dir = os.path.join(base_dir, "secrets")
    main_res_dir = os.path.join(base_dir, "src", "main", "resources")
    test_res_dir = os.path.join(base_dir, "src", "test", "resources")

    os.makedirs(secrets_dir, exist_ok=True)
    os.makedirs(main_res_dir, exist_ok=True)
    os.makedirs(test_res_dir, exist_ok=True)

    pem_secrets_path = os.path.join(secrets_dir, "private_key.pem")
    pem_main_path = os.path.join(main_res_dir, "private_key.pem")
    pem_test_path = os.path.join(test_res_dir, "private_key.pem")

    # Save to external secrets mount volume (production) and resources (test fallbacks)
    with open(pem_secrets_path, "wb") as f:
        f.write(private_pem)
    with open(pem_main_path, "wb") as f:
        f.write(private_pem)
    with open(pem_test_path, "wb") as f:
        f.write(private_pem)

    print(f"[+] Active Private Key saved to external secret mount: {pem_secrets_path}")

    # Build JWK JSON for new key
    public_numbers = private_key.public_key().public_numbers()
    n_b64 = int_to_base64url(public_numbers.n)
    e_b64 = int_to_base64url(public_numbers.e)

    new_kid = compute_rsa_jwk_thumbprint(e_b64, n_b64)
    now_epoch = int(time.time())
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"[+] New Active RFC 7638 KID: '{new_kid}' (created_at: {now_iso})")

    new_jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": new_kid,
        "iat": now_epoch,
        "created_at": now_iso,
        "n": n_b64,
        "e": e_b64
    }

    # Rotate JWKS: Keep only the new active key and the immediate previous active key (max 2 keys total)
    combined_keys = [new_jwk]
    if existing_keys:
        # Sort existing keys by 'iat' descending to pick the most recent previous key
        sorted_existing = sorted(existing_keys, key=lambda k: k.get("iat", 0), reverse=True)
        previous_key = sorted_existing[0]
        if previous_key.get("kid") != new_kid:
            combined_keys.append(previous_key)

    jwks = {
        "keys": combined_keys
    }
    jwks_json = json.dumps(jwks, indent=2).encode('utf-8')

    print(f"\n[*] Rotated JWKS Payload (Total keys: {len(combined_keys)}):\n{jwks_json.decode('utf-8')}")

    # Ensure bucket exists
    bucket_url = f"{endpoint_url}/{bucket_name}"
    object_url = f"{endpoint_url}/{bucket_name}/{s3_key}"

    print(f"\n[*] Ensuring bucket '{bucket_name}' exists on LocalStack...")
    create_bucket_req = urllib.request.Request(bucket_url, method="PUT")
    try:
        with urllib.request.urlopen(create_bucket_req) as resp:
            print(f"[+] Bucket verified/created (status {resp.status})")
    except urllib.error.HTTPError as err:
        if err.code in (200, 409):
            print(f"[+] Bucket exists (status {err.code})")
        else:
            print(f"[-] HTTP Error: {err}")
    except Exception as e:
        print(f"[-] Could not connect to LocalStack: {e}")

    # Upload rotated JWKS to S3
    print(f"[*] Uploading rotated JWKS to {object_url}...")
    upload_req = urllib.request.Request(
        object_url,
        data=jwks_json,
        headers={"Content-Type": "application/json"},
        method="PUT"
    )
    try:
        with urllib.request.urlopen(upload_req) as resp:
            print(f"[+] Successfully uploaded rotated JWKS to S3! (status {resp.status})")
            print(f"[+] Rotation complete: 1 new active key, {len(combined_keys) - 1} previous key(s) retained.")
    except Exception as e:
        print(f"[-] Upload failed: {e}")

if __name__ == "__main__":
    main()
