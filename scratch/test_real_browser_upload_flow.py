"""
Real End-to-End Artifact Upload & Verification Flow Test Script
"""
import io
import json
import struct
import time
import urllib.request

def make_test_elf_bytes() -> bytes:
    """Helper creating a minimal valid 64-bit ELF binary."""
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 256, 256, 4096)
    shdr0 = b"\x00" * 64
    shdr1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 248, 11, 0, 0, 1, 0)
    shstrtab = b"\x00.shstrtab\x00"
    return ident + header + phdr + shdr0 + shdr1 + shstrtab

def encode_multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    boundary = f"----Boundary{int(time.time()*1000)}"
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{value}\r\n".encode("utf-8"))
    for name, (filename, content, content_type) in files.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8"))
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"

def main():
    print("=" * 70)
    print("PROVENANCEGUARD REAL ARTIFACT UPLOAD & VERIFICATION TEST")
    print("=" * 70)

    # 1. Mint Dev Token
    req_token_body = json.dumps({
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "role": "SECURITY_ANALYST",
        "user_id": "e2e-tester-upload",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "scopes": ["*"]
    }).encode("utf-8")

    req_token = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/auth/token",
        data=req_token_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req_token) as resp:
        jwt_token = json.loads(resp.read().decode("utf-8"))["access_token"]
        print(f"[OK] Obtained Dev JWT Token via API (Length: {len(jwt_token)} chars)")

    # 2. Upload Safe Real ELF Binary Artifact
    elf_bytes = make_test_elf_bytes()
    upload_body, content_type = encode_multipart(
        fields={"version": "1.0.0"},
        files={"file": ("test-upload-elf.bin", elf_bytes, "application/octet-stream")}
    )

    req_upload = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/artifacts/upload",
        data=upload_body,
        headers={
            "Content-Type": content_type,
            "Authorization": f"Bearer {jwt_token}"
        },
        method="POST"
    )

    with urllib.request.urlopen(req_upload) as resp:
        artifact_res = json.loads(resp.read().decode("utf-8"))
        artifact_id = artifact_res["id"]
        sha256_digest = artifact_res["digest_sha256"]
        print(f"[OK] Uploaded Artifact -> HTTP {resp.status}")
        print(f"     Artifact ID:           {artifact_id}")
        print(f"     Authoritative SHA-256: {sha256_digest}")
        print(f"     Detected Media Type:   {artifact_res['media_type']}")
        print(f"     Storage Reference:     {artifact_res['storage_path']}")

    # 3. Submit Verification Job for Uploaded Artifact
    req_ver_body = json.dumps({
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "project_id": "00000000-0000-0000-0000-000000000002",
        "production_artifact_id": artifact_id,
    }).encode("utf-8")

    req_ver = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/verifications",
        data=req_ver_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {jwt_token}"
        },
        method="POST"
    )

    with urllib.request.urlopen(req_ver) as resp:
        ver_res = json.loads(resp.read().decode("utf-8"))
        run_id = ver_res.get("verification_run_id") or ver_res.get("id")
        print(f"[OK] Verification Job Submitted -> HTTP {resp.status}, Run ID: {run_id}")

    # 4. Wait for Background Worker Execution
    print("Waiting for ARQ worker processing...")
    for _ in range(15):
        time.sleep(1)
        req_get = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/verifications/{run_id}",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )
        with urllib.request.urlopen(req_get) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data["status"] in ("SUCCEEDED", "FAILED"):
                print(f"[OK] Worker Processing Completed -> Status: {data['status']}, Decision: {data['decision']}, Risk Score: {data['risk_score']}")
                break

    # 5. Query Audit Stream via REST API
    req_audit = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/audit-log",
        headers={"Authorization": f"Bearer {jwt_token}"}
    )
    with urllib.request.urlopen(req_audit) as resp:
        audit_res = json.loads(resp.read().decode("utf-8"))
        print(f"[OK] Audit Stream Total Records: {audit_res.get('total', 0)}")
        for item in audit_res.get("items", [])[:3]:
            print(f"     - Event ID: {item.get('id')}, Action: {item.get('action')}, Resource: {item.get('resource')}")

if __name__ == "__main__":
    main()
