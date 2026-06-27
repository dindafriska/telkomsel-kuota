#!/usr/bin/env python3
"""Telkomsel auth + quota checker - pure Python, no external deps"""
import urllib.request, urllib.parse, json, sys, ssl, hashlib, base64, secrets, os
from datetime import datetime, timezone

# Load config
_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
with open(_cfg_path) as _f:
    _cfg = json.load(_f)
FULL_PHONE = _cfg['phone']
CLIENT_ID = _cfg['client_id']
CLIENT_SECRET = _cfg['client_secret']
OTP_CODE = "517773"
AUTH_URL = "https://ciam.telkomsel.com/iam/v1/realms/tsel/authenticate?authIndexType=service&authIndexValue=phoneLogin"
SESSION_FILE = "/data/data/com.termux/files/home/.telkomsel_session.json"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302

# ─── Pure Python AES-128-OFB ───
s_box = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def key_expansion(key):
    w = [list(key[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = [s_box[b] for b in temp[1:]+temp[:1]]
            temp[0] ^= rcon[(i//4)-1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    return b''.join(bytes(word) for word in w)

def galois_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def aes_128_encrypt_block(block, rk):
    s = list(block)
    for i in range(16): s[i] ^= rk[i]
    for rnd in range(1, 10):
        for i in range(16): s[i] = s_box[s[i]]
        s[1],s[5],s[9],s[13] = s[5],s[9],s[13],s[1]
        s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
        s[3],s[7],s[11],s[15] = s[15],s[3],s[7],s[11]
        for c in range(4):
            i=c*4; s0,s1,s2,s3=s[i],s[i+1],s[i+2],s[i+3]
            s[i]=galois_mul(2,s0)^galois_mul(3,s1)^s2^s3
            s[i+1]=s0^galois_mul(2,s1)^galois_mul(3,s2)^s3
            s[i+2]=s0^s1^galois_mul(2,s2)^galois_mul(3,s3)
            s[i+3]=galois_mul(3,s0)^s1^s2^galois_mul(2,s3)
        for i in range(16): s[i] ^= rk[rnd*16+i]
    for i in range(16): s[i] = s_box[s[i]]
    s[1],s[5],s[9],s[13] = s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15] = s[15],s[3],s[7],s[11]
    for i in range(16): s[i] ^= rk[160+i]
    return bytes(s)

def evp_bytes_to_key(password, key_len=16, iv_len=16):
    pw = password.encode() if isinstance(password, str) else password
    result = b''
    h = b''
    while len(result) < key_len + iv_len:
        h = hashlib.md5(h + pw).digest()
        result += h
    return result[:key_len], result[key_len:key_len+iv_len]

def aes_128_ofb_encrypt(plaintext, key, iv):
    rk = key_expansion(key)
    output = b''
    fb = iv
    for offset in range(0, len(plaintext), 16):
        fb = aes_128_encrypt_block(fb, rk)
        chunk = plaintext[offset:offset+16]
        output += bytes(a ^ b for a, b in zip(chunk, fb[:len(chunk)]))
    return output

def encrypt_payload(payload, password="production"):
    key, iv = evp_bytes_to_key(password)
    ct = aes_128_ofb_encrypt(payload.encode(), key, iv)
    return base64.b64encode(ct).decode()

def generate_auth_headers(at, idt):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    aa = encrypt_payload(json.dumps({"accessToken": at, "timestamp": ts}, separators=(',',':')))
    au = encrypt_payload(json.dumps({"token": idt, "timestamp": ts}, separators=(',',':')))
    return "Bearer " + aa, "Bearer " + au

def random_hex(n):
    return secrets.token_hex(n // 2)

base_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Origin": "https://my.telkomsel.com",
    "Referer": "https://my.telkomsel.com/",
    "Content-Type": "application/json",
    "Dnt": "1",
    "Sec-Ch-Ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
}

def do_request(url, body=None, headers=None, method='POST'):
    h = base_headers.copy()
    if headers: h.update(headers)
    data = json.dumps(body).encode() if body else b'{}'
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.loads(resp.read()), [v for k,v in resp.headers.items() if k.lower() == 'set-cookie']

def get_cookie(cookies, prefix):
    for c in cookies:
        for part in c.split(';'):
            part = part.strip()
            if part.startswith(prefix): return part
    return ''

# ════════════════════════════════════════════
# MAIN FLOW
# ════════════════════════════════════════════

print("🔐 Step 1: Request OTP...")
h1 = {"Am-Phonenumber": "+" + FULL_PHONE, "Am-Clientid": CLIENT_ID, "Am-Send": "otp"}
b1, c1 = do_request(AUTH_URL, {}, h1)
auth_id = b1.get('authId', '')
aml = get_cookie(c1, 'amlbcookie=')
if not auth_id: print("❌ Fail:", json.dumps(b1, indent=2)[:200]); sys.exit(1)
print(f"  ✅ authId + cookie captured")

print("🔐 Step 2: Submit OTP...")
otp_body = {
    "authId": auth_id,
    "callbacks": [
        {"type": "PasswordCallback", "output": [{"name":"prompt","value":"One Time Password"}],
         "input": [{"name":"IDToken1","value":OTP_CODE}]},
        {"type": "ConfirmationCallback",
         "output": [{"name":"prompt","value":""},{"name":"messageType","value":0},
                    {"name":"options","value":["Submit OTP","Request OTP"]},
                    {"name":"optionType","value":-1},{"name":"defaultOption","value":0}],
         "input": [{"name":"IDToken2","value":0}]}
    ]
}
h2 = {"Am-Phonenumber": "+" + FULL_PHONE, "Am-Clientid": CLIENT_ID}
if aml: h2["Cookie"] = aml
b2, c2 = do_request(AUTH_URL, otp_body, h2)
token_id = b2.get('tokenId', '')
ip_cookie = get_cookie(c2, 'iPlanetDirectoryPro=')
if not ip_cookie and token_id: ip_cookie = "iPlanetDirectoryPro=" + token_id
if not token_id: print("❌ Fail:", json.dumps(b2, indent=2)[:200]); sys.exit(1)
print(f"  ✅ Token obtained")

print("🔐 Step 3: Get authorization code...")
authz_params = urllib.parse.urlencode({
    "client_id": CLIENT_ID, "nonce": "true",
    "redirect_uri": "https://my.telkomsel.com/web/callback",
    "response_type": "code", "scope": "profile openid phone identifier"
})
authz_url = f"https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/authorize?{authz_params}"
h3 = {"User-Agent": base_headers["User-Agent"], "Accept": "application/json", "Referer": "https://my.telkomsel.com/"}
c3 = "; ".join(filter(None, [aml, ip_cookie]))
if c3: h3["Cookie"] = c3

req3 = urllib.request.Request(authz_url, headers=h3, method='GET')
with urllib.request.build_opener(NoRedirectHandler).open(req3, timeout=30) as r3:
    loc = r3.headers.get('Location', '')
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get('code', [None])[0]
if not code: print("❌ No auth code!"); sys.exit(1)
print(f"  ✅ Auth code obtained")

print("🔐 Step 4: Get access token...")
token_params = urllib.parse.urlencode({
    "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    "code": code, "grant_type": "authorization_code",
    "redirect_uri": "https://my.telkomsel.com/web/callback",
    "response_type": "code"
})
token_url = f"https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/access_token?{token_params}"
h4 = {"User-Agent": base_headers["User-Agent"], "Accept": "application/json",
      "Origin": "https://my.telkomsel.com", "Referer": "https://my.telkomsel.com/",
      "Content-Type": "application/x-www-form-urlencoded"}
req4 = urllib.request.Request(token_url, data=b'', headers=h4, method='POST')
with urllib.request.urlopen(req4, context=ctx, timeout=30) as r4:
    td = json.loads(r4.read())
access_token = td.get('access_token', '')
id_token = td.get('id_token', '')
if not access_token: print("❌ Fail:", json.dumps(td, indent=2)[:200]); sys.exit(1)
print(f"  ✅ Access token: {access_token[:50]}...")
print(f"  ✅ ID token: {id_token[:50]}...")

session = {'access_token': access_token, 'id_token': id_token, 'phone': FULL_PHONE}
with open(SESSION_FILE, 'w') as f: json.dump(session, f)
print("\n🎉 Authentication complete! Session saved.")

# ─── FETCH QUOTA ───
print("\n📊 Fetching quota...")
access_auth, authorization = generate_auth_headers(access_token, id_token)
x_device = f"{random_hex(4)}-{random_hex(2)}-{random_hex(2)}-{random_hex(2)}-{random_hex(6)}"
sah = random_hex(28)

q_headers = {
    "AccessAuth": access_auth,
    "Authorization": authorization,
    "X-Device": x_device,
    "sah": sah,
    "Web-App-Version": "2.0.0",
}

quota_url = "https://tdw.telkomsel.com/api/subscriber/v5/bonuses"
quota_body = {"isPrepaid": True, "location": "", "roaming": False}

try:
    b_q, _ = do_request(quota_url, quota_body, q_headers)
    
    if b_q.get('status') == '00000':
        groups = b_q.get('data', {}).get('userBonuses', [])
        print("\n" + "=" * 55)
        print("  📊 TELKOMSEL QUOTA REPORT")
        print("=" * 55)
        
        if not groups:
            print("   No quota data found.")
        else:
            for g in groups:
                cls = g.get('class', 'Unknown')
                total = g.get('totalText', '')
                print(f"\n  📦 {cls} — {total}")
                print("  " + "-" * 50)
                for item in g.get('bonusList', []):
                    name = item.get('name') or item.get('bucketdescription', '')
                    remaining = item.get('remainingquota', '')
                    expiry = item.get('expirydate', '')
                    print(f"  • {name}")
                    rem_val = item.get('remainingquotaValue', 0)
                    print(f"    Remaining: {remaining}  |  Exp: {expiry}")
    else:
        print(f"\nAPI Error: {b_q.get('message', 'unknown')}")
        print(json.dumps(b_q, indent=2)[:500])
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# ─── FETCH PROFILE (balance) ───
print("\n\n" + "=" * 55)
print("  💰 FETCHING PROFILE & BALANCE...")
print("=" * 55)

profile_url = "https://tdw.telkomsel.com/api/subscriber/v5/profile"
try:
    b_p, _ = do_request(profile_url, quota_body, q_headers)
    if b_p.get('status') == '00000':
        pdata = b_p.get('data', {})
        print(f"   📱 Number: {pdata.get('msisdn', 'N/A')}")
        print(f"   📋 Plan: {pdata.get('planName', 'N/A')}")
        print(f"   💰 Main Balance: {pdata.get('mainBalance', 'N/A')}")
        if pdata.get('additionalBalances'):
            for ab in pdata['additionalBalances']:
                print(f"   💳 {ab.get('balanceName','Extra')}: {ab.get('balance','N/A')}")
    else:
        print(f"   Profile API: {b_p.get('message', 'unknown')}")
except Exception as e:
    print(f"   Profile error: {e}")

print("\n✅ Done! Access token saved for reuse.")
