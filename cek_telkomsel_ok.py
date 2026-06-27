#!/usr/bin/env python3
"""Working Telkomsel quota/balance checker - uses pycryptodome"""
import urllib.request, json, ssl, gzip, hashlib, base64, secrets, sys, os, subprocess, time, re
from datetime import datetime, timezone
from Crypto.Cipher import AES

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

SESSION_FILE = os.path.expanduser("~/.telkomsel_session.json")

# Load config
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
with open(config_path) as f:
    config = json.load(f)
CLIENT_ID = config['client_id']
CLIENT_SECRET = config['client_secret']
FULL_PHONE = config['phone']
AUTH_URL = "https://ciam.telkomsel.com/iam/v1/realms/tsel/authenticate?authIndexType=service&authIndexValue=phoneLogin"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a): return None
    def http_error_302(self,req,fp,code,msg,hdrs): return fp
    http_error_301=http_error_303=http_error_307=http_error_302

# ─── AES Encryption ───
def evp(pw):
    if isinstance(pw, str): pw = pw.encode()
    r = b''; h = b''
    while len(r) < 32:
        h = hashlib.md5(h + pw).digest()
        r += h
    return r[:16], r[16:32]

def encrypt_b64(payload, password="production"):
    k, iv = evp(password)
    c = AES.new(k, AES.MODE_OFB, iv)
    return base64.b64encode(c.encrypt(payload.encode())).decode()

def gen_auth_headers(at, idt):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    aa = encrypt_b64(json.dumps({"accessToken": at, "timestamp": ts}, separators=(',',':')))
    au = encrypt_b64(json.dumps({"token": idt, "timestamp": ts}, separators=(',',':')))
    return "Bearer " + aa, "Bearer " + au

def rh(n):
    return secrets.token_hex(n // 2)

def gen_tid():
    return 'A' + datetime.now().strftime('%y%m%d%H%M%S%f') + '148700'

# ─── HTTP ───
def api_req(url, body, headers):
    data = json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(r, context=ctx, timeout=30) as resp:
        body = resp.read()
        if resp.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        return json.loads(body)

def auth_req(url, body, headers):
    data = json.dumps(body).encode() if body else b'{}'
    r = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(r, context=ctx, timeout=30) as resp:
        return json.loads(resp.read()), [v for k,v in resp.headers.items() if k.lower() == 'set-cookie']

def gc(cookies, pfx):
    for c in cookies:
        for part in c.split(';'):
            part = part.strip()
            if part.startswith(pfx):
                return part
    return ''

# ─── API Call ───
def fetch_data(at, idt):
    aa, au = gen_auth_headers(at, idt)
    xd = f"{rh(4)}-{rh(2)}-{rh(2)}-{rh(2)}-{rh(6)}"
    
    headers = {
        'accept': 'application/json', 'accept-encoding': 'gzip',
        'accessauthorization': aa, 'authorization': au,
        'authserver': '2', 'channelid': 'WEB',
        'content-type': 'application/json', 'dnt': '1',
        'hash': rh(28), 'language': 'id',
        'mytelkomsel-web-app-version': '2.0.0',
        'origin': 'https://my.telkomsel.com',
        'referer': 'https://my.telkomsel.com/',
        'sah': rh(28),
        'transactionid': gen_tid(),
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'web-msisdn': FULL_PHONE,
        'x-device': xd,
    }
    body = {'isPrepaid': True, 'location': '', 'roaming': False}
    
    # Quota
    bq = api_req('https://tdw.telkomsel.com/api/subscriber/v5/bonuses', body, headers)
    # Profile (balance)
    try:
        bp = api_req('https://tdw.telkomsel.com/api/subscriber/v5/profile', body, headers)
    except:
        bp = None
    return bq, bp

# ─── Display ───
def show(bq, bp):
    print()
    print("=" * 55)
    print("  📊 TELKOMSEL QUOTA REPORT")
    print("=" * 55)
    
    if bq.get('status') == '00000':
        groups = bq.get('data', {}).get('userBonuses', [])
        if groups:
            for g in groups:
                cls = g.get('class', '?')
                tot = g.get('totalText', '')
                print(f"\n  📦 {cls} — {tot}")
                print("  " + "-" * 50)
                for i in g.get('bonusList', []):
                    n = i.get('name') or i.get('bucketdescription', '?')
                    r = i.get('remainingquota', '?')
                    e = i.get('expirydate', '?')
                    print(f"  • {n}")
                    print(f"    Remaining: {r}  |  Exp: {e}")
        else:
            print("  (no quota data)")
    else:
        print(f"  API Error: {bq.get('message', '?')}")
    
    print()
    print("=" * 55)
    print("  💰 BALANCE & PROFILE")
    print("=" * 55)
    
    if bp and bp.get('status') == '00000':
        d = bp.get('data', {})
        print(f"  📱 Number: {d.get('msisdn', '?')}")
        print(f"  📋 Plan: {d.get('planName', '?')}")
        print(f"  💰 Main Balance: {d.get('mainBalance', '?')}")
        for ab in d.get('additionalBalances', []):
            print(f"  💳 {ab.get('balanceName', 'Extra')}: {ab.get('balance', '?')}")
    else:
        print("  (profile API unavailable)")
    print()

# ─── Auth Flow ───
def new_auth():
    print("🔐 Sending OTP to", FULL_PHONE, "...")
    h1 = {
        'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json',
        'Origin': 'https://my.telkomsel.com', 'Referer': 'https://my.telkomsel.com/',
        'Content-Type': 'application/json',
        'Am-Phonenumber': '+' + FULL_PHONE, 'Am-Clientid': CLIENT_ID, 'Am-Send': 'otp',
    }
    b1, c1 = auth_req(AUTH_URL, {}, h1)
    auth_id = b1.get('authId', '')
    aml = gc(c1, 'amlbcookie=')
    if not auth_id:
        print("❌ Failed:", json.dumps(b1, indent=2)[:200])
        sys.exit(1)
    
    before = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("⏳ Waiting for OTP SMS...")
    time.sleep(15)
    
    otp = None
    for attempt in range(5):
        try:
            r = subprocess.run(['termux-sms-list','--message-type=inbox','--message-limit=10'],
                             capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                msgs = json.loads(r.stdout)
                for msg in msgs:
                    if msg.get('received','') < before: continue
                    body = msg.get('body','')
                    if 'OTP' in body or 'otp' in body or 'kode' in body.lower():
                        m = re.search(r'\b(\d{6})\b', body)
                        if m: otp = m.group(1); break
        except: pass
        if otp: break
        print(f"  waiting ({attempt+1}/5)...")
        time.sleep(3)
    
    if not otp:
        otp = input("Enter OTP manually: ").strip()
    
    print("🔐 Submitting OTP...")
    ob = {
        "authId": auth_id,
        "callbacks": [
            {"type": "PasswordCallback",
             "output": [{"name":"prompt","value":"One Time Password"}],
             "input": [{"name":"IDToken1","value":otp}]},
            {"type": "ConfirmationCallback",
             "output": [{"name":"prompt","value":""},{"name":"messageType","value":0},{"name":"options","value":["Submit OTP","Request OTP"]},{"name":"optionType","value":-1},{"name":"defaultOption","value":0}],
             "input": [{"name":"IDToken2","value":0}]}
        ]
    }
    h2 = {
        'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json',
        'Origin': 'https://my.telkomsel.com', 'Referer': 'https://my.telkomsel.com/',
        'Content-Type': 'application/json',
        'Am-Phonenumber': '+' + FULL_PHONE, 'Am-Clientid': CLIENT_ID,
    }
    if aml: h2['Cookie'] = aml
    b2, c2 = auth_req(AUTH_URL, ob, h2)
    token_id = b2.get('tokenId', '')
    ipc = gc(c2, 'iPlanetDirectoryPro=')
    if not ipc and token_id: ipc = 'iPlanetDirectoryPro=' + token_id
    if not token_id:
        print("❌ OTP rejected:", json.dumps(b2, indent=2)[:200])
        sys.exit(1)
    print("✅ OTP accepted!")
    
    print("🔐 Getting auth code...")
    params = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "nonce": "true",
        "redirect_uri": "https://my.telkomsel.com/web/callback",
        "response_type": "code", "scope": "profile openid phone identifier"
    })
    authz_url = f"https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/authorize?{params}"
    h3 = {
        'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json',
        'Referer': 'https://my.telkomsel.com/', 'Accept-Language': 'id-ID,id;q=0.9',
    }
    c3 = '; '.join(filter(None, [aml, ipc]))
    if c3: h3['Cookie'] = c3
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(authz_url, headers=h3, method='GET'), timeout=30) as r:
        loc = r.headers.get('Location', '')
        code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get('code', [None])[0]
    if not code: print("❌ No auth code!"); sys.exit(1)
    print("✅ Auth code obtained")
    
    print("🔐 Getting access token...")
    tp = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "code": code, "grant_type": "authorization_code",
        "redirect_uri": "https://my.telkomsel.com/web/callback",
        "response_type": "code"
    })
    token_url = f"https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/access_token?{tp}"
    h4 = {
        'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json',
        'Origin': 'https://my.telkomsel.com', 'Referer': 'https://my.telkomsel.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    r4 = urllib.request.Request(token_url, data=b'', headers=h4, method='POST')
    with urllib.request.urlopen(r4, context=ctx, timeout=30) as r:
        td = json.loads(r.read())
    at = td.get('access_token', '')
    idt = td.get('id_token', '')
    if not at: print("❌ No access token!"); sys.exit(1)
    print("✅ Token obtained!")
    
    with open(SESSION_FILE, 'w') as f:
        json.dump({'access_token': at, 'id_token': idt}, f)
    return at, idt

# ════════════════════════════════════════
# MAIN
# ════════════════════════════════════════
try:
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            s = json.load(f)
        at, idt = s.get('access_token', ''), s.get('id_token', '')
        if at:
            print("📱 Using saved session...")
            bq, bp = fetch_data(at, idt)
            show(bq, bp)
        else:
            raise Exception("no token")
    else:
        raise Exception("no session")
except (urllib.error.HTTPError, Exception) as e:
    code = getattr(e, 'code', 0)
    if code == 401 or '401' in str(e):
        print("🔑 Session expired. Re-authenticating...")
        at, idt = new_auth()
        bq, bp = fetch_data(at, idt)
        show(bq, bp)
    else:
        print(f"❌ Error: {e}")
        import traceback; traceback.print_exc()
