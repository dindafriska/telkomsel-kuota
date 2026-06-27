#!/usr/bin/env python3
"""Quick Telkomsel quota/balance checker - reuses saved session"""
import urllib.request, urllib.parse, json, ssl, hashlib, base64, secrets, sys, os, gzip
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

SESSION_FILE = os.path.expanduser("~/.telkomsel_session.json")
if not os.path.exists(SESSION_FILE):
    print("❌ No saved session found. Run telkomsel_auto.py first.")
    sys.exit(1)

with open(SESSION_FILE) as f:
    session = json.load(f)

access_token = session.get("access_token", "")
id_token = session.get("id_token", "")
phone = session.get("phone", "")

if not access_token:
    print("❌ Invalid session file")
    sys.exit(1)

print(f"📱 Phone: {phone}")
print(f"🔑 Token: {access_token[:40]}...")

# ─── AES-128-OFB (pure Python) ───
S = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
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
     0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
RC = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def ke(k):
    w=[list(k[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4,44):
        t=w[i-1][:]
        if i%4==0:t=[S[b] for b in t[1:]+t[:1]];t[0]^=RC[(i//4)-1]
        w.append([w[i-4][j]^t[j] for j in range(4)])
    return b''.join(bytes(x) for x in w)
def gm(a,b):
    p=0
    for _ in range(8):
        if b&1:p^=a
        hi=a&0x80;a=(a<<1)&0xff
        if hi:a^=0x1b
        b>>=1
    return p
def ae(s,rk):
    s=list(s)
    for i in range(16):s[i]^=rk[i]
    for r in range(1,10):
        for i in range(16):s[i]=S[s[i]]
        s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
        s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
        s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
        for c in range(4):
            i=c*4;s0,s1,s2,s3=s[i],s[i+1],s[i+2],s[i+3]
            s[i]=gm(2,s0)^gm(3,s1)^s2^s3
            s[i+1]=s0^gm(2,s1)^gm(3,s2)^s3
            s[i+2]=s0^s1^gm(2,s2)^gm(3,s3)
            s[i+3]=gm(3,s0)^s1^s2^gm(2,s3)
        for i in range(16):s[i]^=rk[r*16+i]
    for i in range(16):s[i]=S[s[i]]
    s[1],s[5],s[9],s[13]=s[5],s[9],s[13],s[1]
    s[2],s[6],s[10],s[14]=s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15]=s[15],s[3],s[7],s[11]
    for i in range(16):s[i]^=rk[160+i]
    return bytes(s)
def evp(pw):
    if isinstance(pw,str):pw=pw.encode()
    r=b'';h=b''
    while len(r)<32:h=hashlib.md5(h+pw).digest();r+=h
    return r[:16],r[16:32]
def ofb(pt,k,iv):
    rk=ke(k);out=b'';fb=iv
    for o in range(0,len(pt),16):
        fb=ae(fb,rk);c=pt[o:o+16]
        out+=bytes(a^b for a,b in zip(c,fb[:len(c)]))
    return out
def en(payload,pw='production'):
    k,iv=evp(pw);return base64.b64encode(ofb(payload.encode(),k,iv)).decode()
def gen(at,idt):
    ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    a=json.dumps({'accessToken':at,'timestamp':ts},separators=(',',':'))
    u=json.dumps({'token':idt,'timestamp':ts},separators=(',',':'))
    return 'Bearer '+en(a),'Bearer '+en(u)
def rh(n):return secrets.token_hex(n//2)

BASE = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept':'application/json','Origin':'https://my.telkomsel.com',
        'Referer':'https://my.telkomsel.com/','Content-Type':'application/json','Dnt':'1'}

def req(url,body=None,headers=None,method='POST'):
    h=BASE.copy()
    if headers:h.update(headers)
    data=json.dumps(body).encode() if body else b'{}'
    r=urllib.request.Request(url,data=data,headers=h,method=method)
    with urllib.request.urlopen(r,context=ctx,timeout=30) as resp:
        body = resp.read()
        if resp.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        return json.loads(body)

# Generate headers
aa,au = gen(access_token, id_token)
xd = rh(4)+'-'+rh(2)+'-'+rh(2)+'-'+rh(2)+'-'+rh(6)
qh = {'AccessAuth':aa,'Authorization':au,'X-Device':xd,'sah':rh(28),
      'Web-App-Version':'2.0.0','Accept-Language':'id-ID,id;q=0.9',
      'User-Agent':BASE['User-Agent'],'Accept':'application/json',
      'Origin':'https://my.telkomsel.com','Referer':'https://my.telkomsel.com/',
      'Content-Type':'application/json'}
qb = {'isPrepaid':True,'location':'','roaming':False}

# ─── QUOTA ───
print("\n" + "="*55)
print("  📊 QUOTA REPORT")
print("="*55)
try:
    bq = req('https://tdw.telkomsel.com/api/subscriber/v5/bonuses', qb, qh)
    if bq.get('status')=='00000':
        gs = bq.get('data',{}).get('userBonuses',[])
        if gs:
            for g in gs:
                cls = g.get('class','?'); tot = g.get('totalText','')
                print(f"\n  📦 {cls} — {tot}")
                print("  " + "-"*50)
                for i in g.get('bonusList',[]):
                    n = i.get('name') or i.get('bucketdescription','?')
                    r = i.get('remainingquota','?')
                    e = i.get('expirydate','?')
                    print(f"  • {n}")
                    print(f"    Remaining: {r}  |  Exp: {e}")
        else:
            print("  No quota data")
    else:
        print(f"  Error: {bq.get('message','?')}")
        if bq.get('status') in ('40010','40001','401'):
            print("\n⚠️  Session expired! Run telkomsel_auto.py to get a new one.")
except Exception as e:
    print(f"  ❌ Error: {e}")

# ─── BALANCE ───
print("\n" + "="*55)
print("  💰 BALANCE")
print("="*55)
try:
    bp = req('https://tdw.telkomsel.com/api/subscriber/v5/profile', qb, qh)
    if bp.get('status')=='00000':
        pd = bp.get('data',{})
        print(f"  📱 Number: {pd.get('msisdn','?')}")
        print(f"  📋 Plan: {pd.get('planName','?')}")
        print(f"  💰 Main Balance: {pd.get('mainBalance','?')}")
        for ab in pd.get('additionalBalances',[]):
            print(f"  💳 {ab.get('balanceName','Extra')}: {ab.get('balance','?')}")
    else:
        print(f"  Error: {bp.get('message','?')}")
except Exception as e:
    print(f"  ❌ Error: {e}")

print()
