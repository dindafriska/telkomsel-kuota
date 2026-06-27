#!/usr/bin/env python3
"""Telkomsel auto OTP + quota - uses cryptography library"""
import urllib.request, urllib.parse, json, ssl, hashlib, base64, secrets, sys, subprocess, time, re, os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssl._create_default_https_context = lambda: ctx

# Load config
_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
with open(_cfg_path) as _f:
    _cfg = json.load(_f)
FULL_PHONE = _cfg['phone']
CLIENT_ID = _cfg['client_id']
CLIENT_SECRET = _cfg['client_secret']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a): return None
    def http_error_302(self,req,fp,code,msg,hdrs): return fp
    http_error_301=http_error_303=http_error_307=http_error_302

def evp(pw):
    if isinstance(pw,str): pw=pw.encode()
    r=b'';h=b''
    while len(r)<32: h=hashlib.md5(h+pw).digest();r+=h
    return r[:16], r[16:32]

def en(payload, pw='production'):
    k,iv = evp(pw)
    cipher = Cipher(algorithms.AES(k), modes.OFB(iv))
    enc = cipher.encryptor()
    return base64.b64encode(enc.update(payload.encode()) + enc.finalize()).decode()

def gen(at,idt):
    ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    a=json.dumps({'accessToken':at,'timestamp':ts},separators=(',',':'))
    u=json.dumps({'token':idt,'timestamp':ts},separators=(',',':'))
    return en(a),en(u)   # just encrypted, no Bearer prefix

def rh(n): return secrets.token_hex(n//2)
def gen_tid():
    return 'A'+datetime.now().strftime('%y%m%d%H%M%S%f')+'148700'

def build_api_headers(aa, au, msisdn, xd):
    return {
        'accept':'application/json', 'accept-encoding':'gzip', 'accept-language':'id-ID,id;q=0.9',
        'accessauthorization':'Bearer '+aa, 'authorization':'Bearer '+au,
        'authserver':'2', 'channelid':'WEB', 'content-type':'application/json', 'dnt':'1',
        'hash':rh(28), 'language':'id', 'mytelkomsel-web-app-version':'2.0.0',
        'origin':'https://my.telkomsel.com', 'priority':'u=1, i', 'referer':'https://my.telkomsel.com/',
        'sec-ch-ua':"Not:A-Brand;v=99, Google Chrome;v=145, Chromium;v=145",
        'sec-ch-ua-mobile':'?0', 'sec-ch-ua-platform':'Windows',
        'sec-fetch-dest':'empty', 'sec-fetch-mode':'cors', 'sec-fetch-site':'same-site',
        'transactionid':gen_tid(),
        'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        'web-msisdn':msisdn, 'x-device':xd
    }

def req(url,body=None,headers=None,method='POST'):
    data=json.dumps(body).encode() if body else b'{}'
    r=urllib.request.Request(url,data=data,headers=headers,method=method)
    with urllib.request.urlopen(r,context=ctx,timeout=30) as resp:
        return json.loads(resp.read()),[v for k,v in resp.headers.items() if k.lower()=='set-cookie']
def gc(cookies,pfx):
    for c in cookies:
        for part in c.split(';'):
            part=part.strip()
            if part.startswith(pfx):return part
    return ''

def read_sms_otp(after_time=None):
    result = subprocess.run(['termux-sms-list','--message-type=inbox','--message-limit=10'],
                          capture_output=True, text=True, timeout=10)
    if result.returncode != 0: return None
    try:
        msgs = json.loads(result.stdout)
        for msg in msgs:
            received = msg.get('received','')
            if after_time and received < after_time: continue
            body = msg.get('body','')
            if 'OTP' in body or 'otp' in body or 'kode' in body.lower():
                match = re.search(r'\b(\d{6})\b', body)
                if match: return match.group(1)
        return None
    except: return None

AUTH='https://ciam.telkomsel.com/iam/v1/realms/tsel/authenticate?authIndexType=service&authIndexValue=phoneLogin'

print('Step 1: Sending OTP...')
b1,c1=req(AUTH,{},{'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36','Accept':'application/json','Origin':'https://my.telkomsel.com','Referer':'https://my.telkomsel.com/','Content-Type':'application/json','Dnt':'1','Am-Phonenumber':'+'+FULL_PHONE,'Am-Clientid':CLIENT_ID,'Am-Send':'otp'})
aid=b1.get('authId','');aml=gc(c1,'amlbcookie=')
if not aid:print('FAIL');print(json.dumps(b1,indent=2)[:200]);sys.exit(1)
print('  Sent!')

before_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
time.sleep(12)

print('Step 2: Reading OTP from SMS...')
otp = None
for attempt in range(5):
    otp = read_sms_otp(before_time)
    if otp: print('  OTP:', otp); break
    print(f'  waiting ({attempt+1}/5)...')
    time.sleep(3)
if not otp: print('Could not read OTP'); sys.exit(1)

print('Step 3: Submitting OTP...')
h2={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36','Accept':'application/json','Origin':'https://my.telkomsel.com','Referer':'https://my.telkomsel.com/','Content-Type':'application/json','Dnt':'1','Am-Phonenumber':'+'+FULL_PHONE,'Am-Clientid':CLIENT_ID}
if aml:h2['Cookie']=aml
ob={'authId':aid,'callbacks':[
    {'type':'PasswordCallback','output':[{'name':'prompt','value':'One Time Password'}],'input':[{'name':'IDToken1','value':otp}]},
    {'type':'ConfirmationCallback','output':[{'name':'prompt','value':''},{'name':'messageType','value':0},{'name':'options','value':['Submit OTP','Request OTP']},{'name':'optionType','value':-1},{'name':'defaultOption','value':0}],'input':[{'name':'IDToken2','value':0}]}
]}
b2,c2=req(AUTH,ob,h2)
tid=b2.get('tokenId','');ipc=gc(c2,'iPlanetDirectoryPro=')
if not ipc and tid:ipc='iPlanetDirectoryPro='+tid
if not tid:print('OTP rejected:',json.dumps(b2,indent=2)[:200]);sys.exit(1)
print('  Accepted!')

print('Step 4: Auth code...')
p=urllib.parse.urlencode({'client_id':CLIENT_ID,'nonce':'true','redirect_uri':'https://my.telkomsel.com/web/callback','response_type':'code','scope':'profile openid phone identifier'})
au='https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/authorize?'+p
h3={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36','Accept':'application/json','Referer':'https://my.telkomsel.com/','Accept-Language':'id-ID,id;q=0.9','Dnt':'1'}
c3='; '.join(filter(None,[aml,ipc]))
if c3:h3['Cookie']=c3
import ssl as _ssl
_ssl._create_default_https_context = lambda: ctx
opener=urllib.request.build_opener(NoRedirect)
with opener.open(urllib.request.Request(au,headers=h3,method='GET'),timeout=30) as r:
    loc=r.headers.get('Location','')
    code=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get('code',[None])[0]
if not code:print('No auth code!');sys.exit(1)
print('  OK')

print('Step 5: Access token...')
tp=urllib.parse.urlencode({'client_id':CLIENT_ID,'client_secret':CLIENT_SECRET,'code':code,'grant_type':'authorization_code','redirect_uri':'https://my.telkomsel.com/web/callback','response_type':'code'})
h4={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36','Accept':'application/json','Origin':'https://my.telkomsel.com','Referer':'https://my.telkomsel.com/','Content-Type':'application/x-www-form-urlencoded'}
with urllib.request.urlopen(urllib.request.Request('https://ciam.telkomsel.com/iam/v1/oauth2/realms/tsel/access_token?'+tp,data=b'',headers=h4,method='POST'),context=ctx,timeout=30) as r:
    td=json.loads(r.read())
at=td.get('access_token','');idt=td.get('id_token','')
if not at:print('FAIL:',json.dumps(td,indent=2)[:200]);sys.exit(1)
print('  Token:',at[:40]+'...')

# ─── QUOTA + PROFILE ───
print('\nFetching data...')
aa,au=gen(at,idt)
xd=rh(4)+'-'+rh(2)+'-'+rh(2)+'-'+rh(2)+'-'+rh(6)
qh = build_api_headers(aa, au, FULL_PHONE, xd)
qb={'isPrepaid':True,'location':'','roaming':False}

bq,_=req('https://tdw.telkomsel.com/api/subscriber/v5/bonuses',qb,qh)
print(); print('='*55); print('  TELKOMSEL QUOTA'); print('='*55)
if bq.get('status')=='00000':
    gs=bq.get('data',{}).get('userBonuses',[])
    if gs:
        for g in gs:
            cls=g.get('class','?');tot=g.get('totalText','')
            print(); print('  '+str(cls)+' - '+str(tot)); print('  '+'-'*50)
            for i in g.get('bonusList',[]):
                n=i.get('name')or i.get('bucketdescription','?')
                r=i.get('remainingquota','?'); e=i.get('expirydate','?')
                print('  '+str(n)); print('    Remaining: '+str(r)+'  |  Exp: '+str(e))
    else: print('  No quota data')
else: print('  Error: '+str(bq))

bp,_=req('https://tdw.telkomsel.com/api/subscriber/v5/profile',qb,qh)
print(); print('='*55); print('  BALANCE'); print('='*55)
if bp.get('status')=='00000':
    pd=bp.get('data',{})
    print('  Number: '+str(pd.get('msisdn','?')))
    print('  Plan: '+str(pd.get('planName','?')))
    print('  Main Balance: '+str(pd.get('mainBalance','?')))
    for ab in pd.get('additionalBalances',[]):
        print('  '+str(ab.get('balanceName','Extra'))+': '+str(ab.get('balance','?')))
else: print('  Error: '+str(bp))
print(); print('Done!')
