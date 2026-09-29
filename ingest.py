"""ThreatTrace ingestion: reads Gmail (read-only), analyzes each email, stores results in SQLite.
Usage:  python ingest.py [count] [gmail-search-query]
        python ingest.py 20            -> latest 20 inbox emails
        python ingest.py 50 "in:spam"  -> latest 50 spam emails
Analysis is rule-based and local. No links are opened and no attachment is executed.
"""
import sys, re, base64, hashlib, ipaddress, json, sqlite3, os
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BRANDS = ['microsoft', 'paypal', 'google', 'apple', 'amazon', 'netflix', 'docusign', 'dhl', 'fedex', 'linkedin', 'facebook', 'instagram', 'sbi', 'hdfc', 'icici']
SHORT = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.ly'}
EXT_HIGH = ('.exe', '.js', '.scr', '.iso', '.lnk', '.vbs', '.bat', '.jar', '.docm', '.xlsm')
EXT_MED = ('.html', '.htm', '.zip', '.rar')
URGENT = ['urgent', 'immediately', 'within 24 hours', 'account suspended', 'verify your', 'password expires', 'action required', 'final notice', 'expires']
MONEY = ['wire transfer', 'bank details', 'invoice', 'payment', 'gift card', 'payroll', 'change of account', 'remittance']


def creds():
    c = None
    if os.path.exists('token.json'):
        c = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not c or not c.valid:
        if c and c.expired and c.refresh_token:
            c.refresh(Request())
        else:
            c = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES).run_local_server(port=0)
        open('token.json', 'w').write(c.to_json())
    return c


def root(d):
    return '.'.join(d.split('.')[-2:])


def lookalike(d):
    """Return brand if domain imitates it via character substitution or brand-in-name."""
    d = d.lower()
    n = d.replace('rn', 'm').translate(str.maketrans('0135', 'oles'))
    for b in BRANDS:
        if b in n and b not in d:
            return b, 'character substitution'
        if b in d and root(d).split('.')[0] != b:
            return b, 'brand name inside an unrelated domain'
    return None


def authres(msg):
    h = ' '.join(str(x) for x in msg.get_all('Authentication-Results', [])).lower()
    g = lambda k: (re.search(k + r'=(\w+)', h) or [None, 'not found'])[1]
    return g('spf'), g('dkim'), g('dmarc'), h[:200] or 'not present'


def analyze(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(msg['From'] or ''))
    dom = addr.split('@')[-1].lower()
    _, raddr = parseaddr(str(msg['Reply-To'] or ''))
    rdom = raddr.split('@')[-1].lower() if raddr else ''
    subj = str(msg['Subject'] or '(no subject)')
    try:
        body = msg.get_body(preferencelist=('html', 'plain'))
        text = body.get_content() if body else ''
    except Exception:
        text = ''
    plain = re.sub(r'<[^>]+>', ' ', text)
    low = (subj + ' ' + plain).lower()
    ind = []
    add = lambda t, s, ev, tag, c: ind.append([t, s, ev, tag, c])

    spf, dkim, dmarc, ares = authres(msg)
    for k, v in (('SPF', spf), ('DKIM', dkim), ('DMARC', dmarc)):
        if v in ('fail', 'softfail', 'permerror'):
            add(k + ' check failed', 'HIGH', k.lower() + '=' + v + ' in Authentication-Results', 'Observed', 95)
    if rdom and rdom != dom:
        add('Reply-To domain differs from sender domain', 'MEDIUM', 'From ' + dom + ' vs Reply-To ' + rdom, 'Observed', 90)
    nl = name.lower()
    if ('@' in name and name.split('@')[-1].lower() != dom) or any(b in nl and b not in dom for b in BRANDS):
        add('Display name impersonates another identity', 'HIGH', 'Display name "' + name + '" vs address ' + addr, 'Inferred', 85)
    la = lookalike(dom) if dom else None
    if la:
        add('Look-alike sender domain', 'HIGH', dom + ' imitates "' + la[0] + '" (' + la[1] + ')', 'Inferred', 88)

    hrefs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, re.S | re.I)
    urls = list(dict.fromkeys(re.findall(r'https?://[^\s<>"\')]+', text)))
    for h, label in hrefs:
        lt = re.sub(r'<[^>]+>', '', label).strip()
        m, hh = re.match(r'https?://([^/\s:]+)', lt), re.match(r'https?://([^/:]+)', h)
        if m and hh and m[1].lower() != hh[1].lower():
            add('Link text shows a different site than the real link', 'HIGH', 'Shows ' + m[1] + ' but goes to ' + hh[1], 'Observed', 93)
            break
    hosts = list(dict.fromkeys(re.match(r'https?://([^/:?#]+)', u)[1].lower() for u in urls if re.match(r'https?://([^/:?#]+)', u)))
    for hst in hosts:
        if hst in SHORT:
            add('URL shortener used', 'MEDIUM', hst + ' hides the final destination', 'Observed', 80)
        elif re.fullmatch(r'[\d.]+', hst):
            add('Link points to a raw IP address', 'HIGH', hst, 'Observed', 90)
        elif 'xn--' in hst:
            add('Punycode (possible homoglyph) domain in link', 'MEDIUM', hst, 'Observed', 80)
        elif lookalike(hst) and hst != dom:
            add('Look-alike domain in link', 'HIGH', hst + ' imitates ' + lookalike(hst)[0], 'Inferred', 85)

    atts = []
    for p in msg.iter_attachments():
        data = p.get_payload(decode=True) or b''
        fn = (p.get_filename() or 'unnamed').lower()
        sha = hashlib.sha256(data).hexdigest()
        atts.append((p.get_filename() or 'unnamed', len(data), sha))
        if fn.endswith(EXT_HIGH):
            add('Risky attachment type', 'HIGH', fn + ' (sha256 ' + sha[:12] + '...)', 'Observed', 92)
        elif fn.endswith(EXT_MED):
            add('Attachment type often abused', 'MEDIUM', fn, 'Observed', 75)

    u = [k for k in URGENT if k in low]
    if u:
        add('Urgency language', 'MEDIUM', 'Matched: ' + ', '.join(u[:3]), 'Rule-based', 70)
    mo = [k for k in MONEY if k in low]
    if mo:
        add('Payment / financial language', 'MEDIUM', 'Matched: ' + ', '.join(mo[:3]), 'Rule-based', 70)

    ip = 'not found'
    for r in reversed(msg.get_all('Received', [])):
        for c in re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', str(r)):
            try:
                if ipaddress.ip_address(c).is_global:
                    ip = c
                    break
            except ValueError:
                pass
        if ip != 'not found':
            break

    risk = min(100, sum({'HIGH': 25, 'MEDIUM': 12, 'LOW': 0}[i[1]] for i in ind))
    if not ind:
        add('No rule-based indicators fired', 'LOW', 'Checked auth results, reply-to, look-alikes, links, attachments, keywords', 'Observed', 80)
    kinds = ' '.join(i[0] for i in ind)
    if risk < 25:
        cls = 'No indicators (likely legitimate)'
    elif mo and risk >= 40 and ('Reply-To' in kinds or 'Look-alike' in kinds):
        cls = 'Business Email Compromise (suspected)'
    elif urls and risk >= 50:
        cls = 'Credential Phishing (suspected)'
    else:
        cls = 'Suspicious'
    lvl = 'CRITICAL' if risk >= 90 else 'HIGH' if risk >= 70 else 'MEDIUM' if risk >= 40 else 'LOW'
    h = hashlib.sha1((dom + ip + ''.join(a[2] for a in atts)).encode()).hexdigest().upper()
    try:
        dt = parsedate_to_datetime(str(msg['Date']))
        date, tm = dt.strftime('%d %b %Y %H:%M'), dt.strftime('%H:%M')
    except Exception:
        date, tm = str(msg['Date'] or ''), '--:--'
    return dict(id='MSG-' + h[:6], **{'from': addr or str(msg['From']), 'subj': subj}, risk=risk, lvl=lvl, cls=cls,
                conf=min(95, 55 + risk // 3), time=tm, ind=ind, ip=ip, geo='not looked up, not looked up', dom=dom,
                age='not checked', chain=['Email URL'] + (urls[:3] or ['(no URLs found)']),
                att=atts[0][0] if atts else 'None',
                attd='; '.join('%s, %d bytes, sha256 %s' % a for a in atts) or 'none',
                dna='TT-%s-%s-%s' % (h[:4], h[4:8], h[8:10]), to=str(msg['To'] or ''), reply=raddr or 'none',
                rpath=str(msg['Return-Path'] or ''), mid=str(msg['Message-ID'] or ''), date=date, spf=spf.upper(),
                dkim=dkim.upper(), dmarc=dmarc.upper(), arc='present' if msg['ARC-Seal'] else 'none', authres=ares)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    q = sys.argv[2] if len(sys.argv) > 2 else 'in:inbox'
    svc = build('gmail', 'v1', credentials=creds())
    ids = svc.users().messages().list(userId='me', maxResults=n, q=q).execute().get('messages', [])
    db = sqlite3.connect('threattrace.db')
    db.execute('create table if not exists emails(gid text primary key, ts text, data text)')
    for m in ids:
        raw = base64.urlsafe_b64decode(svc.users().messages().get(userId='me', id=m['id'], format='raw').execute()['raw'])
        d = analyze(raw)
        db.execute('insert or replace into emails values(?,?,?)', (m['id'], d['date'], json.dumps(d)))
        print('%3d  %-32s %s' % (d['risk'], d['from'][:32], d['subj'][:50]))
    db.commit()
    print('Stored %d emails in threattrace.db' % len(ids))


if __name__ == '__main__':
    main()