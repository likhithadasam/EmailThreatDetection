import os, json, sqlite3
from ingest import analyze

os.makedirs('samples', exist_ok=True)
A = 'mx.example.com; spf=%s; dkim=%s; dmarc=%s'
OK = A % ('pass', 'pass', 'pass')

# (file, From, Subject, Reply-To, auth results, HTML body)
MAILS = [
 ('paypal_phish', '"PayPal Support" <security@paypa1-support.com>', 'Urgent: verify your account', None,
  A % ('fail', 'fail', 'fail'),
  '<p>Account suspended: verify your details now. <a href="http://185.220.101.4/login">https://paypal.com/verify</a></p>'),
 ('ceo_bec', '"CEO John" <ceo@company-corp.co>', 'Urgent wire transfer needed', 'john.ceo88@gmail.com',
  A % ('pass', 'pass', 'fail'),
  '<p>Please process a wire transfer today and send the bank details. Keep this confidential.</p>'),
 ('hdfc_kyc', '"HDFC Alerts" <alerts@hdfc-secure-login.in>', 'Action required: KYC update', None,
  A % ('pass', 'fail', 'fail'),
  '<p>Action required: update your KYC at https://bit.ly/3xYzKyc</p>'),
 ('netflix_phish', '"Netflix" <support@netfl1x-account.com>', 'Payment declined', None,
  A % ('fail', 'pass', 'pass'),
  '<p>Your payment was declined. Update your card at https://netfl1x-account.com/billing</p>'),
 ('github_digest', 'GitHub <digest@github.com>', 'Your weekly digest', None, OK,
  '<p>You have 3 new stars on your repository this week.</p>'),
 ('coursera_ok', 'Coursera <info@coursera.org>', 'Your course is waiting', None, OK,
  '<p>Continue learning where you left off.</p>'),
]

for name, frm, subj, rp, auth, body in MAILS:
    h = 'From: %s\nTo: demo@example.com\nSubject: %s\nDate: Tue, 29 Sep 2026 10:00:00 +0000\nMessage-ID: <%s@example.com>\nContent-Type: text/html; charset=utf-8\n' % (frm, subj, name)
    if rp: h += 'Reply-To: %s\n' % rp
    h += 'Authentication-Results: %s\n' % auth
    open('samples/%s.eml' % name, 'w', encoding='utf-8').write(h + '\n' + body)

rows = [analyze(open('samples/%s.eml' % m[0], 'rb').read()) for m in MAILS]
rows.sort(key=lambda d: -d['risk'])
for d in rows:
    print('%3d  %-9s %-32s %s' % (d['risk'], d['lvl'], d['from'][:32], d['cls']))

open('sample_emails.js', 'w', encoding='utf-8').write('const EMAILS = ' + json.dumps(rows, indent=2) + ';')
db = sqlite3.connect('sample.db')
db.execute('create table if not exists emails(gid text primary key, ts text, data text)')
for d in rows:
    db.execute('insert or replace into emails values(?,?,?)', (d['id'], d['date'], json.dumps(d)))
db.commit()
print('Scored', len(rows), 'sample emails')