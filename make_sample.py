import sqlite3, json

P, B, S, L = ('Credential Phishing (suspected)', 'Business Email Compromise (suspected)',
              'Suspicious', 'No indicators (likely legitimate)')
LA = lambda d, b: ['Look-alike sender domain', 'HIGH', d + ' imitates "' + b + '"', 'Inferred', 88]
U = lambda m: ['Urgency language', 'MEDIUM', 'Matched: ' + m, 'Rule-based', 70]
M = lambda m: ['Payment / financial language', 'MEDIUM', 'Matched: ' + m, 'Rule-based', 70]
LNK = ['Link text shows a different site than the real link', 'HIGH', 'Shows a trusted site but goes to another domain', 'Observed', 93]
SHORT = ['URL shortener used', 'MEDIUM', 'bit.ly hides the final destination', 'Observed', 80]
IPL = ['Link points to a raw IP address', 'HIGH', '185.220.101.4', 'Observed', 90]
RPL = ['Reply-To domain differs from sender domain', 'MEDIUM', 'Reply-To is a free Gmail address', 'Observed', 90]
DN = ['Display name impersonates another identity', 'HIGH', 'Display name "CEO" does not match the sender address', 'Inferred', 85]
ATT = ['Risky attachment type', 'HIGH', 'invoice_4471.docm (sha256 9f2a4c1d7e30...)', 'Observed', 92]
ATM = ['Attachment type often abused', 'MEDIUM', 'agreement.html', 'Observed', 75]
OK = ['No rule-based indicators fired', 'LOW', 'Checked auth results, links, attachments', 'Observed', 80]
ST = {'P': 'PASS', 'F': 'FAIL'}

def mk(i, frm, subj, risk, cls, inds, auth='PPP', att=None, rp='none'):
    lvl = 'CRITICAL' if risk >= 90 else 'HIGH' if risk >= 70 else 'MEDIUM' if risk >= 40 else 'LOW'
    t = '%02d:%02d' % (8 + i // 4, (i * 13) % 60)
    return dict(id='MSG-%03d' % i, **{'from': frm, 'subj': subj}, risk=risk, lvl=lvl, cls=cls,
        conf=min(95, 55 + risk // 3), time=t, ind=inds, ip='203.0.113.%d' % i,
        geo='not looked up', dom=frm.split('@')[-1], age='not checked',
        chain=['Email URL', '(sample)'], att=att or 'None',
        attd=(att + ', 48213 bytes, sha256 9f2a4c1d7e30') if att else 'none',
        dna='TT-SAMPLE-%03d' % i, to='demo@example.com', reply=rp, rpath=frm,
        mid='<sample%d@example.com>' % i, date='29 Sep 2026 ' + t,
        spf=ST[auth[0]], dkim=ST[auth[1]], dmarc=ST[auth[2]], arc='none', authres='sample data')

data = [
 ('security@paypa1-support.com', 'Urgent: verify your account', 92, P, [LA('paypa1-support.com', 'paypal'), U('urgent, verify your'), LNK], 'FFF'),
 ('billing@micros0ft-billing.com', 'Your Microsoft 365 subscription expires', 85, P, [LA('micros0ft-billing.com', 'microsoft'), U('expires')], 'FFP'),
 ('alerts@hdfc-secure-login.in', 'Action required: KYC update', 88, P, [LA('hdfc-secure-login.in', 'hdfc'), U('action required'), SHORT], 'PFF'),
 ('noreply@amazon-delivery.top', 'Package on hold: confirm address', 78, P, [LA('amazon-delivery.top', 'amazon'), IPL], 'FPF'),
 ('support@netfl1x-account.com', 'Payment declined, update your card', 81, P, [LA('netfl1x-account.com', 'netflix'), M('payment'), SHORT], 'FFP'),
 ('docs@docusign-review.net', 'Please review and sign document', 74, P, [LA('docusign-review.net', 'docusign'), ATM], 'PFF', 'agreement.html'),
 ('it-helpdesk@company-support.org', 'Password expires in 24 hours', 68, P, [U('within 24 hours, password expires'), SHORT], 'PPF'),
 ('hr@company-payroll.net', 'Updated payroll schedule', 70, B, [RPL, M('payroll')], 'PPF', None, 'hr.payroll88@gmail.com'),
 ('ceo@company-corp.co', 'Urgent wire transfer needed', 89, B, [DN, RPL, M('wire transfer'), U('urgent')], 'PFF', None, 'john.ceo88@gmail.com'),
 ('accounts@vendor-invoices.biz', 'Invoice #4471 overdue', 83, S, [M('invoice, payment'), ATT], 'FPP', 'invoice_4471.docm'),
 ('parcel@dhl-express-track.info', 'Your parcel could not be delivered', 76, P, [LA('dhl-express-track.info', 'dhl'), SHORT], 'PFP'),
 ('security@faceb00k-alerts.com', 'Someone tried to log in', 80, P, [LA('faceb00k-alerts.com', 'facebook'), U('verify your'), LNK], 'FFF'),
 ('digest@github.com', 'Your weekly digest', 0, L, [OK]),
 ('no-reply@accounts.google.com', 'Security alert', 12, L, [U('action required')]),
 ('newsletter@linkedin.com', '5 jobs that match your profile', 0, L, [OK]),
 ('receipts@swiggy.in', 'Your order receipt', 12, L, [M('invoice, payment')]),
 ('team@devpost.com', 'Hackathon submissions close soon', 12, L, [U('expires')]),
 ('noreply@irctc.co.in', 'Ticket booking confirmation', 0, L, [OK]),
 ('info@coursera.org', 'Your course is waiting for you', 0, L, [OK]),
 ('noreply@zoom.us', 'Meeting reminder: Project sync', 0, L, [OK]),
]
rows = [mk(i + 1, *r) for i, r in enumerate(data)]

open('sample_emails.js', 'w', encoding='utf-8').write('const EMAILS = ' + json.dumps(rows, indent=2) + ';')
db = sqlite3.connect('sample.db')
db.execute('create table if not exists emails(gid text primary key, ts text, data text)')
for r in rows:
    db.execute('insert or replace into emails values(?,?,?)', (r['id'], r['date'], json.dumps(r)))
db.commit()
print(len(rows), 'sample emails created')