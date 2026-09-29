import sqlite3, json

db = sqlite3.connect('threattrace.db')
rows = [json.loads(r[0]) for r in db.execute('select data from emails')]
open('emails.js', 'w', encoding='utf-8').write('const EMAILS = ' + json.dumps(rows, indent=2) + ';')
print(len(rows), 'emails exported')