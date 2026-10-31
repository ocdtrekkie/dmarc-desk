import gzip
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from app import create_app, import_file, parse_xml, unpack, ReportError, LIMIT

FIXTURE = b'''<?xml version="1.0"?><feedback><report_metadata><org_name>Example Receiver</org_name><email>dmarc@receiver.test</email><report_id>test-001</report_id><date_range><begin>1704067200</begin><end>1704153599</end></date_range></report_metadata><policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><pct>100</pct></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>90</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from><envelope_from>mailer.example.net</envelope_from></identifiers><auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim><spf><domain>mailer.example.net</domain><scope>mfrom</scope><result>pass</result></spf></auth_results></record><record><row><source_ip>2001:db8::1</source_ip><count>10</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf><reason><type>local_policy</type><comment>Example override</comment></reason></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>other.test</domain><selector>bad</selector><result>fail</result></dkim><spf><domain>other.test</domain><result>fail</result></spf></auth_results></record></feedback>'''

def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in entries:
            z.writestr(name, content)
    return output.getvalue()

class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({'TESTING':True,'DATA_DIR':self.tmp.name})
        self.client = self.app.test_client()
        self.client.get('/')
        with self.client.session_transaction() as s:
            self.token=s['csrf']
        self.db = sqlite3.connect(Path(self.tmp.name)/'dmarc.sqlite3')

    def tearDown(self):
        self.db.close(); self.tmp.cleanup()

    def test_alignment_not_raw_auth(self):
        parsed = parse_xml(FIXTURE)
        self.assertEqual([r[5] for r in parsed['rows']], [1,0])
        self.assertEqual(parsed['rows'][0][4], 'fail')

    def test_xml_gzip_zip_and_duplicates(self):
        self.assertEqual(import_file(self.db, FIXTURE)['imported'],1)
        self.assertEqual(import_file(self.db, gzip.compress(FIXTURE))['duplicates'],1)
        self.assertEqual(import_file(self.db, archive([('a.xml',FIXTURE)]))['duplicates'],1)
        self.assertEqual(self.db.execute('SELECT SUM(count) FROM records').fetchone()[0],100)

    def test_multidomain_and_filters(self):
        import_file(self.db,FIXTURE)
        import_file(self.db,FIXTURE.replace(b'example.com',b'second.test'))
        result=self.client.get('/api/dashboard').json
        self.assertEqual(result['stats']['total'],200)
        self.assertEqual(result['stats']['failed'],20)
        self.assertEqual(len(result['domains']),2)
        result=self.client.get('/api/dashboard?domain=second.test').json
        self.assertEqual(result['stats']['total'],100)
        self.assertEqual(result['rows'][0]['ip'],'2001:db8::1')

    def test_namespace(self):
        self.assertEqual(parse_xml(FIXTURE.replace(b'<feedback>',b'<feedback xmlns="urn:example:dmarc">'))['domain'],'example.com')

    def test_xxe_and_dtd_rejected(self):
        with self.assertRaises(ReportError):
            parse_xml(b'<!DOCTYPE feedback [<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>')

    def test_zip_expansion_limit(self):
        with self.assertRaises(ReportError):
            unpack(archive([('bomb.xml',b'x'*(LIMIT+1))]))

    def test_gzip_expansion_limit(self):
        with self.assertRaises(ReportError):
            unpack(gzip.compress(b'x'*(LIMIT+1)))

    def test_atomic_zip(self):
        with self.assertRaises(ReportError):
            import_file(self.db,archive([('good.xml',FIXTURE),('bad.xml',b'<bad/>')]))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM reports').fetchone()[0],0)

    def test_no_csrf_no_import(self):
        response=self.client.post('/api/import',data={'files':(io.BytesIO(FIXTURE),'r.xml')})
        self.assertEqual(response.status_code,403)

    def test_upload_and_report_details(self):
        response=self.client.post('/api/import',headers={'X-CSRF-Token':self.token},data={'files':(io.BytesIO(gzip.compress(FIXTURE)),'r.xml.gz')})
        self.assertEqual(response.json['results'][0]['imported'],1)
        row=self.client.get('/api/dashboard').json['rows'][0]
        self.assertEqual(row['auth']['dkim'][0]['selector'],'bad')
        self.assertEqual(row['reasons'][0]['type'],'local_policy')
        self.assertEqual(self.client.get('/api/report/1').json['policy']['p'],'reject')

    def test_period_filter(self):
        import_file(self.db,FIXTURE)
        self.assertEqual(self.client.get('/api/dashboard?start=2024-01-02').json['stats']['total'],0)
        self.assertEqual(self.client.get('/api/dashboard?end=2024-01-01').json['stats']['total'],100)
        self.assertEqual(self.client.get('/api/dashboard?start=bogus').status_code,400)

    def test_persistence(self):
        import_file(self.db,FIXTURE)
        app2=create_app({'TESTING':True,'DATA_DIR':self.tmp.name})
        self.assertEqual(app2.test_client().get('/api/dashboard').json['stats']['total'],100)

    def test_invalid_ip_and_missing_result(self):
        for data in [FIXTURE.replace(b'192.0.2.1',b'not-an-ip'),FIXTURE.replace(b'<spf>fail</spf>',b'')]:
            with self.assertRaises(ReportError):parse_xml(data)

if __name__=='__main__': unittest.main()
