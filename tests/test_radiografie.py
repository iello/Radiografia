#!/usr/bin/env python3
"""Teste pentru programul Radiografia. Rulează: python3 -m unittest -v (din tests/) sau
   python3 tests/test_radiografie.py . Fără dependențe externe."""
import unittest, os, sys, tempfile, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import radiografie as R

def ep(dstr): return int(datetime.datetime.strptime(dstr,'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp())
SNAP = ep('2026-07-13')

def comp(osname, enabled=True, laps=False, dc=False, llt=None):
    dn = "CN=DC01,OU=DOMAIN CONTROLLERS,DC=T,DC=L" if dc else "CN=PC,OU=S,DC=T,DC=L"
    return {"ObjectIdentifier":"S-1-5-21-1-2-3-"+str(id(osname)%9999),"HasSIDHistory":[],"Properties":{
        "enabled":enabled,"operatingsystem":osname,"haslaps":laps,"distinguishedname":dn,
        "unconstraineddelegation":dc,"sidhistory":[],"serviceprincipalnames":[],
        "lastlogontimestamp": llt if llt is not None else SNAP}}
def usr(oid, **kw):
    p={"enabled":True,"passwordnotreqd":False,"sensitive":False,"hasspn":False,"dontreqpreauth":False,
       "unconstraineddelegation":False,"sidhistory":[],"serviceprincipalnames":[],"lastlogontimestamp":SNAP}
    p.update(kw)
    return {"ObjectIdentifier":oid,"HasSIDHistory":[],"SPNTargets":[],"Properties":p}
def grp(sam, members, rid='512'):
    return {"ObjectIdentifier":"S-1-5-21-1-2-3-"+rid,"Properties":{"name":sam+"@T.L","samaccountname":sam},
            "Members":[{"ObjectIdentifier":m,"ObjectType":"User"} for m in members]}

class TestOS(unittest.TestCase):
    def test_eol_si_suportat(self):
        self.assertEqual(R.os_status("Windows XP Professional Service Pack 3", SNAP)[0], 'EOL')
        self.assertEqual(R.os_status("Windows Server 2012 R2 Standard", SNAP)[0], 'EOL')
        self.assertEqual(R.os_status("Windows 11 Pro", SNAP)[0], 'suportat')
        self.assertEqual(R.os_status("Windows Server 2019 Standard", SNAP)[0], 'suportat')
        self.assertEqual(R.os_status("", SNAP)[0], 'necunoscut')
    def test_win10_time_aware(self):
        # Windows 10 EOL 14.10.2025: EOL după, suportat înainte
        self.assertEqual(R.os_status("Windows 10 Pro", ep('2026-07-13'))[0], 'EOL')
        self.assertEqual(R.os_status("Windows 10 Pro", ep('2025-01-01'))[0], 'suportat')

class TestScor(unittest.TestCase):
    def test_gol(self):
        self.assertEqual(R.posture_score([]), 0)
        self.assertEqual(R.grade_of(0), 'A')
    def test_bounds_si_monoton(self):
        f=lambda s: R.F(s,'t','d','r','n')
        s1=R.posture_score([f('MEDIU')])
        s2=R.posture_score([f('MEDIU'),f('CRITIC')])
        self.assertTrue(0<=s1<=100 and 0<=s2<=100)
        self.assertGreater(s2, s1)                       # mai multe/mai grave → scor mai mare
    def test_critic_grad(self):
        self.assertEqual(R.posture_score([R.F('CRITIC','t','d','r','n')]), 55)
        self.assertEqual(R.grade_of(55), 'D')
        self.assertEqual(R.grade_of(96), 'E')

class TestAnalyze(unittest.TestCase):
    def setUp(self):
        C=[comp("Windows XP Professional") ,comp("Windows 11 Pro"),
           comp("Windows Server 2019 Standard", dc=True)]  # 1 mort, 1 suportat, 1 controler de domeniu (suportat)
        admins=["u%02d"%i for i in range(1,11)]            # 10 administratori de domeniu
        U=[usr(a) for a in admins] + [usr("p1", passwordnotreqd=True)]
        G=[grp("DOMAIN ADMINS", admins, '512'), grp("ENTERPRISE ADMINS", admins[:2], '519')]
        self.f,self.h,self.st,self.sc,self.gr = R.analyze(C,U,G,SNAP)
    def test_stats(self):
        self.assertEqual(self.st['da'], 10)
        self.assertEqual(self.st['ea'], 2)
        self.assertEqual(self.st['dcs'], 1)
        self.assertEqual(self.st['dc_eol'], 0)            # controlerul de domeniu pe 2019 = sănătos
        self.assertEqual(self.st['pnr'], 1)
        self.assertEqual(self.st['xp'], 1)
        self.assertEqual(self.st['pct_eol'], 33)          # 1 mort din 3 cu sistem cunoscut (XP + Win11 + controler-2019)
    def test_findings(self):
        titluri=" | ".join(f.titlu for f in self.f)
        self.assertIn("scoase din suport", titluri)       # apare constatarea de sisteme moarte
        self.assertIn("domain admins", titluri)           # 10 > 8, deci apare
        self.assertNotIn("controlere de domeniu EOL", titluri)  # controler sănătos, NU apare
    def test_healthy(self):
        self.assertTrue(any("SID history" in h for h in self.h))
        self.assertTrue(any("Kerberoasting" in h for h in self.h))

class TestNmap(unittest.TestCase):
    def _load(self, block):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d,"scan.txt"),"w",encoding="utf-8") as fp: fp.write(block)
            return R.load_nmap(d, SNAP)
    def test_parse(self):
        block=("Nmap scan report for srv.test (10.0.0.5)\nHost is up.\nPORT STATE SERVICE\n"
               "22/tcp open ssh\n|_  SSH-2.0-OpenSSH_6.6\n"
               "23/tcp open telnet\n445/tcp open microsoft-ds\n"
               "| smb2-security-mode:\n|_  Message signing enabled but not required\n"
               "443/tcp open https\n| ssl-cert: Not valid after:  2024-01-01\n"
               "3389/tcp open ms-wbt-server\n2049/tcp open nfs\n")
        H=self._load(block)
        self.assertEqual(len(H), 1)
        h=H[0]
        self.assertTrue(h['telnet'] and h['smb_nosign'] and h['rdp'] and h['cert_exp'] and h['ssh_old'] and h['nfs'])
        self.assertEqual(h['name'], 'srv.test')
    def test_gazda_fara_ip(self):
        # doar nume de calculator, fără adresă între paranteze. Trebuie citit, nu ignorat.
        H=self._load("Nmap scan report for myhost\n23/tcp open telnet\n")
        self.assertEqual(len(H), 1)
        self.assertTrue(H[0]['telnet']); self.assertEqual(H[0]['name'], 'myhost')
    def test_ip_singur(self):
        H=self._load("Nmap scan report for 10.9.9.9\n23/tcp open telnet\n")
        self.assertEqual(len(H), 1)
        self.assertTrue(H[0]['telnet']); self.assertIsNone(H[0]['name'])
    def test_cert_data_imposibila(self):
        # dată cu forma bună dar imposibilă: nu trebuie să dărâme tot scanul
        H=self._load("Nmap scan report for x (10.0.0.9)\n443/tcp open https\n"
                     "| ssl-cert: Not valid after: 2024-99-99\n")
        self.assertEqual(len(H), 1); self.assertFalse(H[0]['cert_exp'])
    def test_nfs_regula(self):
        H=self._load("Nmap scan report for x (10.0.0.1)\n2049/tcp open nfs\n")
        f,st=R.analyze_network(H)
        self.assertEqual(st['nfs'], 1)
        self.assertTrue(any("NFS" in x.titlu for x in f))

class TestDetectii(unittest.TestCase):
    # Grupul „fals-liniștitor": înainte, programul tăcea pe cazul rău. Acum trebuie să scoată o constatare.
    def test_delegare_nerestransa_useri(self):
        U=[usr("u1", unconstraineddelegation=True)]
        f,h,st,sc,gr=R.analyze([],U,[],SNAP)
        self.assertEqual(st['ucd_u'], 1)
        self.assertTrue(any("delegare nerestrânsă" in x.titlu for x in f))
    def test_delegare_nerestransa_server_non_dc(self):
        c=comp("Windows 11 Pro"); c['Properties']['unconstraineddelegation']=True
        f,h,st,sc,gr=R.analyze([c],[],[],SNAP)
        self.assertEqual(st['ucd_c'], 1)
        self.assertTrue(any("delegare nerestrânsă" in x.titlu for x in f))
    def test_delegare_pe_dc_e_normala(self):
        dc=comp("Windows Server 2019 Standard", dc=True)  # funcția de ajutor pune delegare nerestrânsă pe controlerul de domeniu
        f,h,st,sc,gr=R.analyze([dc],[],[],SNAP)
        self.assertEqual(st['ucd_c'], 0)                  # controlerul de domeniu e exclus, nu e o problemă
    def test_kerberoasting_peste_prag(self):
        U=[usr("u%d"%i, hasspn=True) for i in range(4)]   # 4, adică peste pragul de 3
        f,h,st,sc,gr=R.analyze([],U,[],SNAP)
        self.assertEqual(st['spn'], 4)
        self.assertTrue(any("Kerberoasting" in x.titlu for x in f))
        self.assertFalse(any("Kerberoasting" in x for x in h))  # când e constatare, nu mai e „sănătos"
    def test_krbtgt_exclus_din_spn(self):
        U=[usr("k", hasspn=True, samaccountname="krbtgt")]
        f,h,st,sc,gr=R.analyze([],U,[],SNAP)
        self.assertEqual(st['spn'], 0)                    # krbtgt are mereu SPN, nu se pune
    def test_sid_history(self):
        U=[usr("u1", sidhistory=["S-1-5-21-9-9-9-1105"])]
        f,h,st,sc,gr=R.analyze([],U,[],SNAP)
        self.assertEqual(st['sidh'], 1)
        self.assertTrue(any("SID history" in x.titlu for x in f))

class TestRobustete(unittest.TestCase):
    def test_laps_pe_gol_nu_declanseaza(self):
        # folder gol → 0 din 0 calculatoare. Nu trebuie să inventeze o alarmă falsă „LAPS 0%".
        f,h,st,sc,gr=R.analyze([],[],[],SNAP)
        self.assertFalse(any("LAPS" in x.titlu for x in f))
    def test_grup_cu_proprietati_null_nu_crapa(self):
        # SharpHound poate scrie name/samaccountname goale (null). Înainte, asta dărâma tot programul.
        G=[{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"name":None,"samaccountname":None},"Members":[]}]
        f,h,st,sc,gr=R.analyze([],[],G,SNAP)             # nu trebuie să arunce
        self.assertEqual(st['da'], 0)
    def test_membri_imbricati_numarati_recursiv(self):
        # un grup băgat în „Domain Admins" trebuie desfăcut și numărați oamenii lui, nu socotit ca 1
        da_group={"ObjectIdentifier":"S-1-5-21-1-2-3-512",
                  "Properties":{"name":"DOMAIN ADMINS@T.L","samaccountname":"DOMAIN ADMINS"},
                  "Members":[{"ObjectIdentifier":"S-1-5-21-1-2-3-7001","ObjectType":"Group"},
                             {"ObjectIdentifier":"direct1","ObjectType":"User"}]}
        inner={"ObjectIdentifier":"S-1-5-21-1-2-3-7001",
               "Properties":{"name":"INNER@T.L","samaccountname":"INNER"},
               "Members":[{"ObjectIdentifier":"u1"},{"ObjectIdentifier":"u2"}]}
        f,h,st,sc,gr=R.analyze([],[],[da_group,inner],SNAP)
        self.assertEqual(st['da'], 3)                     # direct1 + u1 + u2, nu 2 (grup + direct)
    def test_never_logged_e_stale(self):
        # conturile care nu s-au folosit NICIODATĂ (fără dată de intrare) sunt vechi, nu „recente"
        U=[usr("u%d"%i, lastlogontimestamp=None) for i in range(51)]
        f,h,st,sc,gr=R.analyze([],U,[],SNAP)
        self.assertEqual(st['stale_u'], 51)
        self.assertEqual(st['never'], 51)

if __name__=='__main__':
    unittest.main(verbosity=2)
