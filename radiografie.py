#!/usr/bin/env python3
"""
Radiografia, programul (versiune de probă).

Ce face, pe scurt: ia ce ai strâns despre calculatoarele și rețeaua instituției
tale și îți scoate o „radiografie", o foaie în română care spune ce e stricat și
ce repari mai întâi.

De unde ia datele: din două programe cunoscute, pe care le rulezi tu. SharpHound
se uită la conturile și calculatoarele din rețeaua Windows (Active Directory).
nmap se uită ce servicii sunt pornite pe rețea. Amândouă lasă niște fișiere, iar
programul ăsta le citește și scrie o pagină web cu rezultatul.

Ce NU face: nu-ți cere nicio parolă (nu are un fișier de secrete „.env"), nu se
leagă la internet și nu trimite nimic nicăieri. Citește fișiere de pe calculator,
scrie o pagină. Atât.

Cum îl pornești:
  python3 radiografie.py <folder_cu_date> <rezultat.html> [--data-snapshot 2026-07-13] [--net <folder>]

E doar o versiune de probă. Programul „adevărat" (în Rust) rămâne de decis cu arhitectul.
"""
import json, glob, os, sys, html, datetime, re

# ---------- Citirea fișierelor ----------
def load(d):
    # Citește cele trei feluri de fișiere de care avem nevoie (calculatoare, utilizatori,
    # grupuri). Dacă unul lipsește sau e stricat, îl sărim și mergem mai departe, nu oprim
    # tot programul din cauza lui.
    def rd(kind):
        fs=sorted(glob.glob(os.path.join(d, f"*_{kind}.json")), key=os.path.getmtime, reverse=True)
        if not fs:
            return []
        if len(fs)>1:
            # Sunt mai multe fișiere de același fel în folder. Îl luăm pe cel mai nou (după data
            # lui) și spunem clar care, ca omul să nu se mire de unde vin cifrele.
            print(f"Atenție: mai multe fișiere *_{kind}.json în folder. Folosesc cel mai recent ({os.path.basename(fs[0])}).", file=sys.stderr)
        try:
            with open(fs[0], encoding='utf-8') as fp:
                j=json.load(fp)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            # Fișier rupt, gol, sau scris altfel decât ne așteptam (de pildă, o colectare
            # întreruptă la mijloc). Îl sărim, ca să iasă totuși un raport din ce e bun.
            print(f"Atenție: nu pot citi {os.path.basename(fs[0])} ({e.__class__.__name__}). Îl sar.", file=sys.stderr)
            return []
        if not isinstance(j, dict):
            return []
        return j.get('data',[]) or []
    return rd('computers'), rd('users'), rd('groups')

def P(o):
    # Scurtătură spre „proprietățile" unui obiect din fișierele SharpHound. Întoarce mereu
    # un dicționar, ca să nu crape nimic dacă lipsesc.
    return o.get('Properties',{}) or {}

# ---------- Ce sistem de operare are fiecare calculator ----------
# Sisteme de operare care nu mai primesc actualizări de securitate („moarte"), fiecare cu data
# la care au murit. Comparăm data asta cu ziua în care ai strâns datele, ca un sistem să fie
# socotit mort doar dacă chiar murise ATUNCI, nu după. Windows 10, de exemplu, a ieșit din
# suport abia pe 14.10.2025.
EOL_OS = [
 (r'\bxp\b','Windows XP','2014-04-08'),
 (r'server\s*2003','Server 2003','2015-07-14'),
 (r'server\s*2008','Server 2008/2008 R2','2020-01-14'),
 (r'server\s*2012','Server 2012/2012 R2','2023-10-10'),
 (r'\bvista\b','Windows Vista','2017-04-11'),
 (r'windows\s*7','Windows 7','2020-01-14'),
 (r'windows\s*8(\.1)?','Windows 8/8.1','2023-01-10'),
 (r'windows\s*10\b','Windows 10','2025-10-14'),
 (r'server\s*2000','Server 2000','2010-07-13'),
]
# Sisteme care încă primesc actualizări. Le recunoaștem anume, ca să nu le socotim greșit moarte.
SUPPORTED = [r'server\s*2016', r'server\s*2019', r'server\s*2022', r'server\s*2025',
             r'windows\s*11\b']
def _ep(dstr):
    # Transformă o dată scrisă „2024-01-31" într-un număr, ca să putem compara date între ele.
    # Dacă data e imposibilă (de pildă 2024-99-99), crapă intenționat, iar cine o cheamă prinde eroarea.
    return int(datetime.datetime.strptime(dstr,'%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp())
def os_status(s, snap):
    # Spune în ce stare e sistemul de operare al unui calculator: „EOL" (mort, fără actualizări),
    # „suportat" (încă primește actualizări), „necunoscut" (colectarea nu i-a prins sistemul), sau
    # „altul" (ceva ce nu recunoaștem).
    s=(s or '').lower()
    if not s.strip():
        return ('necunoscut', None)
    for pat,label,eol in EOL_OS:
        if re.search(pat,s):
            # E mort doar dacă data la care a ieșit din suport a trecut deja față de ziua colectării.
            return ('EOL' if _ep(eol)<=snap else 'suportat', (label,eol))
    for pat in SUPPORTED:
        if re.search(pat,s):
            return ('suportat', None)
    return ('altul', None)

# ---------- Ajutoare mărunte ----------
def truthy(v):
    # SharpHound scrie uneori adevărat/fals curat, alteori ca text „true". Le înțelegem pe amândouă.
    return v is True or str(v).lower()=='true'
def epoch(v):
    # O dată-oră validă e un număr mare (secunde de la anul 1970). Orice altceva (0, gol, lipsă)
    # înseamnă „nu știm" și întoarcem nimic. Cine o cheamă decide ce face atunci.
    try:
        v=int(v)
    except (TypeError, ValueError):
        return None
    return v if v>1_000_000_000 else None

# ---------- Regulile ----------
class F:
    # Un lucru găsit: cât e de grav, titlul, dovada (cifra), cum se repară și ce obligație din legea NIS2 atinge.
    def __init__(s,sev,titlu,dovada,remediere,nis2,calib=None):
        s.sev=sev; s.titlu=titlu; s.dovada=dovada; s.remediere=remediere; s.nis2=nis2; s.calib=calib
SEV_ORD={'CRITIC':0,'MARE':1,'MEDIU':2,'MIC':3,'OK':4}
# Scorul de RISC (0 = perfect, 100 = dezastru; mai mic e mai bine). Fiecare lucru găsit adaugă o
# bucată de risc, iar bucățile se adună așa încât multe probleme mărunte nu urcă scorul cât o
# singură problemă gravă. Așa deosebim o instituție cu o gaură critică de una cu multe fleacuri.
SEV_RISK={'CRITIC':0.55,'MARE':0.28,'MEDIU':0.10,'MIC':0.03,'OK':0.0}
def posture_score(findings):
    prod=1.0
    for f in findings:
        prod*=(1-SEV_RISK[f.sev])
    return round(100*(1-prod))
def grade_of(score):
    return 'A' if score<10 else 'B' if score<30 else 'C' if score<55 else 'D' if score<80 else 'E'

def analyze(C,U,G,snapshot):
    stale_th = snapshot - 365*86400   # linia peste care un cont e „vechi": nefolosit de peste un an
    findings=[]; healthy=[]
    n_comp=len(C); n_user=len(U)
    comp_enabled=[c for c in C if truthy(P(c).get('enabled'))]

    # ---------- Ce sisteme de operare rulează ----------
    eol=[]; xp=0; unknown=0; sup=0
    for c in comp_enabled:
        st,info=os_status(P(c).get('operatingsystem'), snapshot)
        if st=='EOL':
            eol.append(c)
            if 'xp' in (P(c).get('operatingsystem') or '').lower(): xp+=1
        elif st=='suportat': sup+=1
        elif st=='necunoscut': unknown+=1
    base=len(eol)+sup   # calculăm procentul doar din calculatoarele cărora le știm sistemul (restul nu-l putem judeca)
    pct_eol = round(100*len(eol)/base) if base else 0
    if base and pct_eol>=25:
        # Spunem procentul, dar spunem cinstit și pe câte calculatoare nu am aflat sistemul
        # (SharpHound nu le prinde pe cele oprite), ca procentul să nu pară mai sigur decât e.
        nota_unknown = f" {unknown} calculatoare au OS neidentificat (nu intră în procent)." if unknown else ""
        findings.append(F('CRITIC', f"{pct_eol}% din parcul cu OS cunoscut rulează sisteme scoase din suport",
            f"{len(eol)} din {base} calculatoare active pe OS scos din suport (din care {xp} pe Windows XP).{nota_unknown} {n_comp} obiecte-calculator în total.",
            "Plan de retragere sau migrare a sistemelor moarte. Până le înlocuiești, izolează-le în rețea.",
            "NIS2 art. 21(2)(e), securitatea achiziției și mentenanței, patching"))
    if unknown and base and unknown>=base:
        # Dacă nu am aflat sistemul pe mai multe calculatoare decât pe câte am aflat, cifrele
        # despre sisteme acoperă doar o parte. O spunem deschis, ca să nu păcălim pe nimeni.
        findings.append(F('MIC', f"OS neidentificat pe {unknown} calculatoare (clasificare parțială)",
            f"Cifrele despre sistemele de operare acoperă doar {base} calculatoare cu OS cunoscut din {n_comp}. Restul nu au putut fi clasificate (adesea mașini oprite la colectare).",
            "Reia colectarea cu mașinile pornite, sau completează inventarul de OS din altă sursă.",
            "NIS2 art. 21(2)(i), inventar"))

    # ---------- LAPS: parolă de administrator diferită pe fiecare calculator ----------
    joinable=[c for c in comp_enabled if os_status(P(c).get('operatingsystem'), snapshot)[0] in ('EOL','suportat')]
    laps=[c for c in joinable if truthy(P(c).get('haslaps'))]
    cov=round(100*len(laps)/len(joinable)) if joinable else 0
    if joinable and cov<50:
        # Dacă nu avem niciun calculator de numărat, tăcem. Altfel, pe un folder gol, „0 din 0" ar da o alarmă falsă de „0% LAPS".
        findings.append(F('MARE', f"Parole de administrator local ne-randomizate (LAPS {cov}%)",
            f"Doar {len(laps)} din {len(joinable)} calculatoare au LAPS. Fără el, parola de admin local e probabil aceeași peste tot, deci o singură mașină spartă le descuie pe toate.",
            "Activează LAPS (Windows LAPS) pe tot parcul înrolat în domeniu.",
            "NIS2 art. 21(2)(i), igiena de bază, control acces"))

    # ---------- Controlerele de domeniu (calculatoarele-șef ale rețelei) ----------
    dcs=[c for c in C if 'OU=DOMAIN CONTROLLERS' in (P(c).get('distinguishedname') or '').upper()]
    dc_oids={c.get('ObjectIdentifier') for c in dcs}
    dc_eol=[c for c in dcs if os_status(P(c).get('operatingsystem'), snapshot)[0]=='EOL']
    if dc_eol:
        oss=sorted(set(P(c).get('operatingsystem','?') for c in dc_eol))
        findings.append(F('CRITIC', f"Rădăcina de încredere pe OS mort: {len(dc_eol)}/{len(dcs)} controlere de domeniu EOL",
            f"Controlere pe: {', '.join(oss)}. Controlerul de domeniu e rădăcina de încredere a întregii rețele. Dacă el e putred, tot ce se sprijină pe el moștenește riscul.",
            "Calendar de migrare a controlerelor pe OS suportat, cu prioritate.",
            "NIS2 art. 21(2)(e),(i)"))

    # ---------- Grupuri privilegiate ----------
    G_by_oid={ (g.get('ObjectIdentifier') or ''): g for g in G }
    def members(gname, rid):
        # Găsește grupul după numărul lui (ultimele cifre din codul SID, la fel în orice limbă),
        # cu numele ca rezervă. Apoi numără OAMENII, nu cutiile: dacă în „Domain Admins" e băgat
        # alt grup, intrăm în el și numărăm oamenii lui adevărați, nu grupul ca 1.
        target=None
        for g in G:
            oid=g.get('ObjectIdentifier') or ''
            sam=(P(g).get('samaccountname') or '').upper()
            nm=(P(g).get('name') or '').upper()
            if oid.endswith('-'+rid) or sam==gname or nm.startswith(gname+'@'):
                target=g; break
        if target is None:
            return set()
        seen=set(); out=set()
        def walk(grp):
            for m in (grp.get('Members',[]) or []):
                if not isinstance(m,dict): continue
                moid=m.get('ObjectIdentifier')
                if not moid or moid in seen: continue
                seen.add(moid)
                sub=G_by_oid.get(moid)
                if sub is not None:
                    walk(sub)        # e un grup băgat înăuntru, coborâm în el
                else:
                    out.add(moid)    # e o persoană sau un calculator, îl numărăm
        walk(target)
        return out
    da_set=members('DOMAIN ADMINS','512'); ea_set=members('ENTERPRISE ADMINS','519')
    da=len(da_set); ea=len(ea_set)
    if da>8 or ea>3:
        findings.append(F('MEDIU', f"Prea multe conturi privilegiate: {da} domain admins, {ea} enterprise admins",
            "Peste pragul de bună practică (idealul e câțiva, numărați pe degete). Cu cât mai mulți admini, cu atât mai multe conturi de furat ca să iei tot.",
            "Redu la minim, conturi separate pentru administrare, stații dedicate (PAW).",
            "NIS2 art. 21(2)(i),(j), control acces, MFA"))

    # ---------- Conturi la care parola nu e obligatorie ----------
    pnr=[u for u in U if truthy(P(u).get('enabled')) and truthy(P(u).get('passwordnotreqd'))]
    if pnr:
        findings.append(F('MEDIU', f"{len(pnr)} conturi la care o parolă goală e posibilă tehnic",
            f"Flag-ul passwordnotreqd e pus pe {len(pnr)} conturi active.",
            "Scoate flag-ul și impune o politică de parole.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Conturi de administrator nemarcate „nu poate fi delegat" ----------
    priv_names=da_set | ea_set
    priv_users=[u for u in U if u.get('ObjectIdentifier') in priv_names]
    not_sensitive=[u for u in priv_users if not truthy(P(u).get('sensitive'))]
    if not_sensitive:
        findings.append(F('MEDIU', f"{len(not_sensitive)} conturi privilegiate nemarcate „sensibil, nu poate fi delegat\"",
            "Conturile privilegiate ar trebui marcate ca nedelegabile, ca să nu poată fi abuzate printr-un mecanism de delegare.",
            "Bifează „Account is sensitive and cannot be delegated\" pe toate conturile privilegiate.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Delegare nerestrânsă ----------
    # Un cont sau calculator cu „delegare nerestrânsă" ține la el legitimațiile de acces (biletele
    # Kerberos) ale oricui se conectează la el. Dacă e spart, atacatorul ia inclusiv biletul unui
    # administrator. E una dintre cele mai scurte scurtături spre a lua toată rețeaua.
    ucd_u=[u for u in U if truthy(P(u).get('enabled')) and truthy(P(u).get('unconstraineddelegation'))]
    if ucd_u:
        findings.append(F('CRITIC', f"{len(ucd_u)} conturi de utilizator cu delegare nerestrânsă (unconstrained delegation)",
            "Un asemenea cont poate colecta biletele Kerberos ale oricui îl folosește, inclusiv ale unui administrator. E una dintre cele mai directe căi spre preluarea domeniului.",
            "Scoate delegarea nerestrânsă de pe conturi. Unde chiar trebuie, folosește delegare constrânsă (bazată pe resursă).",
            "NIS2 art. 21(2)(i),(j)"))
    # Pe controlerele de domeniu asta e normal, așa că nu le punem la socoteală.
    ucd_c=[c for c in comp_enabled if truthy(P(c).get('unconstraineddelegation')) and c.get('ObjectIdentifier') not in dc_oids]
    if ucd_c:
        findings.append(F('MARE', f"{len(ucd_c)} servere (altele decât controlerele de domeniu) cu delegare nerestrânsă",
            "Pe un controler de domeniu e firesc. Pe un server obișnuit e o capcană: cine sparge serverul fură biletele Kerberos ale tuturor celor care l-au folosit.",
            "Scoate delegarea nerestrânsă de pe serverele care nu sunt controlere de domeniu.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Conturi vechi sau nefolosite ----------
    def _stale(u):
        # „Vechi" = ori ultima intrare în cont e mai veche de un an, ori contul nu a fost folosit
        # NICIODATĂ (nu are dată de intrare). Un cont activ nefolosit vreodată e la fel de suspect ca unul uitat de mult.
        lt=epoch(P(u).get('lastlogontimestamp'))
        return lt is None or lt<stale_th
    stale_u=[u for u in U if truthy(P(u).get('enabled')) and _stale(u)]
    never=[u for u in U if truthy(P(u).get('enabled')) and epoch(P(u).get('lastlogontimestamp')) is None]
    if len(stale_u)>50:
        nota_never = f" Dintre ele, {len(never)} nu s-au autentificat niciodată." if never else ""
        findings.append(F('MIC', f"{len(stale_u)} conturi active nefolosite de peste un an",
            f"Conturi neduse la retragere înseamnă suprafață inutilă de atac.{nota_never}",
            "Dezactivare sau retragere periodică a conturilor inactive.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Conturi cărora li se poate fura parola prea ușor (AS-REP roasting) ----------
    asrep=[u for u in U if truthy(P(u).get('enabled')) and truthy(P(u).get('dontreqpreauth'))]
    if asrep:
        findings.append(F('MEDIU', f"{len(asrep)} conturi vulnerabile la AS-REP roasting (pre-autentificare Kerberos oprită)",
            "Conturi cu „Do not require Kerberos preauthentication”. La ele, un atacator poate cere un hash pe care apoi îl sparge offline, în liniște.",
            "Reactivează pre-autentificarea Kerberos.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Kerberoasting ----------
    # Un cont de utilizator cu „SPN" (un fel de etichetă de serviciu) poate fi cerut de oricine din
    # rețea, iar apoi parola lui poate fi spartă liniștit, pe calculatorul atacatorului. Contul special
    # „krbtgt" are mereu SPN și nu se pune, așa că îl scoatem din numărătoare.
    spn_users=[u for u in U if truthy(P(u).get('enabled')) and (truthy(P(u).get('hasspn')) or P(u).get('serviceprincipalnames'))
               and (P(u).get('samaccountname') or '').lower()!='krbtgt']
    if len(spn_users)>3:
        findings.append(F('MEDIU', f"{len(spn_users)} conturi de utilizator cu SPN (expuse la Kerberoasting)",
            "Cu cât mai multe conturi de utilizator cu SPN, cu atât mai mare suprafața de Kerberoasting. Fiecare e o parolă care se poate sparge offline.",
            "Redu numărul lor. Unde rămân, dă-le parole lungi și aleatorii (peste 25 de caractere) sau conturi gestionate de grup (gMSA).",
            "NIS2 art. 21(2)(i)"))

    # ---------- SID history ----------
    # „SID history" lipește pe un cont drepturile altui cont (uneori unul de administrator, dintr-un
    # domeniu vechi). E o cale curată de a-ți crește drepturile pe ascuns și de a rămâne înăuntru, greu de văzut.
    sidh=[o for o in (C+U) if o.get('HasSIDHistory') or P(o).get('sidhistory')]
    if sidh:
        findings.append(F('MARE', f"{len(sidh)} obiecte cu SID history",
            "SID history poate purta pe tăcute drepturile unui cont privilegiat vechi. E folosit și ca escaladare, și ca ușă din spate care rezistă la schimbarea parolei.",
            "Verifică fiecare intrare și curăț-o pe cea care nu are o migrare reală în spate.",
            "NIS2 art. 21(2)(i)"))

    # ---------- Ce e sănătos (ca raportul să nu doar sperie) ----------
    if not spn_users:
        healthy.append("Suprafață de Kerberoasting practic zero (niciun cont de utilizator cu SPN).")
    if not sidh:
        healthy.append("Fără istoric de identificatori clonați (SID history), nicio urmă de migrare abuzabilă.")
    if not ucd_u and not ucd_c:
        healthy.append("Fără delegare nerestrânsă în afara controlerelor de domeniu.")

    findings.sort(key=lambda f: SEV_ORD[f.sev])
    score=posture_score(findings); grada=grade_of(score)
    stats=dict(n_comp=n_comp, n_user=n_user, eol=len(eol), base=base, pct_eol=pct_eol, xp=xp,
               unknown=unknown, laps_cov=cov, dcs=len(dcs), dc_eol=len(dc_eol), da=da, ea=ea,
               pnr=len(pnr), stale_u=len(stale_u), never=len(never), ucd_u=len(ucd_u), ucd_c=len(ucd_c),
               spn=len(spn_users), sidh=len(sidh))
    return findings, healthy, stats, score, grada

# ---------- Citirea scanurilor de rețea (nmap) ----------
DB_PORTS={5432:'PostgreSQL',3306:'MySQL',1521:'Oracle',1433:'MSSQL',27017:'MongoDB',6379:'Redis'}
def load_nmap(d, scan_ep):
    hosts={}
    for f in glob.glob(os.path.join(d,'*')):
        if os.path.basename(f).startswith('.') or not os.path.isfile(f): continue
        # Citim mereu ca UTF-8 și înlocuim caracterele ciudate, ca un semn straniu din răspunsul
        # unui calculator să nu ne oprească toată analiza rețelei.
        with open(f,encoding='utf-8',errors='replace') as fp: txt=fp.read()
        for b in re.split(r'(?=^Nmap scan report for )', txt, flags=re.M):
            m=re.match(r'Nmap scan report for +(\S.*)', b)
            if not m: continue
            head=m.group(1).splitlines()[0].strip()
            # Rândul poate arăta în trei feluri: „nume (adresă)", doar „adresă", sau doar „nume".
            mm=re.match(r'^(\S+) \(([^)]+)\)$', head)
            if mm:
                name, key = mm.group(1), mm.group(2)
            else:
                tok=head.split()[0]
                # Arată a adresă (doar cifre, litere de la a la f, „:" și „.", și are măcar o cifră)? Atunci
                # e adresă, fără nume. Altfel e un nume de calculator, pe care îl folosim și ca nume, și ca cheie.
                if re.match(r'^[0-9a-fA-F:.]+$', tok) and any(ch.isdigit() for ch in tok):
                    name, key = None, tok
                else:
                    name, key = tok, tok
            h=hosts.setdefault(key, dict(name=None,telnet=False,smb_nosign=False,ssh_old=False,
                cert_exp=False,memc=False,rdp=False,websphere=False,db=False,nfs=False))
            if name and not name[0].isdigit(): h['name']=name
            for pm in re.finditer(r'^(\d+)/tcp\s+open\s+(\S+)', b, flags=re.M):
                port=int(pm.group(1)); svc=pm.group(2)
                if port==23: h['telnet']=True
                if port==3389 or 'ms-wbt' in svc: h['rdp']=True
                if port==9080: h['websphere']=True
                if port==11211 or 'memcache' in svc: h['memc']=True
                if port==2049 or svc=='nfs': h['nfs']=True
                if port in DB_PORTS: h['db']=True
            vs=[float(v) for v in re.findall(r'OpenSSH[_ ]([0-9]+\.[0-9]+)', b)]
            if vs and min(vs)<7.0: h['ssh_old']=True
            if 'Message signing enabled but not required' in b: h['smb_nosign']=True
            for dt in re.findall(r'Not valid after:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})', b):
                # O dată cu forma bună dar imposibilă (2024-99-99) ar crăpa. O ignorăm, nu dărâmăm
                # tot scanul din cauza unui certificat ciudat.
                try:
                    if _ep(dt)<scan_ep: h['cert_exp']=True
                except ValueError:
                    continue
    return list(hosts.values())

def analyze_network(H):
    findings=[]
    def c(k): return sum(1 for h in H if h[k])
    named=sum(1 for h in H if h['name'])
    rules=[
     ('telnet','MARE',"Telnet în clar pe {n} sisteme","Administrare fără criptare (parolele trec în text clar) chiar în inima rețelei.","Scoate telnet peste tot. Alternative criptate (SSH) există de zeci de ani.","NIS2 art. 21(2)(h), criptografie"),
     ('smb_nosign','MEDIU',"Semnătură SMB neimpusă pe {n} sisteme","Deschide o clasă de atacuri de retransmitere pe rețeaua internă.","Impune semnătura SMB prin politică.","NIS2 art. 21(2)(i)"),
     ('memc','MEDIU',"Cache (memcached) fără autentificare pe {n} sisteme","Serviciu de cache accesibil pe rețea, fără nicio autentificare.","Leagă-l la localhost sau pune-l în spatele unui firewall, cu autentificare.","NIS2 art. 21(2)(i)"),
     ('rdp','MEDIU',"Desktop la distanță (RDP) expus pe {n} sisteme","Sesiuni grafice de administrare direct pe rețeaua internă.","Restrânge RDP (VPN sau bastion), NLA, MFA.","NIS2 art. 21(2)(i),(j)"),
     ('nfs','MEDIU',"Partajări NFS expuse pe {n} sisteme","Export-uri de fișiere prin NFS (port 2049) accesibile pe rețea, adesea fără autentificare puternică.","Restrânge export-urile NFS (liste de gazde, firewall) sau mută-le în spatele unei rețele de administrare.","NIS2 art. 21(2)(i)"),
     ('websphere','MEDIU',"Administrare de tip WebSphere (port 9080) pe {n} sisteme","Consolă de administrare a aplicației expusă pe rețea, posibil pe o versiune veche.","Restrânge accesul la consolă și actualizeaz-o.","NIS2 art. 21(2)(e)"),
     ('db','MEDIU',"Port de bază de date deschis pe rețea, pe {n} sisteme","Baze de date care ascultă pe rețea (PostgreSQL, Oracle, MySQL și altele).","Segmentează, leagă-le la interfețe interne, firewall.","NIS2 art. 21(2)(i)"),
     ('ssh_old','MEDIU',"Versiuni vechi de SSH (sub 7.0) pe {n} sisteme","Semn că rulează pe sisteme de operare ieșite din suport.","Actualizează OpenSSH sau migrează OS-ul.","NIS2 art. 21(2)(e)"),
     ('cert_exp','MIC',"Certificate TLS expirate pe {n} sisteme","Certificate efectiv expirate, verificate pe dată.","Reînnoire și automatizare (ACME).","NIS2 art. 21(2)(h)"),
    ]
    for k,sev,t,dov,rem,nis in rules:
        n=c(k)
        if n: findings.append(F(sev,t.format(n=n),dov,rem,nis))
    stats=dict(hosts=len(H),named=named,telnet=c('telnet'),smb=c('smb_nosign'),rdp=c('rdp'),nfs=c('nfs'),
               websphere=c('websphere'),db=c('db'),certs=c('cert_exp'),ssh=c('ssh_old'))
    return findings, stats

# ---------- Raport HTML ----------
SEV_COLOR={'CRITIC':'#A6372E','MARE':'#C0562E','MEDIU':'#C08A2D','MIC':'#8A8782','OK':'#3E7C5A'}
def render(findings, healthy, stats, score, grada, snapshot_str, out, net_stats=None):
    # Tot ce vine din colectare (și ar putea fi pus intenționat de un atacator, de pildă un nume de
    # sistem falsificat) e mai întâi curățat de cod periculos, cu esc(), înainte să ajungă în pagină.
    # În plus, o regulă strictă în pagină (CSP) face ca, și dacă ceva ar scăpa, browserul tot să nu
    # ruleze niciun script. Două plase de siguranță, nu una.
    def esc(x): return html.escape(str(x))
    rows=''.join(f'''<tr>
      <td><span class="pill" style="background:{SEV_COLOR[f.sev]}">{f.sev}</span></td>
      <td><strong>{esc(f.titlu)}</strong><div class="dov">{esc(f.dovada)}</div>
          <div class="rem">→ {esc(f.remediere)}</div><div class="nis">{esc(f.nis2)}</div></td></tr>''' for f in findings)
    heal=''.join(f'<li>{esc(h)}</li>' for h in healthy)
    net_kpis=''
    if net_stats:
        net_kpis=f'''<h2>Rețea (scan intern)</h2><div class="kpis">
 <div class="kpi"><b>{net_stats['hosts']}</b><span>gazde active ({net_stats['named']} cu nume)</span></div>
 <div class="kpi"><b>{net_stats['telnet']}</b><span>cu telnet în clar</span></div>
 <div class="kpi"><b>{net_stats['smb']}</b><span>SMB fără semnătură</span></div>
 <div class="kpi"><b>{net_stats['rdp']}</b><span>RDP expus</span></div>
 <div class="kpi"><b>{net_stats['certs']}</b><span>certificate expirate</span></div>
 <div class="kpi"><b>{net_stats['db']}</b><span>port DB pe rețea</span></div>
</div>'''
    kpi_eol_sub=f"OS scos din suport ({stats['eol']}/{stats['base']} cunoscute" + (f", {stats['unknown']} neidentificate" if stats.get('unknown') else "") + ")"
    doc=f'''<!doctype html><html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Radiografie de securitate, postură Active Directory</title>
<style>
 :root{{--ink:#141414;--muted:#4A4A46;--bg:#FAFAF7;--rule:#D7D4CC;--accent:#1B3A5B}}
 *{{box-sizing:border-box}} body{{font:16px/1.6 system-ui,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:32px}}
 .wrap{{max-width:820px;margin:0 auto}}
 h1{{font-size:1.7rem;margin:0 0 4px}} .sub{{color:var(--muted);margin-bottom:24px}}
 .score{{display:flex;gap:20px;align-items:center;border:1px solid var(--rule);border-radius:12px;padding:20px;background:#fff;margin-bottom:28px}}
 .grada{{font-size:3.2rem;font-weight:800;line-height:1;width:88px;height:88px;display:flex;align-items:center;justify-content:center;border-radius:12px;color:#fff}}
 .kpis{{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:28px}}
 .kpi{{border:1px solid var(--rule);border-radius:10px;padding:12px 16px;background:#fff;min-width:150px}}
 .kpi b{{font-size:1.5rem;display:block}} .kpi span{{color:var(--muted);font-size:.85rem}}
 h2{{font-size:1.15rem;border-top:1px solid var(--rule);padding-top:20px;margin-top:28px}}
 table{{width:100%;border-collapse:collapse}} td{{border-bottom:1px solid var(--rule);padding:12px 6px;vertical-align:top}}
 .pill{{color:#fff;font-size:.72rem;font-weight:700;padding:3px 8px;border-radius:20px;white-space:nowrap}}
 .dov{{color:var(--muted);font-size:.92rem;margin-top:4px}} .rem{{font-size:.92rem;margin-top:6px}}
 .nis{{color:var(--muted);font-size:.78rem;margin-top:4px;font-style:italic}}
 .heal{{background:#fff;border:1px solid var(--rule);border-left:4px solid #3E7C5A;border-radius:8px;padding:8px 20px}}
 .foot{{color:var(--muted);font-size:.82rem;margin-top:32px;border-top:1px solid var(--rule);padding-top:16px}}
</style></head><body><div class="wrap">
<h1>Radiografie de securitate, Active Directory și rețea</h1>
<div class="sub">Auto-evaluare pe date proprii · instantaneu {esc(snapshot_str)} · generat la tine, datele nu pleacă nicăieri</div>
<div class="score"><div class="grada" style="background:{['#3E7C5A','#3E7C5A','#C08A2D','#C0562E','#A6372E'][ 'ABCDE'.index(grada) ]}">{grada}</div>
 <div><strong>Scor de risc: {score}/100</strong> (mai mic e mai bine)<br>
 <span class="sub">{len(findings)} constatări · {len(healthy)} semnale sănătoase</span></div></div>
<div class="kpis">
 <div class="kpi"><b>{stats['n_comp']:,}</b><span>obiecte-calculator</span></div>
 <div class="kpi"><b>{stats['pct_eol']}%</b><span>{kpi_eol_sub}</span></div>
 <div class="kpi"><b>{stats['xp']}</b><span>pe Windows XP</span></div>
 <div class="kpi"><b>{stats['laps_cov']}%</b><span>acoperire LAPS</span></div>
 <div class="kpi"><b>{stats['dc_eol']}/{stats['dcs']}</b><span>controlere de domeniu EOL</span></div>
 <div class="kpi"><b>{stats['da']}+{stats['ea']}</b><span>domain + enterprise admins</span></div>
</div>
{net_kpis}
<h2>Constatări, prioritizate</h2>
<table>{rows}</table>
<h2>Ce e sănătos (calibrare, ca să echilibreze povestea)</h2>
<ul class="heal">{heal}</ul>
<div class="foot"><strong>Metodă și limite.</strong> Agregări directe din colectarea proprie (SharpHound pentru Active Directory, scan nmap pentru rețea). Semnalele brute sunt calibrate (de exemplu, permisiunile implicite standard din orice domeniu Windows NU sunt căi de atac). Un semnal e un indiciu, nu o dovadă de exploatabilitate. Datele nu părăsesc mașina. Radiografie de triaj, nu audit formal.</div>
</div></body></html>'''
    with open(out,'w',encoding='utf-8') as fp: fp.write(doc)

# ---------- Main ----------
def _parse_snapshot(snap):
    try:
        return _ep(snap)
    except ValueError:
        print(f"Data „{snap}” nu e în formatul YYYY-MM-DD.", file=sys.stderr)
        sys.exit(2)

def _flag_value(flag):
    # Ia valoarea de după o opțiune (ex. data de după --data-snapshot), cu grijă dacă opțiunea e ultima și nu are nimic după ea.
    i=sys.argv.index(flag)
    if i+1>=len(sys.argv):
        print(f"„{flag}” cere o valoare după el.", file=sys.stderr); sys.exit(2)
    return sys.argv[i+1]

if __name__=='__main__':
    if len(sys.argv)<3:
        print("Usage: python3 radiografie.py <dir_date> <output.html> [--data-snapshot YYYY-MM-DD] [--net <dir>]")
        sys.exit(2)
    d=sys.argv[1]; out=sys.argv[2]
    # Dacă nu spui altfel, socotim că datele au fost strânse chiar azi (ca să știm corect ce sistem
    # a ieșit din suport și ce nu). Pune --data-snapshot dacă datele sunt dintr-o colectare mai veche.
    snap=datetime.date.today().isoformat()
    if '--data-snapshot' in sys.argv: snap=_flag_value('--data-snapshot')
    snapshot=_parse_snapshot(snap)
    C,U,G=load(d)
    if not C:
        print(f"Atenție: n-am găsit niciun fișier *_computers.json în „{d}”. Verifică folderul de date.", file=sys.stderr)
    findings,healthy,stats,score,grada=analyze(C,U,G,snapshot)
    # Rețeaua e opțională: fie îi dai folderul cu --net, fie căutăm un subfolder „network" lângă date.
    netdir=_flag_value('--net') if '--net' in sys.argv else os.path.join(d,'network')
    net_stats=None
    if os.path.isdir(netdir):
        H=load_nmap(netdir, snapshot)
        net_findings, net_stats = analyze_network(H)
        findings=findings+net_findings
    findings.sort(key=lambda f: SEV_ORD[f.sev])
    score=posture_score(findings); grada=grade_of(score)
    render(findings,healthy,stats,score,grada,snap,out,net_stats)
    extra=f" · {net_stats['hosts']} gazde rețea" if net_stats else ""
    print(f"OK · {stats['n_comp']} computere, {stats['n_user']} useri{extra} · scor de risc {score}/100 ({grada}) · {len(findings)} constatări → {out}")
    print("Self-check:", {k:stats[k] for k in ('pct_eol','unknown','xp','laps_cov','dcs','dc_eol','da','ea','pnr','stale_u','ucd_u','ucd_c','spn','sidh')})
