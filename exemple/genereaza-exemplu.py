#!/usr/bin/env python3
"""
Face date INVENTATE (o instituție fictivă, „EXEMPLU") pentru demonstrația Radiografiei.
Zero date reale. Iese la fel de fiecare dată. E o instituție cu de toate: câteva probleme
adevărate și câteva lucruri făcute bine, ca demonstrația să arate și roșu, și galben, și verde.
Apoi rulează:
  python3 ../radiografie.py date-exemplu raport-exemplu.html --data-snapshot 2026-07-13
"""
import json, os

DOM="EXEMPLU.LOCAL"; SID="S-1-5-21-1111111111-2222222222-3333333333"
OUT="date-exemplu"; os.makedirs(os.path.join(OUT,"network"), exist_ok=True)
RECENT=1783000000  # ~iul 2026 (activ)
OLD=1690000000     # ~iul 2023 (stale)

def comp(i, osname, enabled=True, laps=False, dc=False, stale=False):
    dn = (f"CN=DC{i:02d},OU=DOMAIN CONTROLLERS,DC=EXEMPLU,DC=LOCAL" if dc
          else f"CN=PC{i:04d},OU=Statii,DC=EXEMPLU,DC=LOCAL")
    return {"ObjectIdentifier": f"{SID}-{5000+i}", "HasSIDHistory": [], "Properties": {
        "name": f"{'DC' if dc else 'PC'}{i:02d}.{DOM}", "samaccountname": f"{'DC' if dc else 'PC'}{i:02d}$",
        "domain": DOM, "distinguishedname": dn, "enabled": enabled, "operatingsystem": osname,
        "haslaps": laps, "unconstraineddelegation": dc, "sidhistory": [],
        "serviceprincipalnames": [], "lastlogontimestamp": OLD if stale else RECENT}}

def user(i, enabled=True, pnr=False, sensitive=False, spn=False, asrep=False, stale=False):
    return {"ObjectIdentifier": f"{SID}-{10000+i}", "HasSIDHistory": [], "SPNTargets": [], "Properties": {
        "name": f"user{i:03d}@{DOM}", "samaccountname": f"user{i:03d}", "domain": DOM,
        "enabled": enabled, "passwordnotreqd": pnr, "sensitive": sensitive, "hasspn": spn,
        "dontreqpreauth": asrep, "unconstraineddelegation": False, "sidhistory": [],
        "serviceprincipalnames": (["HTTP/app"] if spn else []),
        "lastlogontimestamp": OLD if stale else RECENT}}

def wr(kind, data):
    with open(os.path.join(OUT, f"EXEMPLU_{kind}.json"),"w",encoding="utf-8") as fp:
        json.dump({"data": data, "meta": {"methods":0,"type":kind,"count":len(data),"version":6}}, fp)

# --- Computere: ~133 (EOL ~27%, LAPS ~40%, DC-uri sănătoase) ---
C=[]; i=1
def add(n, osname, stale=False):
    global i
    for _ in range(n):
        C.append(comp(i, osname, laps=(i%5<2), stale=stale)); i+=1   # ~40% LAPS
add(30,"Windows 10 Pro")                                    # EOL (14.10.2025)
add(65,"Windows 11 Pro")                                    # suportat
add(5, "Windows 7 Professional Service Pack 1", stale=True) # EOL
add(1, "Windows XP Professional Service Pack 3", stale=True)# EOL
add(30,"Windows Server 2019 Standard")                      # suportat
C.append(comp(i,"Windows Server 2019 Standard", dc=True)); i+=1     # controler de domeniu sănătos
C.append(comp(i,"Windows Server 2019 Standard", dc=True)); i+=1     # controler de domeniu sănătos
wr("computers", C)

# --- Utilizatori: 80 (6 admini marcați sensibil, 2 parole goale, identitate curată) ---
U=[]; da=[]
for j in range(1,81):
    is_admin = j<=6
    u=user(j, pnr=(j in (11,12)), sensitive=is_admin, spn=(j==20), asrep=False, stale=False)
    U.append(u)
    if is_admin: da.append(u["ObjectIdentifier"])
wr("users", U)

# --- Grupuri (6 domain admins, 2 enterprise admins) ---
wr("groups", [
 {"ObjectIdentifier":f"{SID}-512","Properties":{"name":f"DOMAIN ADMINS@{DOM}","samaccountname":"DOMAIN ADMINS"},
  "Members":[{"ObjectIdentifier":m,"ObjectType":"User"} for m in da]},
 {"ObjectIdentifier":f"{SID}-519","Properties":{"name":f"ENTERPRISE ADMINS@{DOM}","samaccountname":"ENTERPRISE ADMINS"},
  "Members":[{"ObjectIdentifier":da[0],"ObjectType":"User"},{"ObjectIdentifier":da[1],"ObjectType":"User"}]},
])
wr("domains", [{"Properties":{"name":DOM},"ObjectIdentifier":SID}])

# --- Rețea (nmap sintetic, 15 gazde): 3 SMB fără semnătură, 4 RDP, 3 certificate expirate ---
lines=[]
def host(ip,name,ports,ssl_exp=None,smb_nosign=False):
    lines.append(f"Nmap scan report for {name} ({ip})"); lines.append("Host is up (0.001s latency).")
    lines.append("PORT     STATE SERVICE")
    for p,s in ports:
        lines.append(f"{p}/tcp open  {s}")
        if p==22: lines.append("|_  SSH-2.0-OpenSSH_9.7")
        if p==443 and ssl_exp: lines.append(f"| ssl-cert: Not valid after:  {ssl_exp}")
        if p==445 and smb_nosign:
            lines.append("| smb2-security-mode:"); lines.append("|_  Message signing enabled but not required")
    lines.append("")
for k in range(1,16):
    ports=[(22,"ssh"),(443,"https")]
    if k<=3: ports.append((445,"microsoft-ds"))     # 3 SMB fără semnătură
    if k<=4: ports.append((3389,"ms-wbt-server"))   # 4 RDP
    host(f"10.10.0.{k}", f"srv{k:02d}.{DOM.lower()}", ports,
         ssl_exp=("2024-02-01" if k<=3 else "2027-06-01"), smb_nosign=(k<=3))  # 3 certificate expirate
with open(os.path.join(OUT,"network","scan-10.10.0.txt"),"w",encoding="utf-8") as fp:
    fp.write("\n".join(lines))
print(f"Date sintetice: {len(C)} computere, {len(U)} utilizatori, 15 gazde rețea.")
