# Colectarea datelor

> **Autorizare, întâi.** Rulează colectarea DOAR pe infrastructura instituției tale, cu mandat scris. Colectarea de directoare și scanarea de rețea pe sisteme care nu-ți aparțin sunt ilegale. Acest instrument e pentru **auto-evaluare**.

Colectezi cu două instrumente open-source consacrate. Nu le reinventăm; programul citește ce scot ele.

> **Programul nu-ți cere nicio parolă și nu are `.env`.** Te conectezi cu parola doar aici, la colectare, cu contul tău de domeniu obișnuit (prin SharpHound). Parola aceea rămâne între tine și SharpHound. Programul primește doar fișierele rezultate.

## 1. Active Directory — SharpHound

[SharpHound](https://github.com/SpecterOps/BloodHound) e colectorul standard de postură AD.

- Rulează cu un cont de domeniu obișnuit (nu e nevoie de admin), de pe o mașină înrolată în domeniu.
- Colectează structura: computere, utilizatori, grupuri, GPO, delegări, LAPS, apartenențe.
- **Nu colectează parole și nici conținut de fișier.** Colectarea conține metadate de director, atât.

Exemplu (PowerShell/CLI SharpHound):
```
SharpHound.exe -c All --outputdirectory C:\radiografie\date
```
Rezultă mai multe fișiere `*_computers.json`, `*_users.json`, `*_groups.json` etc. Pune-le într-un folder, ex. `date/`.

## 2. Rețea — nmap

[nmap](https://nmap.org) descoperă ce ascultă pe rețeaua internă (servicii, versiuni, certificate).

- Scanează **doar subrețelele tale interne**, cele pe care le administrezi.
- Scanare de servicii + versiuni + câteva scripturi utile (semnătură SMB, certificate TLS):

```
nmap -sV -p- --script "ssl-cert,smb2-security-mode" -oN date/network/scan-10.0.0.txt 10.0.0.0/24
```
Repetă per subrețea; pune fișierele într-un subfolder `network/` sub folderul de date. Programul le adună și scoate dublurile după adresă (IP).

> Notă: o scanare de servicii arată ce e **expus**, nu ce e **spart**. E o radiografie, nu un test de penetrare.

## 3. Structura folderului

```
date/
  20260713_computers.json      <- SharpHound
  20260713_users.json
  20260713_groups.json
  ...
  network/                     <- scanuri nmap
    scan-10.0.0.txt
    scan-10.0.1.txt
```

Apoi:
```
python3 radiografie.py date/ raport.html --data-snapshot 2026-07-13
```

## 4. După ce ai raportul

- Ține `date/` și `raport.html` **local și criptate**. Sunt harta propriilor tale slăbiciuni.
- Șterge colectarea când nu-ți mai trebuie. Nu o trimite necriptat, nu o urca nicăieri.
