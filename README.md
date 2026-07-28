# Radiografia

**Îți pui instituția la radiografie. Pe rețeaua ta, cu mâna ta. Iese o foaie pe limba omului: ce e putred și ce repari întâi.**

Nu-ți trebuie un expert de securitate ca s-o citești. Îți trebuie doar voința să repari ce e roșu.

## Ce e și de ce

Instituțiile nu cad din filme cu hackeri. Cad din lucruri mărunte, lăsate baltă: sisteme de operare moarte de ani, aceeași parolă de administrator peste tot, servicii vechi uitate deschise pe rețea. Se vede în fiecare spargere documentată public în 2026.

Întrebarea nu e dacă ai și tu din astea. E câte, și care te doare primul.

Aici intervine Radiografia. Îți arată exact lucrurile astea, la tine, adunate și așezate în ordinea gravității, fiecare cu ce ai de făcut și cu obligația NIS2 pe care o atinge.

Nu e un audit formal. Nu e un pentest. E un triaj: îți spune unde sângerezi, ca să știi ce prinzi primul.

## Siguranță (citește întâi)

Patru lucruri, înainte de orice.

- **Rulează la tine. Datele nu pleacă nicăieri.** Nu urmărește ce faci, nu trimite nimic în afară, nu raportează nimic înapoi la nimeni. Raportul e al tău și rămâne al tău.
- **Zero parole. Fără `.env`.** Programul nu se conectează nicăieri și nu-ți cere niciun secret. Citește fișierele pe care le-ai strâns și scrie un raport. Parola cu care colectezi (contul tău de domeniu, prin SharpHound) rămâne între tine și SharpHound, nu ajunge niciodată la program.
- **Pe rețeaua ta, cu autorizarea ta.** Nu-l pune pe sisteme care nu-ți aparțin sau pentru care nu ai mandat scris. Punct.
- **Raportul e o hartă a slăbiciunilor tale.** Adică fix ce n-ai vrea să ajungă în mâini străine. Ține-l criptat, nu-l trimite pe e-mail în clar.
- **E cod deschis, care se citește.** Nu rula niciodată un instrument închis pe Active Directory-ul tău. Pe ăsta îl citești linie cu linie, sau îl dai cuiva să ți-l citească.

## Ce-ți trebuie

Puțin.

- **Python 3.9+.** Programul nu are nevoie de alte programe instalate.
- **Datele tale**, colectate cu două instrumente open-source pe care le folosește toată branșa:
  - **SharpHound** (din BloodHound) pentru Active Directory, iese JSON.
  - **nmap** pentru rețea, iese text.
  - Pașii exacți, cu formularea de autorizare cu tot, în [`docs/COLECTARE.md`](docs/COLECTARE.md).

## Cum rulezi (3 pași)

```bash
# 1. Colectezi (vezi docs/COLECTARE.md) — pui JSON-urile SharpHound într-un folder,
#    iar scanurile nmap într-un subfolder network/ .

# 2. Pornești programul pe folderul tău:
python3 radiografie.py /cale/catre/date raport.html --data-snapshot 2026-07-13

# 3. Deschizi raport.html în browser.
```

`--data-snapshot` = data colectării (ca să clasifice corect în timp ce e scos din suport și ce nu). `--net <dir>` dacă scanurile de rețea sunt în alt folder.

## Cum citești raportul

Cinci lucruri, de sus în jos:

- **Scorul și nota** (A…E): o măsură de postură, pe care o urmărești în timp, de la o rulare la alta.
- **KPI-uri**: cifrele mari. Cât la sută din sisteme sunt scoase din suport, cât acoperă LAPS, câte controlere de domeniu sunt moarte, ce ai expus pe rețea.
- **Constatări, în ordinea gravității**: roșu (CRITIC) sus. Fiecare îți spune ce e, dovada (cifra), cum repari și ce obligație NIS2 bifezi.
- **Ce e sănătos**: și ce ai făcut bine. Ca să vezi tabloul întreg, nu doar sperietura.
- **Metodă și limite**: un semnal nu e o dovadă de exploatabilitate. E triaj, nu audit. Ține minte.

## Ce NU e

Ca să fim înțeleși de la început:

- Nu exploatează nimic, nu trimite payload-uri.
- Nu scanează nimic din afara a ceea ce colectezi tu.
- Nu trimite date nicăieri.
- Nu îți ține locul unui audit formal sau al unui pentest. Le pregătește terenul.

## Aliniere NIS2

Fiecare constatare e legată de o obligație din Directiva NIS2, așa cum e transpusă în România. Așa că, pe lângă reparat, îți vezi și îți documentezi postura pe ce cere legea: managementul riscului, inventarul, ținerea sistemelor la zi.

## Licență

MIT. Adică: îl folosești, îl studiezi, îl modifici, îl dai mai departe, cum vrei. E un instrument civic, făcut ca să fie luat și folosit, nu păzit. Rulează-l, citește-l, croiește-l pe instituția ta.

## Stadiu

Program funcțional, verificat pe date reale. A trecut printr-o verificare a codului și printr-un tur de „spargere" de probă: am confirmat că nu trimite nimic în afară, că raportul nu poate fi păcălit cu cod strecurat și că nu crapă la date ciudate (nume cu diacritice, informații lipsă, date de certificat imposibile). Adună din două părți: Active Directory (SharpHound) și rețea (nmap). 23 de teste, pornite cu `python3 -m unittest tests.test_radiografie`.
