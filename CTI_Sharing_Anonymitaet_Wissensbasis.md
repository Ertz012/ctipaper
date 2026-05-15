# Anonymes CTI-Sharing in kritischen Infrastrukturen — Wissensbasis

> Erstellt auf Basis einer Recherche- und Analysesitzung (Mai 2026).  
> Grundlage: Paper „Spectrum: High-bandwidth Anonymous Broadcast" (Newman, Servan-Schreiber, Devadas — MIT CSAIL, NSDI 2022) sowie Recherchen zu CTI-Sharing-Praxis in Europa.

---

## Inhaltsverzeichnis

1. [Motivation und Problemstellung](#1-motivation-und-problemstellung)
2. [Grundlagen anonymer Broadcast-Systeme](#2-grundlagen-anonymer-broadcast-systeme)
3. [Systemvergleich: Spectrum, Riposte, Express](#3-systemvergleich-spectrum-riposte-express)
4. [Anpassungen und Erweiterungen für den CTI-Anwendungsfall](#4-anpassungen-und-erweiterungen-für-den-cti-anwendungsfall)
5. [Bestehende CTI-Sharing-Systeme in der Praxis](#5-bestehende-cti-sharing-systeme-in-der-praxis)
6. [Datenformate im CTI-Sharing](#6-datenformate-im-cti-sharing)
7. [Bandbreitenbedarf und Frequenz](#7-bandbreitenbedarf-und-frequenz)
8. [Das Zählproblem: Angriffszahlen vs. geteilte Incidents](#8-das-zählproblem-angriffszahlen-vs-geteilte-incidents)
9. [Anonymitätsmenge und Teilnehmerstruktur](#9-anonymitätsmenge-und-teilnehmerstruktur)
10. [Architekturempfehlungen](#10-architekturempfehlungen)
11. [Quellen](#11-quellen)

---

## 1. Motivation und Problemstellung

### 1.1 Der Whistleblower-Kontext

Systeme für anonyme Kommunikation sind ursprünglich für Whistleblower entwickelt worden, die Missstände aufdecken wollen, ohne sich selbst zu gefährden. Prominente Fälle — Chelsea Manning (SFTP-Metadaten als Beweismittel), Natalie Edwards (Metadaten einer verschlüsselten Messaging-App als Beweismittel), Edward Snowden — zeigen, dass reine Inhaltsverschlüsselung nicht ausreicht. Angreifer können allein aus Metadaten (Quelle, Ziel, Zeitpunkt, Volumen) auf Inhalte schließen.

### 1.2 Übertragung auf CTI-Sharing

Im Kontext des Teilens von Cyber Threat Intelligence (CTI) unter Unternehmen — insbesondere in kritischen Infrastrukturen wie der Energieversorgung — entsteht dasselbe Metadaten-Problem:

- **Competitive Intelligence**: Wenn bekannt wird, *dass* ein Energieversorger eine bestimmte Schwachstelle gemeldet hat, verrät das, welche Systeme er einsetzt.
- **Reputationsrisiko**: Das Bekanntwerden eines Breaches schadet dem Kundenvertrauen.
- **Antitrust-Bedenken**: Koordinierter Datenaustausch unter Wettbewerbern kann rechtliche Risiken erzeugen.

NIST SP 800-150 benennt Anonymität explizit als „recommended mitigation strategy" und hält fest: *„Unattributed information sharing allows an organization to share more information because there is less perceived risk."*

Das Ziel ist also ein System, das CTI-Daten teilt, ohne zu verraten, *wer* die Daten eingebracht hat.

---

## 2. Grundlagen anonymer Broadcast-Systeme

### 2.1 DC-Nets (Dining Cryptographer Networks)

Das Fundament aller besprochenen Systeme ist das DC-Net-Konzept von David Chaum (1988). Die Grundidee im Zwei-Server-Fall:

- Jeder Client *i* wählt einen zufälligen Bitstring *r_i*
- Broadcaster schickt `r_i ⊕ m_i` an Server A und `r_i` an Server B
- Subscriber schickt `r_i ⊕ 0 = r_i` an Server A und `r_i` an Server B
- Server aggregieren lokal: `aggA = XOR aller (r_i ⊕ m_i)`, `aggB = XOR aller r_i`
- XOR der Aggregate ergibt `m_Broadcaster`, da alle *r_i* sich wegkürzen

Kein einzelner Server kann den Absender identifizieren. Die Anonymitätsmenge umfasst alle N Clients.

**Kernproblem:** Jeder böswillige Client kann undetektiert eine Nicht-Null-Nachricht schicken und damit den gesamten Broadcast sabotieren.

### 2.2 Distributed Point Functions (DPFs)

Für den Fall mehrerer gleichzeitiger Broadcaster würde ein naives DC-Net eine L-fache Wiederholung erfordern (linear in der Broadcaster-Anzahl L). DPFs lösen das effizienter:

Eine Punktfunktion *P* gibt an Index *j* den Wert *m* zurück und überall sonst 0. Sie lässt sich in kompakte DPF-Schlüsselpaare aufteilen, deren Größe nur O(log L + |m|) beträgt (für zwei Server) statt O(L · |m|). Die Server können ihre Shares lokal aggregieren, ohne zu wissen, an welchen Kanal *j* der Broadcaster geschrieben hat.

### 2.3 Anonymitätsgarantien

Alle besprochenen Systeme garantieren Anonymität unter der Annahme, dass **mindestens ein Server ehrlich** ist. Formal (Claim 1 in Spectrum):

> *„No PPT adversary observing the entire network and corrupting any strict subset of servers and an arbitrary subset of clients can distinguish between an honest broadcaster and an honest subscriber."*

Die **Anonymitätsmenge ist N** (alle Clients), nicht nur L (Broadcaster) — vorausgesetzt, alle Clients bleiben online und senden Cover Traffic. Die Server wissen zwar, dass es L Kanäle gibt, können aber nicht zuordnen, welche der N Clients die Broadcaster sind.

**Kritische Einschränkung:** Intersection Attacks über mehrere Runden hinweg können die Anonymitätsmenge faktisch reduzieren, wenn Clients nicht konstant online bleiben.

---

## 3. Systemvergleich: Spectrum, Riposte, Express

### 3.1 Überblick

| Merkmal | Spectrum | Riposte | Express |
|---|---|---|---|
| Server-Arbeit pro Request | O(L · \|m\|) | O(N · \|m\|) | O(L · \|m\|) |
| Request-Größe | O(log L + \|m\|) | O(\|m\| + √N) | O(\|m\| + log L) |
| Malicious-Server-Sicherheit | ✓ (BlameGame) | ✗ | ✗ |
| Störungsverhinderung | proaktiv (blind) | proaktiv (Audit-Server) | proaktiv |
| Schuldzuweisung bei Fehler | leichtgewichtig | keine | keine |
| Mindestanzahl Server | 2 | 3 | genau 2 |
| Ehrlichkeitsannahme | mind. 1 ehrlich | 1 ehrlicher Audit-Server | mind. 1 ehrlich |
| Große Nachrichten (GB) | ✓ | ✗ (< 5 kB) | eingeschränkt |
| Primärer Anwendungsfall | Broadcast (wenige Sender) | Twitter-style (alle senden) | Mailbox/Dropbox |
| Kosten für 1 GB, 10k Nutzer | $6,84 | $218.000 | $30,22 |

*Kosten basieren auf Amazon EC2 c5.4xlarge ($0,68/h), gemessen September 2021. Quelle: Newman et al. (2022), Table 3.*

### 3.2 Spectrum im Detail

**Architektur:** 2+ nicht-kolludierende Broadcast-Server, N Clients (L Broadcaster + N-L Subscriber). Alle Clients senden in jeder Runde — Broadcaster senden Shares ihrer Nachricht, Subscriber senden Shares von 0 (Cover Traffic).

**Drei Phasen:**
1. **Setup**: Broadcaster registrieren anonym einen öffentlichen Schlüssel g^α via Bootstrapping-System (externes System, nicht in Spectrum implementiert).
2. **Hauptprotokoll**: DPF-basiertes Secret Sharing + Blind Access Control; Server aggregieren valide Shares.
3. **BlameGame** (bei Bedarf): Schuldzuweisung bei fehlgeschlagenem Audit.

**Blind Access Control (Carter-Wegman MAC):**

Jeder Broadcaster kennt einen geheimen Schlüssel α. Der MAC ist definiert als `MAC_α(m) = α · m`. Die Verifikation läuft auf den secret-geteilten Werten:
- Server A: `g^βA ← (g^α)^mA / g^tA`
- Server B: `g^βB ← (g^α)^mB / g^tB`
- Check: `g^βA · g^βB = 1` (d.h. βA + βB = 0)

Da `MAC_α(0) = 0`, können Subscriber einen validen Tag (t=0) ohne Kenntnis von α erzeugen — aber keine Nicht-Null-Nachricht fälschen (außer sie lösen das diskrete Logarithmusproblem). Server erhalten nur den öffentlichen Schlüssel g^α, nicht α selbst — Client-Server-Kollusion wird dadurch verhindert.

**BlameGame:**

Motivation: Ein böswilliger Server kann den Request eines Clients manipulieren, sodass der Audit fehlschlägt. Da in einem Broadcast-Setting wenige Clients senden, kann das Ausschließen eines Clients zur Deanonymisierung führen (Audit-Angriff). Riposte und Express sind dafür anfällig.

Ablauf von BlameGame:
1. Client verschlüsselt seinen Request-Share unter dem öffentlichen Schlüssel jedes Servers und broadcastet alle Chiffretexte über ein byzantinisches Broadcast-Protokoll.
2. Bei Audit-Fehler müssen Server ihren Share aufdecken und kryptographisch beweisen, dass sie korrekt entschlüsselt haben.
3. Scheitert ein Server: Server ist schuldig, abort. Kann jeder Server beweisen und Audit schlägt trotzdem fehl: Client ist schuldig, Request wird verworfen.

Overhead: ~140 Bytes pro Client für Backup-Request, Audit ~200 Bytes — läuft nur bei Fehlerfall.

**Performance-Benchmarks (AWS EC2, WAN, September 2021):**

| Setting | Spectrum | Vergleich |
|---|---|---|
| 1 Kanal, 100 kB–5 MB Nachrichten | Basis | 4–7× schneller als Express |
| 10 kB Nachrichten, bis ~100 Kanäle | Basis | übertrifft alle anderen Systeme |
| 10.000 Nutzer, 1 MB | 1 Runde | 16–12.500× schneller als Riposte |
| 1 GB, 10.000 Nutzer | ~13h 20m | zu ~$6,84 |
| Skalierung (10 VMs/Server) | 10× Speedup | linear skalierbar |

### 3.3 Riposte im Detail

Riposte (Corrigan-Gibbs, Boneh, Mazières, 2015) war der Vorgänger und hat DPFs für anonymes Broadcasting eingeführt. **Hauptunterschiede zu Spectrum:**

- Reserviert Kanäle für **jeden der N Clients**, unabhängig davon, ob er broadcaster ist → Server-Arbeit ist O(N · |m|), nicht O(L · |m|). Bei vielen Subscribern und wenigen Broadcastern massiver Nachteil.
- Erfordert einen **dritten, vertrauenswürdigen Audit-Server** für die Zugangskontrolle.
- **Kein Schutz gegen den Audit-Angriff**: Ein böswilliger Server kann Clients undetektiert ausschließen.
- Primäre Annahme: **Alle Nutzer broadcasen** (Twitter-Modell). Bei vielen Subscribern wird Riposte quadratisch langsamer.
- Quellcode versagt bereits ab **5 kB Nachrichtengröße**.

Riposte ist geeignet für: Viele gleichzeitige Broadcaster, kleine Nachrichten, kein starkes Malicious-Server-Modell.

### 3.4 Express im Detail

Express (Eskandarian, Corrigan-Gibbs, Zaharia, Boneh, USENIX Security 2021) ist für anonyme Mailbox-Kommunikation konzipiert, nicht für Broadcast. **Hauptunterschiede zu Spectrum:**

- Kein natives Broadcast-Modell, kann aber adaptiert werden.
- **Kein Schutz gegen den Audit-Angriff**: Ein böswilliger Server kann über die DPF-Verifikation einen Client ausschließen und ihn damit mit Wahrscheinlichkeit ≥ 1/((1−ε)^N) pro Runde deanonymisieren — undetektiert.
- Läuft **ausschließlich mit genau zwei Servern**.
- Request-Overhead: ~5 kB (vs. ~70 Bytes bei Spectrum); Audit-Größe: ~2 kB (vs. 16 Bytes bei Spectrum).

Express ist geeignet für: Asymmetrische Lese-/Schreib-Szenarien, wenige Server, kein starkes Malicious-Server-Modell.

---

## 4. Anpassungen und Erweiterungen für den CTI-Anwendungsfall

### 4.1 Das Bootstrapping-Problem

Spectrum setzt für die Setup-Phase ein externes anonymes System voraus. Das Paper nennt Riposte als mögliche Option. Im CTI-Kontext bedeutet das: Wenn ein Unternehmen einen neuen CTI-Datensatz teilen möchte, muss es zunächst anonym einen Authentifizierungsschlüssel registrieren. Da Schlüssel klein sind (~64 Bytes), ist auch ein langsameres System für diesen Schritt akzeptabel.

**Spectrum implementiert kein eigenes Bootstrapping** — das ist eine externe Abhängigkeit, die im System-Design explizit adressiert werden muss.

### 4.2 Das Any-Client-Can-Send-Problem

Spectrum ist für das Szenario optimiert: **Wenige bekannte Broadcaster, viele Subscriber**. Im CTI-Kontext soll aber prinzipiell jeder Client senden dürfen, auch wenn zu jedem Zeitpunkt nur wenige aktiv senden.

Wenn naiv alle N Clients als Broadcaster vorregistriert werden → L = N → Spectrum verliert seinen Effizienz-Vorteil, Server-Arbeit wird wieder O(N · |m|), identisch zu Riposte.

**Lösungsansätze:**

**Option 1 — Dynamische Slot-Reservierung (empfohlen):**  
Nur Clients, die in der aktuellen Epoche tatsächlich senden wollen, registrieren sich anonym für einen Slot. Registrierung via Bootstrapping-System (klein, günstig). L bleibt klein, auch wenn N groß ist. Vorraussetzung: Runden/Epochen-Modell mit definierter Registrierungsphase.

**Option 2 — Anonymous Credentials:**  
Clients erhalten blind signierte One-Time-Tokens, die zur Registrierung berechtigen, aber keine Identität verraten. Ermöglicht saubere Entkopplung von Berechtigung und Identität. Höherer kryptographischer Aufwand.

**Option 3 — Epoch-basiertes Modell (pragmatischster Ansatz):**  
Feste Epochen (z.B. stündlich oder täglich). Zu Beginn jeder Epoche können sendewillige Clients anonym Slots reservieren. L wird nach erwarteter maximaler gleichzeitiger Senderate dimensioniert (nicht nach N). Wer in einer Epoche nicht sendet, schickt Cover Traffic.

**Option 4 — Zweiphasiges Protokoll:**  
Phase 1: Einfaches DC-Net für Einzelbits ("will senden" = 1, sonst 0). Ergibt k als aktuelle Broadcaster-Anzahl. Phase 2: Spectrum mit L = k. Problem: Phase 1 selbst muss anonym sein (ist lösbar, erzeugt aber Overhead).

### 4.3 BlameGame-Anwendung auf Riposte und Express

Ein wichtiges Ergebnis des Spectrum-Papers: **BlameGame ist als Black-Box-Protokoll auf andere Systeme anwendbar.** Insbesondere Riposte und Express könnten durch BlameGame gegen den Audit-Angriff abgesichert werden. Der Overhead ist identisch zu Spectrum (hauptsächlich ~140 Bytes/Client für den Backup-Request, unabhängig von der Nachrichtengröße). Das ist relevant, wenn aus anderen Gründen Riposte oder Express bevorzugt wird.

### 4.4 Skalierung auf viele Server

Spectrum mit genau zwei Servern ist optimal. Mehr als zwei Server sind möglich, erfordern aber einen **seed-homomorphen Pseudorandom-Generator** (statt AES-basiertem PRG), was ~20.000× langsamer ist. Mit 10 kB Nachrichten war Spectrum mit n > 2 Servern im Benchmark ~5× langsamer als mit 2 Servern. **Kein zusätzlicher Slowdown** zwischen 2 und 10 Servern — d.h. die Kosten entstehen einmal beim Wechsel zu n > 2, nicht progressiv.

### 4.5 Subscriber-Anonymität via PIR

Spectrum veröffentlicht Broadcasts auf einem öffentlichen Bulletin Board. Subscriber, die nicht verraten wollen, welchen Kanal sie lesen, können **Private Information Retrieval (PIR)** nutzen. Moderne PIR-Schemata auf DPF-Basis haben minimalen Bandwidth-Overhead für Queries (logarithmisch in der Kanalanzahl L). Der Server-seitige Verarbeitungsaufwand ist dabei immer linear in L — unvermeidbar.

---

## 5. Bestehende CTI-Sharing-Systeme in der Praxis

### 5.1 EE-ISAC (European Energy — Information Sharing & Analysis Centre)

- **Status:** Aktiv, gegründet 2015; feierte 2025 10-jähriges Jubiläum
- **Mitglieder:** Wachsend; u.a. Eneco, ENEFIT, Enexis, Gemini Wind Park (neu Oktober 2025); genaue Gesamtzahl nicht öffentlich
- **Plattform:** Nextcloud seit Juli 2022, gehostet durch EU-finanziertes Projekt „Empowering EU-ISACs"
- **Aktivität:** 26. Plenartagung Oktober 2025, bi-monatliche SITAW-Updates (Situation Awareness)
- **Website:** https://www.ee-isac.eu/

Quelle: EE-ISAC Official Site; MDPI Energies 2022 (DOI: 10.3390/en15062170)

### 5.2 ENTSO-E (European Network of Transmission System Operators for Electricity)

- **Mitglieder:** 40 Übertragungsnetzbetreiber (TSOs) aus 36 Ländern (Stand Januar 2024; Ukraine als 40. Mitglied seit 01.01.2024)
- **Cybersecurity-Aktivitäten:** Network Code on Cybersecurity (NCCS) — definiert 5-stufige Klassifikation für Cyber-Incidents, harmonisierte Meldeverfahren zwischen TSOs
- **Kooperationspartner:** E.DSO, ENCS (European Network for Cyber Security)
- **Website:** https://www.entsoe.eu/

### 5.3 E-ISAC (Electricity — Information Sharing & Analysis Centre, Nordamerika)

Nicht europäisch, aber relevant als Referenz für konkrete Zahlen. **E-ISAC Annual Report 2023:**
- 968 Cyber-Shares gesamt:
  - 254 Phishing-Incidents
  - 240 Vulnerability Reports
  - 123 Ransomware
  - 110 DDoS
  - 241 Sonstiges
- 2.800+ physische Sicherheits-Incidents

Quelle: NERC/E-ISAC Annual Report 2023

### 5.4 MISP und OpenCTI in der Praxis

MISP (Malware Information Sharing Platform) ist die verbreitetste Open-Source-CTI-Plattform. **Befunde aus einer Studie zu Finnlands kritischen Infrastrukturen** (European Conference on Cyber Warfare and Security):
- MISP-Adoption noch in frühen Stadien
- Vieles läuft noch über manuelle Kanäle (E-Mail, Chat)
- Nationale MISP-Instanz in Gründung unter Führung des nationalen CERT
- Technisch: MISP-Connector konvertiert MISP-Events zu STIX 2.1 in OpenCTI

Das ist kein finnischer Sonderfall — es ist europäischer Standard. Die Technologie ist vorhanden, die Adoption ist gering.

Quelle: CTI Sharing Practices and MISP Adoption in Finland's Critical Infrastructure (ECCWS 2024), https://papers.academic-conferences.org/index.php/eccws/article/view/2352

### 5.5 Andere Sektoren und ihre ISACs

| Sektor | Organisation | Aktivität | Anonymitätsbedarf |
|---|---|---|---|
| **Finanzsektor** | FS-ISAC, FI-ISAC | Sehr aktiv; 100 Bio. USD Assets, 75 Länder | Sehr hoch (Konkurrenz) |
| **Telekommunikation** | ETIS | Bi-weekly Threat Intel Exchange Calls, TLP-geregelt | Mittel |
| **Gesundheitswesen** | EH-ISAC | Ransomware-fokussiert, strukturiertes Programm | Hoch (Patientendaten-Nähe) |
| **Transport** | — | Kaum formale Infrastruktur in Europa | Unbekannt |
| **Wasser/Abwasser** | — | Kein dediziertes europäisches ISAC; OT-Bedrohungen nehmen zu | — |

**isacs.eu** ist eine EU-finanzierte Meta-Plattform, die europäische Sector-ISACs verbindet (Energy, Finance, Telecom, Health) — strukturell der Ansatzpunkt für ein sektorübergreifendes System.

### 5.6 Regulatorische Rahmenbedingungen

**NIS2-Direktive (Artikel 23 — Meldepflichten):**
- **Early Warning:** Innerhalb 24 Stunden nach Erkennung eines signifikanten Incidents
- **Incident Notification:** Innerhalb 72 Stunden
- **Final Report:** Spätestens 1 Monat nach Notification
- Daten können anonymisiert zwischen Mitgliedstaaten ausgetauscht werden
- Nationale CSIRTs müssen Notifications sofort mit Sector Authorities teilen

**ENISA-Empfehlungen:** Keine strikten Frequenz-Mandate, aber Empfehlungen für bi-monatliche Situation-Awareness-Updates und Alignment mit NIS Cooperation Group.

**ENTSO-E NCCS:** Schreibt 5-stufige Klassifikationsmethodik für Cyber-Incidents vor; formalisierte Meldeverfahren zwischen TSOs.

**GDPR-Implikationen:** Hauptbarriere für B2B-Sharing in Deutschland und Finnland. Lösungsansätze: Anonymisierung (IP-Adressen entfernen), Pseudonymisierung mit Differential Privacy, ausschließlich aggregierte Statistiken.

---

## 6. Datenformate im CTI-Sharing

### 6.1 Dominante Standards

| Format | Beschreibung | Verbreitung | Typische Größe |
|---|---|---|---|
| **STIX 2.1** | JSON-basiert; Indicators, Malware, Campaigns, Attack Patterns, Relationships | De-facto-Standard in EU | 500 Bytes – 2 KB pro Objekt |
| **TAXII 2.1** | Transportprotokoll für STIX; Collection-basiert, konfigurierbares Polling | Standard-Transportschicht | — |
| **YARA-Regeln** | Textbasiert; als Extension in STIX-Indicators unterstützt | Verbreitet für Malware-Klassifikation | 10–100 KB pro Regelset |
| **OpenIOC** | Legacy XML (Mandiant); wird durch STIX verdrängt | Ältere Installationen | Variabel |
| **NetFlow** | Netzwerk-Flow-Informationen | Netzwerk-basierte Erkennung | Sehr variabel |

TAXII definiert bewusst keine Standardfrequenz — das wird client-seitig konfiguriert.

### 6.2 STIX Bundle-Größen

Offizielle Benchmarks nicht publiziert, aber Extrapolation:

| Inhalt | Geschätzte Größe |
|---|---|
| Einzelner STIX Indicator (minimal) | 500 Bytes – 2 KB |
| Bundle mit 10 Indicators | 5 – 20 KB |
| Bundle mit 100 Indicators | 50 – 200 KB |
| Bundle mit 1.000 Indicators | 500 KB – 2 MB |
| YARA-Regelset (50–500 Regeln) | 10 – 100 KB |

### 6.3 Federated Learning für IDS (akademisch, nicht Praxis-Standard)

Federated Learning (FL) für verteilte Anomalieerkennung in Smart Grids und ICS ist ein aktives Forschungsfeld, aber **noch kein etablierter Praxis-Standard** bei Energieversorgern.

Relevante Erkenntnisse aus der Literatur:
- **FL-CTIF Framework:** Privacy-preserving CTI für IIoT; 41% reduzierter Kommunikationsoverhead vs. zentralisiertes Training
- **Energieersparnis beim Training:** 22% Reduktion durch optimierte Update-Intervalle und Model Pruning
- **Detektionsgenauigkeit:** 97,2% bei FL + Differential Privacy (ACM 2024)

Typische Datenvolumina:
- Gradienten-Update (komprimiert): 1 – 10 MB
- Voller Modell-Checkpoint (Deep Learning IDS): 50 – 500 MB

Quellen:
- „Federated learning for cyber attack detection to enhance security in protection schemes of cyber-physical energy systems" (ScienceDirect, 2025)
- „Integrating Federated Learning and Differential Privacy for Secure Anomaly Detection in Smart Grids" (ACM, 2024, DOI: 10.1145/3694860.3694869)

---

## 7. Bandbreitenbedarf und Frequenz

### 7.1 Frequenzanforderungen nach Datentyp

| Datentyp | Empfohlene Frequenz | Begründung |
|---|---|---|
| Taktische IoCs (IPs, Hashes) — SCADA/OT | Stündlich bis near-realtime | Schnelle Reaktionsanforderungen in OT-Umgebungen |
| Operative CTI (validierte STIX-Bundles) | Täglich | Standard für die meisten Organisationen |
| Strategische Intelligence (Reports, TTPs) | Wöchentlich bis monatlich | Langfristige Lagebilderstellung |
| FL-Modell-Updates | Täglich bis wöchentlich | Abhängig von Modellstabilität und Datenmenge |
| NIS2-Pflichtmeldungen | Ereignisgetrieben (24h/72h-Fristen) | Regulatorisch vorgegeben |
| SITAW-Updates (EE-ISAC) | Bi-monatlich | Aktuelle EE-ISAC-Praxis |

**Wichtig:** TAXII 2.1 definiert keine Standardfrequenz. Die Frequenz wird individuell konfiguriert.

### 7.2 Implikationen für Spectrum-Runden

Spectrum arbeitet in diskreten Runden. Die Rundentaktung muss zur gewünschten Sharing-Frequenz passen:

| Szenario | Empfohlene Rundenlänge | L (erwartete Broadcaster/Runde) |
|---|---|---|
| Kuratierte CTI, täglich | 1–24 Stunden | Sehr gering (< 5% der Teilnehmer) |
| Operative IoC-Feeds, stündlich | 1 Stunde | Gering (5–20% der Teilnehmer) |
| Automatisierte Telemetrie, near-realtime | Minuten | Potenziell hoch — Spectrum-Vorteil erodiert |

### 7.3 Bandbreitenbedarf pro Runde (Spectrum, 2-Server)

*Aus dem Spectrum-Paper, Table 2 (2-Server-Konfiguration):*

| Komponente | Größe |
|---|---|
| Request pro Client | \|m\| + 70 Bytes |
| Audit-Größe pro Client | 70 Bytes |
| Aggregation (einmalig pro Server) | \|m\| + 3 Bytes |
| BlameGame Backup-Request | 140 Bytes (nur bei Fehlerfall) |
| BlameGame Audit | 200 Bytes (nur bei Fehlerfall) |

Bei einem typischen STIX-Bundle von 100 KB und 1.000 Clients:
- Jeder Client sendet ~100 KB + 70 Bytes an jeden der 2 Server
- Gesamteingang pro Server pro Runde: ~100 MB
- Inter-Server-Kommunikation für Audit: ~70 KB (trivial)

Das ist für moderne Infrastruktur vollständig unproblematisch.

### 7.4 Einschränkungen bei großen Nachrichten und n > 2 Servern

Spectrum mit dem optimierten 2-Server-DPF (AES-128 CTR als PRG, BLAKE3 als Hash) läuft bei 1 GB und 10.000 Nutzern in ~13h 20m. Bei wöchentlichen FL-Modell-Updates (50–500 MB) ist das akzeptabel; für tägliche Updates bei großen Modellen zu langsam.

Bei n > 2 Servern: seed-homomorpher PRG (Jubjub-Kurve) ist ~20.000× langsamer als AES-basierter PRG → ~5× Slowdown für 10 kB Nachrichten. Bei wachsender Nachrichtengröße vergrößert sich der relative Unterschied weiter.

---

## 8. Das Zählproblem: Angriffszahlen vs. geteilte Incidents

### 8.1 Die scheinbare Diskrepanz

Medienberichte sprechen von „Tausenden Angriffen pro Monat" auch auf mittelständische Unternehmen. Der E-ISAC teilte 2023 insgesamt 968 Cyber-Shares über ein gesamtes Jahr bei Tausenden Mitgliedern. Das ist kein Widerspruch — es sind verschiedene Dinge.

### 8.2 Was zählen Unternehmen als „Angriff"?

Was in SIEM-Dashboards und Presseberichten als „Angriff" auftaucht, sind typischerweise **rohe Security Events**:
- Port-Scans automatisierter Bots (Shodan, Masscan-Derivate scannen das gesamte Internet kontinuierlich)
- Fehlgeschlagene Login-Versuche (Credential-Stuffing-Kampagnen)
- Spam-Mails mit maliciösen Links oder Anhängen
- Automatisierte Vulnerability-Prober

Das sind reale Ereignisse, aber keine gezielten Angriffe. Sie produzieren keine neuen CTI-Erkenntnisse — die Indikatoren sind meist bereits in öffentlichen Feeds (VirusTotal, AbuseIPDB, Shodan) bekannt.

### 8.3 Der CTI-Filter-Funnel

```
Millionen rohe Security Events/Monat
        ↓ SIEM-Filterung
Zehntausende Alerts
        ↓ manuelle Triage
Hunderte bestätigte Incidents
        ↓ Relevanzprüfung (neu? geteilt? handlungsrelevant?)
Dutzende schwerwiegende, neuartige Incidents
        ↓ Aufbereitung + Sharing-Entscheidung + Anonymisierung
Handvoll tatsächlich geteilte CTI-Items
```

Jede Stufe reduziert um mindestens eine Größenordnung.

### 8.4 Implikationen für die Architektur

**Wichtige Schlussfolgerung:** Bei einem System, das **kuratierte CTI** (validierte STIX-Bundles, Threat Reports) teilt, ist der Broadcaster-Anteil L/N zu jedem Zeitpunkt gering — selbst wenn jeder Client prinzipiell senden darf.

Wenn dagegen **rohe Events oder automatisierte Telemetrie** geteilt werden sollen, könnte L → N laufen. Dann verliert Spectrum seinen Effizienz-Vorteil und Riposte oder ein anderes System wäre besser geeignet.

**Designempfehlung:** Einen lokalen Validierungsschritt vor dem anonymen Sharing-System einbauen. Nur Daten, die einen Mindestgrad an Neuheit und Relevanz erfüllen (automatisiert oder manuell geprüft), werden in das System eingespeist. Das hält L << N auch in der Praxis.

Der GAO-Report 2023 zeigt, dass föderale US-Systeme im Schnitt **5 Monate** zwischen Incident-Identifikation und Partnerbenachrichtigung vergehen lassen — was unterstreicht, wie manuell und selektiv Sharing in der Praxis ist.

---

## 9. Anonymitätsmenge und Teilnehmerstruktur

### 9.1 Warum Teilnehmer aus mehreren Sektoren?

Die Anonymitätsmenge N muss groß genug sein, um echten Schutz zu bieten. Für einen europäischen Energieversorger-Pool gilt:
- Die Zahl der relevanten Energieversorger in Europa ist begrenzt (TSOs: 40, DSOs: mehrere Hundert, aber nur ein Bruchteil würde teilnehmen)
- Mehr Teilnehmer = größere Anonymitätsmenge = stärkerer Schutz

**Empfohlene Teilnehmerkategorien:**

| Sektor | Rationale | Überlappung mit Energie-IoCs | Anonymitätsbedarf |
|---|---|---|---|
| Energieversorger | Kern-Zielgruppe | 100% | Sehr hoch |
| Finanzinstitute | Sehr aktiv, ähnliche IoC-Profile | Hoch (gemeinsame Angreifer-Gruppen) | Sehr hoch |
| Telekommunikation | Aktiv (ETIS), ähnliche TTPs | Hoch | Mittel |
| Gesundheitswesen | Aktiv (Ransomware), strukturiertes Programm | Mittel | Hoch |

isacs.eu als bestehende Verbindungsstruktur wäre der natürliche Ankerpunkt für ein sektorübergreifendes System.

### 9.2 Grenzen der Anonymitätsgarantien

Spectrum bietet **kryptographisch beweisbare N-Anonymität** unter folgenden Voraussetzungen:
1. Mindestens ein Server ist ehrlich
2. Alle N Clients bleiben während der gesamten Protokollrunde online
3. Alle Clients senden Cover Traffic (Shares von 0)

**Praktische Einschränkungen:**
- Intersection Attacks über mehrere Runden: Wenn ein Client nur in manchen Runden online ist, schrumpft die effektive Anonymitätsmenge
- Timing-Korrelation: Wenn ein Broadcast kurz nach einem bekannten Ereignis erscheint, kann der Zeitpunkt die Anonymität schwächen
- Die Server kennen L (Kanalanzahl) — sie wissen also, dass genau L der N Clients Broadcaster sind, aber nicht welche

---

## 10. Architekturempfehlungen

### 10.1 Empfohlene Konfiguration für CTI-Sharing

Basierend auf allen Erkenntnissen:

**System-Grundlage:** Spectrum (2-Server) mit epoch-basiertem Slot-Reservierungsmodell

**Begründung:**
- STIX-Bundles (50–500 KB) sind sehr Spectrum-freundlich
- Kuratierte CTI hat geringe gleichzeitige Broadcaster-Rate (L << N)
- Malicious-Server-Sicherheit (BlameGame) ist für misstrauische Teilnehmer aus verschiedenen Sektoren essenziell
- 2-Server-Konfiguration optimal für Leistung; Ehrlichkeitsannahme an einen Server ist realistisch mit institutioneller Aufsicht (z.B. ENISA-gehosteter Server)

**Komponenten:**
1. **Epochen-Taktung:** Stündlich für taktische IoCs, täglich für kuratierte Bundles
2. **Slot-Reservierung:** Leichtgewichtiges anonymes Bootstrapping zu Beginn jeder Epoche (Riposte für ~64-Byte Schlüsselregistrierung, dann Spectrum für den eigentlichen Inhalt)
3. **Lokaler Validierungsfilter:** Vor dem Einwerfen in Spectrum; verhindert Flut von Commodity-IoCs
4. **PIR für Downloads:** Subscriber können anonym abrufen, welchen Kanal/welche Indikatoren sie interessieren
5. **Sektorübergreifende Teilnahme:** Energie + Finanzen + Telekommunikation für ausreichende N-Größe

### 10.2 Nicht geeignet für

- **Near-realtime automatisierte Telemetrie** (L → N, Spectrum-Vorteil erodiert → dann eher Riposte oder spezialisierte Systeme)
- **Sehr große FL-Modelle täglich** (500 MB täglich → 13h+ pro Runde nicht praktikabel; wöchentlich grenzwertig)
- **Clients mit stark intermittierender Verfügbarkeit** (reduziert effektive Anonymitätsmenge durch Intersection Attacks)

### 10.3 Offene Forschungsfragen

- Wie kann das Bootstrapping so gestaltet werden, dass kein Henne-Ei-Problem entsteht, ohne ein vollständig separates System zu erfordern?
- Wie lassen sich Intersection Attacks bei intermittierend online seienden Clients mitigieren?
- Ist ein seed-homomorpher PRG mit besserer konkreter Leistung (LWE-basiert) realistisch? Das Paper nennt es als interessante Future Work.
- Wie kann der lokale Validierungsfilter standardisiert werden, damit der Begriff „teilenswürdig" über Sektorgrenzen hinweg konsistent angewendet wird?

---

## 11. Quellen

### Primärquelle

- Newman, Z., Servan-Schreiber, S., Devadas, S. (2022). **Spectrum: High-bandwidth Anonymous Broadcast**. *19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 2022)*. https://www.usenix.org/conference/nsdi22/presentation/newman

### Verwandte Systeme

- Corrigan-Gibbs, H., Boneh, D., Mazières, D. (2015). **Riposte: An anonymous messaging system handling millions of users**. *2015 IEEE Symposium on Security and Privacy*, pp. 321–338.
- Eskandarian, S., Corrigan-Gibbs, H., Zaharia, M., Boneh, D. (2021). **Express: Lowering the cost of metadata-hiding communication with cryptographic privacy**. *30th USENIX Security Symposium*.
- Corrigan-Gibbs, H., Ford, B. (2010). **Dissent: Accountable anonymous group messaging**. *ACM CCS 2010*.
- Abraham, I., Pinkas, B., Yanai, A. (2020). **Blinder: Scalable, robust anonymous committed broadcast**. *ACM CCS 2020*.
- Chaum, D. (1988). **The dining cryptographers problem: Unconditional sender and recipient untraceability**. *Journal of Cryptology*, 1(1):65–75.

### CTI-Sharing Praxis

- EE-ISAC Official Site: https://www.ee-isac.eu/
- MDPI Energies (2022): EE-ISAC Review. DOI: 10.3390/en15062170
- ENTSO-E: https://www.entsoe.eu/
- NERC/E-ISAC Annual Report 2023: https://www.nerc.com/programs/e-isac
- CTI Sharing Practices and MISP Adoption in Finland's Critical Infrastructure. *ECCWS 2024*. https://papers.academic-conferences.org/index.php/eccws/article/view/2352
- Leszczyna, R. (2019). Threat Intelligence Platform for the Energy Sector. *Software: Practice and Experience* (Wiley). DOI: 10.1002/spe.2705
- Krasznay, Gyebnar (2021). Possibilities and Limitations of Cyber Threat Intelligence. *CyCon 2021 @ CCDCOE*. https://ccdcoe.org/uploads/2021/05/CyCon_2021_Krasznay_Gyebnar.pdf

### Regulierung und Standards

- NIS2-Direktive, Artikel 23: https://advisera.com/articles/reporting-obligations-nis2/
- ENISA Threat Landscape 2025: https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025
- ENISA NIS360 2024: https://www.enisa.europa.eu/sites/default/files/2025-03/ENISA%20-%20NIS360%20-%202024_0.pdf
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- OASIS TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
- NIST SP 800-150: Guide to Cyber Threat Information Sharing. https://doi.org/10.6028/NIST.SP.800-150

### Bandbreite, Frequenz, Angriffszahlen

- GAO Report 2023: Critical Infrastructure Protection — Information Sharing Performance Measures. https://www.gao.gov/products/gao-23-105468
- LevelBlue (2024): Energy and Utilities Barriers to Cybersecurity Resilience. https://www.businesswire.com/news/home/20241030579205/
- Springer Nature (2025): Share and benefit — incentives for cyber threat intelligence sharing. https://link.springer.com/article/10.1007/s10207-025-01165-2

### Federated Learning für CTI

- Federated learning for cyber attack detection in cyber-physical energy systems. *ScienceDirect 2025*. DOI: 10.1016/j.iswa.2025.200495
- Integrating Federated Learning and Differential Privacy for Secure Anomaly Detection in Smart Grids. *ACM 2024*. DOI: 10.1145/3694860.3694869
- FL-DPCSA: Federated Learning with Differential Privacy for Cache Side-Channel Attack Detection. *ScienceDirect 2025*. DOI: 10.1016/j.iswa.2025.200540
