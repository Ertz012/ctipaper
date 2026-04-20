# Research Plan: MetaCTI – Metadata-Private Cyber Threat Intelligence Sharing via Anonymous Write Protocols

**Version:** 0.2 (April 2026)  
**Status:** Draft – aktualisiert nach Protokollanalyse (DC-net-Hybrid verworfen, Dual-Mode-Architektur eingeführt)

---

## 1. Motivation und Problemstellung

Cyber Threat Intelligence (CTI) ist ein zentrales Instrument kollektiver Cyberabwehr. Organisationen teilen Indicators of Compromise (IOCs), Taktiken, Techniken und Prozeduren (TTPs) über Plattformen wie MISP, TAXII-Server oder ISACs, um schneller auf Angriffe reagieren zu können. Trotz klarer Vorteile zögern viele Organisationen bei der Teilnahme. Der wichtigste Grund ist nicht fehlende Bereitschaft, sondern ein fundamentales Metadaten-Problem:

> **Wer einen IOC meldet, verrät damit, dass er kompromittiert wurde.**

Das Wissen, *dass* Organisation A gerade einen Angriff meldet, ist für einen Angreifer oft wertvoller als der IOC selbst. Es ermöglicht Attributionsangriffe, verrät Zeitpunkte von Sicherheitsvorfällen, und signalisiert Angreifern, welche ihrer Techniken noch unentdeckt sind. Aktuelle Lösungsansätze adressieren dieses Problem nicht zufriedenstellend:

- **TAXII + TLS**: Verschlüsselt Inhalt, aber der Server sieht, wer sich mit wem verbindet.
- **MISP + Tor** (Wagner et al. 2018): Schützt IP-Adressen, bietet aber keine kryptografischen Garantien gegen aktive Angreifer oder Timing-Korrelationsangriffe.
- **Blockchain-basierte Systeme**: Liefern Pseudonymität, aber Transaktionsgraph und Zeitstempel sind öffentlich sichtbar.
- **SeCTIS (2024)**: Federated Swarm Learning – schützt Rohdaten, nennt aber explizit „connection anonymity" als offene Forschungsfrage.
- **Huff et al. 2024**: BBS+-basierte inhaltliche Anonymität gegenüber dem Empfänger, aber nicht gegenüber der Infrastruktur.

**Die Lücke:** Es existiert kein CTI-Sharing-System mit formal nachgewiesener *Kommunikations-Metadaten-Privatheit* – also dem Schutz davor, dass die Infrastruktur oder Dritte erkennen können, wer wann mit wem welche Art von CTI ausgetauscht hat.

---

## 2. Kernidee

Wir adaptieren das Protokolldesign von **EXPRESS** (Eskandarian et al., USENIX Security 2021) für den CTI-Sharing-Kontext. EXPRESS basiert auf dem Vorgänger **RIPOSTE** (Corrigan-Gibbs et al., IEEE S&P 2015), ist aber 100× effizienter. Beide Systeme wurden für anonymes Messaging (Whistleblowing, Journalistenschutz) entwickelt und bieten starke kryptografische Metadaten-Privatheit mit formalen Beweisen.

Schlüsseleigenschaft von EXPRESS: Ein Client schreibt Nachricht M in eine Mailbox, indem er zwei Shares an zwei nicht-kolludierende Server schickt (S an Server 1, S XOR M an Server 2). Kein Server sieht M allein. Die algebraische Struktur der Shares erlaubt den Servern zu prüfen, dass ein Client wohlgeformt und in exakt eine Mailbox geschrieben hat – Schutz gegen malicious participants ohne Anonymitätsbruch. Schreibkosten: 2 × M pro Client pro Round, unabhängig von der Teilnehmerzahl N.

Im CTI-Kontext übertragen: Eine Organisation kann einen STIX-Report einreichen, ohne dass die Plattform (ISAC, CERT, TAXII-Server) oder Mitmember erfahren, welche Organisation den Report erstellt hat.

Das System nennen wir vorläufig **MetaCTI** und implementiert eine **Dual-Mode-Architektur** (siehe C2).

---

## 3. Forschungsfragen

**RQ1 – Threat Model:** Welche Metadaten-Angriffe sind im CTI-Sharing-Kontext realistisch, und welche Informationen kann ein Angreifer daraus gewinnen? Wie ordnen sich existierende Systeme bezüglich formaler Metadaten-Privatheit ein?

**RQ2 – Protokolldesign:** Wie muss RIPOSTE/EXPRESS für den CTI-Kontext adaptiert werden, um mit großen STIX-Objekten, asynchronem Sharing und TLP-basierten Sharing-Levels umgehen zu können?

**RQ3 – Qualitätssicherung unter Anonymität:** Wie kann False-Positive-Einspeisung und Poisoning-Angriffe verhindert werden, ohne die Anonymität der Submitter zu brechen?

**RQ4 – Praktikabilität:** Welche Performance-Kosten entstehen gegenüber konventionellen TAXII-basierten Systemen, und unter welchen Bedingungen ist das System für reale CTI-Sharing-Gemeinschaften einsetzbar?

---

## 4. Contributions (Projektiert)

### Contribution C1: Formales Threat Model für CTI-Metadaten-Leakage (neu)

Wir entwickeln das erste formale Threat Model speziell für Metadaten-Leakage in CTI-Sharing-Systemen. Das Modell definiert:

- **Adversary-Typen**: Neugieriger Plattformbetreiber (honest-but-curious server), aktiver Angreifer unter den Teilnehmern, externer Netzwerk-Observer.
- **Angriffsziele**: Sender-Anonymität (welche Org hat IOC X gemeldet?), Empfänger-Anonymität (wer hat IOC X gelesen?), Unlinkability (lässt sich Org A's Verhalten über Zeit profilieren?), Traffic-Volume-Angriffe (häufige Submissions deuten auf aktiven Incident hin).
- **Formale Sicherheitsdefinitionen**: Sender-Anonymität als Indistinguishability-Spiel, Unlinkability analog zu anonymen Credential-Schemata.

Zusätzlich **klassifizieren wir existierende CTI-Sharing-Systeme** anhand dieses Modells und zeigen deren Lücken formal auf. Das stellt den Related-Work-Teil auf eine solide, vergleichende Basis.

**Output:** Formales Threat-Model-Paper-Abschnitt + Klassifikations-Tabelle bestehender Systeme.

---

### Contribution C2: Protokolldesign MetaCTI (Kernbeitrag)

Wir entwerfen MetaCTI als adaptiertes Protokoll auf Basis von EXPRESS. Die Adaptionen sind nicht trivial – sie verlassen in mehreren Punkten das ursprüngliche EXPRESS-Sicherheitsmodell und erfordern eigenständige Analysen.

**C2a – Dual-Mode-Architektur (zentrale Designerkenntnis):**  
CTI-Sharing folgt zwei grundlegend verschiedenen Sharing-Mustern, die unterschiedliche Schutzziele erfordern:

*Broadcast-Modus (TLP:WHITE, TLP:GREEN):* Informationen sollen alle Teilnehmer erreichen. Leser-Anonymität ist kein Ziel – jeder soll alles wissen. Schutzziel: nur Sender-Anonymität. Konsequenz: **PIR wird vollständig eliminiert.** Die Datenbank wird nach jeder Round öffentlich heruntergeladen. Das reduziert die Server-Compute-Last von O(N×M) pro PIR-Anfrage auf null und vereinfacht das Protokoll erheblich.

*Directed-Modus (TLP:AMBER, TLP:RED):* Informationen gehen nur an ausgewählte Empfänger. Schutzziel: primär Sender-Anonymität; Leser-Anonymität ist eine offene Designfrage. **Wichtig:** EXPRESS verbirgt nur Writes (Sender-Seite), nicht Reads – ein Angreifer kann beobachten, welche Mailbox ein Client abruft (explizit im Express-Paper, §1 und §6). Optionen für die Read-Seite: (a) uniforme DB-Download-Strategie (alle Empfänger laden alle Mailboxes und entschlüsseln lokal – Leser-Anonymität durch uniformes Zugriffsmuster), (b) separates PIR-Protokoll für Reads (erhebliche Zusatzkomplexität), oder (c) asymmetrische Verschlüsselung mit bekannten Gruppenkeys (einfacher, aber Read-Metadaten entleaken). MetaCTI verwendet initial Option (a) als Kompromiss: maximale Sender-Anonymität, Leser-Anonymität durch uniformes Zugriffsverhalten. Formale Read-Anonymität bleibt als Forschungsfrage (→ C2d). Adaptation des Mailbox-Schemas für **Gruppen-Mailboxen** (Sektor-ISAC, bilaterale Shares) mit group-key-basierter Verschlüsselung.

Diese Unterscheidung existiert in keinem bisherigen CTI-System. Die Elimination unnötiger PIR-Overhead im Broadcast-Modus und das klare Benennen der Read-Anonymitätsgrenzen im Directed-Modus erlaubt eine deutlich effizientere und theoretisch präzisere Implementierung als bisherige Ansätze.

**C2b – Chunking für große STIX-Objekte:**  
STIX-Objekte überschreiten regelmäßig die für Messaging-Systeme übliche Nachrichtengröße. Wir definieren einen Schwellwert (vorläufig 32 KB) und entwickeln ein drei-stufiges Schema:
- Unter 32 KB: direkter Write ohne Overhead
- 32 KB – 1 MB: Chunking in 32-KB-Blöcke, über mehrere Rounds verteilt, symmetrisch verschlüsselt
- Über 1 MB: Out-of-Band-Referenz (nur URL + Schlüssel via MetaCTI, Objekt auf separatem Encrypted Object Store)

Multi-Round-Chunking verlässt das EXPRESS-Sicherheitsmodell: **Wir beweisen formal**, dass die Chunk-Verteilung über Slots keine Round-übergreifenden Timing-Korrelationen erzeugt, die Sender-Anonymität brechen könnten.

**C2c – Cover-Traffic-Management:**  
EXPRESS ist asynchron (kein synchronisiertes Round-Protokoll wie RIPOSTE). Cover-Traffic ist für Timing-Anonymität erforderlich, muss aber *nicht* von den ISAC-Mitgliedern selbst generiert werden – der Express-Paper schlägt explizit third-party Cover-Traffic vor. In MetaCTI generiert der ISAC-Betreiber (oder ein dedizierter Dienst) den Cover-Traffic. Wir entwickeln ein formales Modell: Welche Cover-Traffic-Rate ist nötig, um Traffic-Volume-Angriffe zu verhindern? Unter welchen Annahmen kann ein Angreifer durch beobachtete Batches auf die Anzahl echter Writes rückschließen? Wir leiten konkrete Empfehlungen für die Batch-Frequenz in Abhängigkeit von ISAC-Größe und typischer Sharing-Frequenz ab.

**C2d – Protokollsicherheit:**  
Formale Sicherheitsbeweise für MetaCTI unter den EXPRESS-Basisannahmen (Two non-colluding servers, PRF-Sicherheit). Explizit zu beweisen: dass die CTI-spezifischen Erweiterungen (Chunking, Dual-Mode) keine neuen Angriffsvektoren einführen.

**Output:** Vollständige Protokollspezifikation mit Sicherheitsbeweisen.

---

### Contribution C3: Abuse Prevention unter Anonymität (Anti-Poisoning)

Starke Sender-Anonymität eröffnet einen Angriffsvektor: ein Angreifer kann False Positives oder vergiftete IOCs einschleusen, ohne identifizierbar zu sein. Wir lösen dieses Problem in zwei Schichten:

**C3a – Angepasstes Abuse Reporting:**  
Wir integrieren den Mechanismus aus Eskandarian et al. (USENIX Security 2024) – Abuse Reporting für Metadata-Hiding-Systeme via Secret Sharing – in das MetaCTI-Protokoll. Konkret: Jeder STIX-Submit wird mit einem kryptografischen Token versehen, der im Fall eines gemeldeten Missbrauchs (durch Empfänger) unter Beteiligung beider Server deanonymisiert werden kann, *ohne dass bei normalem Betrieb die Anonymität gebrochen wird*. Wir analysieren, wie dieser Mechanismus für den CTI-Kontext kalibriert werden muss (Missbrauchs-Schwellwert, False-Report-Anreize).

**C3b – ZKP-basierter Sektornachweis:**  
Um die Qualität von Submissions zu stärken, ohne Anonymität zu brechen, entwickeln wir ein Schema, bei dem Submitter mittels Zero-Knowledge-Proof nachweisen können, dass sie einer autorisierten Teilnehmergruppe (z.B. ISAC-Mitglied im Finanzsektor) angehören, ohne ihre Identität preiszugeben. Das erfolgt über ZKP über Mitgliedschaftsnachweise (Merkle-Tree-basiert oder auf Basis anonymer Credentials wie BBS+).

**Output:** Erweitertes Protokoll mit Abuse-Reporting und ZKP-Membership-Nachweis.

---

### Contribution C4: Implementierung und Evaluation

**C4a – Prototyp-Implementierung:**  
Implementierung von MetaCTI in Python/Rust mit folgenden Komponenten:
- Two-Server-Setup (MetaCTI-Server A/B)
- Client-Library mit STIX 2.1-Serialisierung
- Benchmark-Harness

Wir bauen auf dem öffentlichen EXPRESS-Codebase auf und erweitern diesen.

**C4b – Performance-Benchmark:**  
Messung von Durchsatz, Latenz und Bandbreitenkosten für realistische CTI-Workloads:
- Micro-Benchmark: Einzelne IOCs, STIX-Bundles verschiedener Größe (1 KB – 5 MB), Chunking-Overhead
- Macro-Benchmark: Simulierte ISAC mit N ∈ {50, 200, 500, 1000} Teilnehmern, basierend auf empirisch erhobenen CTI-Sharing-Frequenzen
- Metriken pro Modus: Broadcast-Modus (öffentlicher DB-Download) vs. Directed-Modus (uniforme Mailbox-Downloads) separat ausgewiesen
- Vergleich mit: TAXII+TLS (Baseline), MISP+Tor (Wagner 2018), Blockchain-CTI

**C4c – Workload-Charakterisierung:**  
Empirische Erhebung typischer STIX-Objektgrößen und Sharing-Frequenzen an öffentlichen MISP Community Feeds. Validiert die Chunking-Schwelle (32 KB) und die Aussage, dass der Broadcast-Modus den Großteil des operativen Sharings abdeckt.

**C4d – Privacy-Kosten-Tradeoff-Analyse:**  
Quantitative Darstellung: Was kostet Metadatenschutz in Latenz, Dummy-Traffic-Bandbreite und Serverauslastung? Bei welchen Teilnehmerzahlen und Sharing-Frequenzen ist MetaCTI praktisch einsetzbar? Konkrete Deployment-Empfehlungen.

**Output:** Open-Source-Prototyp, Benchmark-Ergebnisse, Deployment-Guidelines.

---

## 5. Systemarchitektur (Skizze)

```
                     ┌─── BROADCAST-MODUS (TLP:WHITE/GREEN) ───┐
                     │   Kein PIR – DB wird öffentlich geladen  │
                     └──────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       MetaCTI System                            │
│                                                                 │
│  ┌──────────┐   Write-Share (2×M)  ┌────────┐    ┌────────┐    │
│  │  Org A   │─────────────────────►│Server 1│◄──►│Server 2│    │
│  │ (Sector: │   S ──────────────►  │        │    │        │    │
│  │  Finance)│   S XOR M ────────►  │        │    │        │    │
│  └──────────┘                      └───┬────┘    └────┬───┘    │
│                                        │              │         │
│  ┌──────────┐   ZKP Membership         ▼              ▼         │
│  │  Org B   │──── Nachweis ──► ┌───────────────────────────┐   │
│  │ (Sector: │                  │     Write-Private DB       │   │
│  │  Energy) │◄── Broadcast ─── │  (STIX Slots, TLP-Ebenen) │   │
│  └──────────┘   (öffentlich,   └───────────────────────────┘   │
│                  kein PIR)              ▲                        │
│  ┌──────────┐   Mailbox-Read           │                        │
│  │  Org C   │── (uniform DB-DL) ──────►│   Directed-Modus       │
│  │          │◄─ enc. Mailbox ──────────┘   (sender-anonym,      │
│  └──────────┘   lokal entschlüsseln        uniforme Reads)      │
│  ┌──────────┐   Abuse Report                                    │
│  │  Org D   │── (Secret Sharing) ──────────────────────────►   │
│  └──────────┘   → Deanonymisierung nur bei Missbrauch           │
└─────────────────────────────────────────────────────────────────┘
```

**Trust-Modell:** Zwei Server, die nicht kolludieren (Two-Server-Non-Collusion). Realistisch umsetzbar durch: zwei verschiedene juristische Jurisdiktionen, oder ISAC + neutrales Security-Forschungsinstitut als Serverbetreiber.

---

## 6. Abgrenzung zum Stand der Technik

| System | Inhalts-Privatheit | Sender-Anonymität | Metadaten-Privatheit | Abuse Prevention | Formale Garantien |
|---|---|---|---|---|---|
| TAXII + TLS | ✓ | ✗ | ✗ | n/a | Nein |
| MISP + Tor | ✓ | Schwach | Schwach | n/a | Nein |
| Blockchain CTI | ✓ | Pseudonym | ✗ | ✗ | Nein |
| Huff et al. 2024 | ✓ | Gegen Empfänger | ✗ | ✗ | Teilweise |
| SeCTIS 2024 | ✓ (FL) | ✗ | ✗ | ✓ | Teilweise |
| FL+DP (Fischer) | ✓ | ✗ | ✗ | ✗ | Ja (DP) |
| **MetaCTI (ours)** | **✓** | **✓ kryptografisch** | **✓ formal** | **✓ (C3)** | **✓** |

---

## 7. Evaluations- und Validierungsplan

### 7.1 Sicherheitsvalidierung
- Formale Analyse der Sicherheitseigenschaften (Sender-Anonymität, Unlinkability) als Indistinguishability-Beweise.
- Analyse des Abuse-Reporting-Mechanismus: Nachweis, dass normaler Betrieb keine Anonymitätsverluste verursacht.
- ZKP-Korrektheit und Zero-Knowledge-Eigenschaft des Membership-Nachweises.

### 7.2 Performance-Evaluation
- **Testumgebung**: Lokales Lab (5–10 Server-Nodes), Simulation größerer Szenarien via Emulation.
- **Metriken**: End-to-End-Latenz einer STIX-Submission, Server-CPU/RAM-Last, Netzwerkbandbreite pro Teilnehmer und Runde (getrennt: Dummy-Write-Traffic vs. DB-Download), Skalierung mit N.
- **Schlüsselvergleich**: Broadcast-Modus (kein PIR-Overhead, öffentlicher DB-Download) vs. Directed-Modus (uniforme Mailbox-Downloads, Zugangskontrolle per Encryption) – zeigt konkret, wo die PIR-Elimination des Broadcast-Modus greift und welche Overhead-Unterschiede entstehen.
- **Benchmarks gegen**: Pure TAXII (Baseline), TAXII + Tor, MetaCTI Broadcast, MetaCTI Directed.
- **Ziel**: Zeigen, dass MetaCTI-Broadcast für ISACs mit bis zu ~500 Mitgliedern praktikabel ist; klare Aussage, ab wann MetaCTI-Directed zum Bottleneck wird.

### 7.3 Usability / Deployment
- Analyse der operativen Anforderungen: Welche Infrastruktur braucht ein ISAC, um MetaCTI zu betreiben?
- Vergleich mit existierenden MISP-Deployments bezüglich Betriebsaufwand.

---

## 8. Zeitplan / Meilensteine

| Phase | Inhalt | Dauer | Output |
|---|---|---|---|
| **Phase 1** | Literaturanalyse, Threat-Model-Formalisierung (C1) | 6 Wochen | Threat-Model-Draft |
| **Phase 2** | Protokolldesign MetaCTI Kern (C2a, C2b) | 8 Wochen | Protokollspezifikation |
| **Phase 3** | Asynchrones Round-Management, Sicherheitsbeweise (C2c, C2d) | 6 Wochen | Formale Analyse |
| **Phase 4** | Abuse Prevention, ZKP-Membership (C3) | 8 Wochen | Erweitertes Protokoll |
| **Phase 5** | Implementierung Prototyp (C4a) | 8 Wochen | Codebase |
| **Phase 6** | Benchmarks, Evaluation (C4b, C4c) | 6 Wochen | Benchmark-Ergebnisse |
| **Phase 7** | Paper Writing, Review-Vorbereitung | 6 Wochen | Paper-Draft |
| **Gesamt** | | **~48 Wochen** | |

---

## 9. Ziel-Venues

### Primär (Applied Security / Systems Security)
- **USENIX Security** (Deadline typisch Februar/Juni): Idealer Fit – Eskandarian's EXPRESS-Paper selbst erschien hier; starker Systems-Track.
- **CCS (ACM CCS)** (Deadline typisch Mai): Breites Security-Publikum, gut für Systembeiträge mit formalen Komponenten.
- **NDSS** (Deadline typisch September): Guter Fit für applied security mit Protokollbeitrag.

### Sekundär (Cybersecurity-spezifisch)
- **IEEE S&P (Oakland)**: Wenn der formale Beweis stark genug ist.
- **DIMVA / RAID**: Wenn der Fokus stärker auf dem CTI-Anwendungsfall liegt.
- **Journal of Cybersecurity (Oxford)** / **Computers & Security (Elsevier)**: Als Journal-Version mit erweiterter Evaluation.

### Entscheidungsfaktor
Das Paper positioniert sich an der **Grenze zwischen Kryptografie/Security-Protokollen und Cybersecurity-Anwendungen**. Das stärkt die Akzeptanzchancen, wenn sowohl Protokollbeitrag als auch Anwendungsvalidierung überzeugend sind. Für USENIX Security oder CCS muss C2d (formale Sicherheitsbeweise) ausreichend stark sein.

---

## 10. Offene Fragen und Risiken

### Technische Risiken
- **Performance bei großen Gemeinschaften**: Für N > 500 wird der tägliche DB-Download (~720 MB/Tag bei M=10KB, 10-min-Rounds) für Teilnehmer mit schlechter Anbindung problematisch. **Mitigation**: Diff-basierter Download (nur Deltas seit letzter Round); oder längere Round-Intervalle bei größeren Gemeinschaften.
- **Directed-Modus Read-Anonymität**: EXPRESS verbirgt keine Reads. Bei der uniformen DB-Download-Strategie (Option a) laden alle Empfänger alle Mailboxes – das erzeugt erheblichen Empfangs-Overhead bei großen Directed-Modus-DBs. **Mitigation**: Directed-Modus auf kleine Empfängergruppen (TLP:AMBER/RED: typisch 5–20 Organisationen) beschränken; oder Read-Anonymität explizit auf Sender-Anonymität einschränken und formal dokumentieren. Ein echtes Read-PIR wäre Forschungsfrage C2d (erhebliche Zusatzkomplexität).
- **Round-Synchronisierung vs. Echtzeit-CTI**: CTI-Sharing hat Latenzanforderungen. **Mitigation**: Empirisch erheben, welche Latenz (5 min? 15 min?) für welche IOC-Typen akzeptabel ist. Operative IOCs benötigen kürzere Rounds als strategische Reports.
- **Chunking-Sicherheit**: Multi-Round-Writes könnten Timing-Leakage erzeugen. **Mitigation**: Formaler Beweis als Teil von C2d; Chunk-Verteilung über Slots verhindert direkte Korrelation.
- **ZKP-Komplexität**: ZKP-basierter Sektornachweis könnte zu teuer sein. **Mitigation**: Evaluation ob einfachere anonyme Credentials (z.B. idemix, BBS+) ausreichen.

### Paper-Risiken
- **"Nur eine Anwendung von EXPRESS"**: Reviewer könnten den Protokollbeitrag als zu inkrementell werten. **Mitigation**: Sicherheitsbeweise und Abuse-Prevention-Mechanismus als eigenständige Beiträge herausarbeiten; das Threat Model als genuinen Beitrag für die CTI-Community positionieren.
- **Fehlende CTI-Experten als Co-Autoren**: Security-Protokoll + CTI-Domäne erfordert Expertise in beiden Bereichen. **Mitigation**: Frühzeitig CTI-Praktiker (ISAC, CERT) als Interviewpartner einbeziehen für das Threat Model; evtl. Ko-Autorenschaft.

---

## 11. Literatur-Basis (Kernreferenzen)

**Protokolle:**
- Corrigan-Gibbs et al., "Riposte: An Anonymous Messaging System Handling Millions of Users", IEEE S&P 2015
- Eskandarian et al., "Express: Lowering the Cost of Metadata-hiding Communication with Cryptographic Privacy", USENIX Security 2021
- Eskandarian et al., "Abuse Reporting for Metadata-Hiding Communication Based on Secret Sharing", USENIX Security 2024

**CTI-Sharing (Related Work):**
- Wagner et al., "Towards an Anonymity Supported Platform for Shared CTI", CRiSIS 2017
- Huff et al., "A Privacy-Preserving Cyber Threat Intelligence Sharing System", IEEE TPS 2024
- Alsaedi et al., "SeCTIS: A Framework to Secure CTI Sharing", FGCS 2024
- Fischer, "Privacy-Preserving Federated Learning for CTI Sharing", MSc-Thesis ETH Zürich

**Standards:**
- STIX 2.1 (OASIS Standard)
- TAXII 2.1 (OASIS Standard)
