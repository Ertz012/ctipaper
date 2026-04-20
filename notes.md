# MetaCTI – Forschungsnotizen und Designüberlegungen

**Zweck:** Zentrale Sammlung aller Erkenntnisse, Überlegungen und Berechnungen aus der Konzeptionsphase. Dient als Vorlage für Paperabschnitte. Alle Zahlen und Argumente sind als Ausgangspunkt zu verstehen und vor der Verwendung im Paper zu verifizieren.

---

## 1. Ausgangslage und Forschungslücke

### 1.1 Das Kernproblem

CTI-Sharing leidet unter einem fundamentalen Anreizproblem: Wer einen IOC meldet, verrät damit, dass er kompromittiert wurde. Diese Metadaten-Leakage ist oft sensibler als der IOC selbst:

- Angreifer erfahren, welche ihrer Techniken entdeckt wurden → können TTPs rotieren
- Dritte (Regulatoren, Konkurrenten, Medien) können Kompromittierungen beobachten
- Zeitstempel von Submissions erlauben Rückschlüsse auf den Zeitpunkt von Incidents

Folge: Organisationen teilen zu wenig, zu spät, oder nur unter hohem Druck. ENISA und CISA berichten übereinstimmend, dass Vertrauens- und Datenschutzbedenken die häufigsten Hindernisse für CTI-Sharing sind.

### 1.2 Bisherige Ansätze und ihre Lücken

| System | Was es schützt | Was es nicht schützt |
|---|---|---|
| TAXII + TLS | Inhalt | Wer mit wem kommuniziert |
| MISP + Tor (Wagner 2018) | IP-Adresse (schwach) | Timing-Korrelation, aktive Angreifer |
| Blockchain-CTI | Inhalt (verschlüsselt) | Transaktionsgraph, Zeitstempel sichtbar |
| Huff et al. 2024 (BBS+/ZKP) | Identität gegenüber Empfänger | Kommunikationsmetadaten gegenüber Infrastruktur |
| SeCTIS 2024 (Swarm Learning) | Rohdaten der Organisationen | Kommunikationsmetadaten (explizit als Future Work genannt) |
| FL + DP (Fischer ETH) | Trainingsdaten | Kommunikationsmetadaten |

**Schlüsselzitat aus SeCTIS 2024:** "current research establishes a solid foundation for ensuring institutional privacy in CTI exchange, yet several avenues remain open for further enhancement, with future work focusing on integrating *connection anonymity*."

Das ist die exakt benannte Lücke, die MetaCTI schließt.

### 1.3 Warum Tor nicht ausreicht

Wagner et al. 2018 verwenden MISP über das Tor-Netzwerk. Das ist zwar ein sinnvoller erster Schritt, bietet aber keine formalen Garantien:

- Tor schützt gegen passive Netzwerkbeobachter, nicht gegen aktive Timing-Angriffe
- Ein Angreifer, der Eingangs- und Ausgangspunkte kontrolliert, kann deanonymisieren (Correlation Attack)
- Es gibt keinen formalen Anonymitätsbeweis; die Garantien sind heuristisch
- Keine Absicherung gegen malicious participants innerhalb des Netzwerks

MetaCTI bietet demgegenüber kryptografisch formale Sender-Anonymität unter klar definierten Annahmen.

---

## 2. Technische Grundlagen: RIPOSTE und EXPRESS

*Dieser Abschnitt basiert auf direkter Lektüre der Originalpaper:*
*– Corrigan-Gibbs, Boneh, Mazières: „Riposte: An Anonymous Messaging System Handling Millions of Users", IEEE S&P 2015 (arXiv:1503.06115v7)*
*– Eskandarian, Corrigan-Gibbs, Zaharia, Boneh: „Express: Lowering the Cost of Metadata-hiding Communication with Cryptographic Privacy", USENIX Security 2021*

---

### 2.1 RIPOSTE (Corrigan-Gibbs et al., IEEE S&P 2015)

#### Grundprinzip: Write-Private Database Scheme

RIPOSTE implementiert ein *write-private database scheme*: Clients können in eine geteilte Datenbank schreiben, ohne dass die Server erkennen, in welche Zeile geschrieben wurde und was der Inhalt ist. Die Datenbank ist eine Tabelle mit L Zeilen fester Länge. Nach Ablauf einer *Zeit-Epoche* wird der Inhalt der Datenbank veröffentlicht – dann ist bekannt, *was* gepostet wurde, aber nicht *von wem*.

Das Anonymitätsset eines Clients entspricht allen Clients, die in derselben Epoche Schreibanfragen gestellt haben.

#### Naiver Ansatz und seine Kosten

Naiv könnte ein Client seinen Eintrag als einen langen Vektor kodieren: Alle Zeilen bis auf die Zielzeile sind Null, die Zielzeile enthält die Nachricht. Dieser Vektor wird additiv in k Shares aufgeteilt (einer pro Server), sodass die XOR-Kombination aller Shares den Originalvektor ergibt, jede Teilmenge von weniger als k Shares aber nichts verrät. **Kosten:** Jeder Share hat die Größe der gesamten Datenbank – O(L) pro Share, O(k·L) gesamt.

#### Optimierung via „Reverse PIR" / DPFs

RIPOSTE verwendet Distributed Point Functions (DPFs), um den Vektor zu komprimieren. Statt den vollen Vektor zu schicken, schickt der Client für jeden der k Server einen komprimierten DPF-Schlüssel, der denselben Effekt erzeugt. Jeder Schlüssel hat Größe O(√L) – daher die O(√L)-Kommunikationskosten pro Client pro Write.

#### Synchronized Rounds (wichtiges Merkmal)

RIPOSTE erfordert, dass *alle* Clients in jeder Epoche schreiben, bevor der Server die Daten veröffentlicht. Kein Client kann lesen, bevor nicht alle geschrieben haben. Das erzwingt starke Synchronisierung und führt dazu, dass Clients kontinuierlich online sein müssen.

#### Disruption-Schutz gegen malicious Clients

Ein zentrales Problem bei anonymen Schreibsystemen: Ein malicious Client kann den gesamten Datenbankinhalt zerstören, indem er eine zufällig geformte Schreibanfrage schickt. RIPOSTE adressiert das mit einem dedizierten **Audit-Server** (dritter Server), der prüft, ob eine Schreibanfrage wohlgeformt ist (Hamming-Gewicht ≤ 1, also nur eine Zeile beschrieben wird). Der Audit-Mechanismus nutzt Multi-Party-Computation zwischen den k Servern. Kosten: Ω(λ√n) Kommunikation und Ω(√n) Rechenarbeit auf dem Client.

#### Kernkennzahlen RIPOSTE

| Parameter | Wert |
|---|---|
| Server | k ≥ 3 (mindestens 2 dürfen nicht kolludieren) |
| Client-Kommunikation pro Write | O(√L), wobei L = Datenbankgröße |
| Synchronisierung | Strikt – alle Clients müssen pro Epoche schreiben |
| Schutz gegen malicious Clients | Ja (via Audit-Server, teuer) |
| Leseprivacy | Nein (DB wird nach Epoche öffentlich veröffentlicht) |

---

### 2.2 EXPRESS (Eskandarian et al., USENIX Security 2021)

#### Kernüberblick

EXPRESS ist ein Two-Server-System für metadata-hiding Kommunikation. Es verbessert RIPOSTE und Pung durch:
- Konstante Client-Kommunikationskosten unabhängig von der Nutzerzahl
- Nur 2 Server statt 3
- Asynchronen Betrieb (keine synchronisierten Runden erforderlich)
- Neues, drastisch effizienteres Audit-Protokoll

Laut Paper: über 100× weniger Bandbreite als Pung und RIPOSTE; Kosten 6× geringer für einen realen Whistleblowing-Dienst.

#### Systemmodell: Mailboxen

Zwei Server A und B verwalten gemeinsam eine Menge von *gesperrten Mailboxen*. Jede Mailbox kann von genau einem Client (dem Besitzer) gelesen werden; jeder Client, der die Mailbox-Adresse kennt, kann hineinschreiben. Die Server halten die Inhalte *additiv secret-geshared*: Server A hält Datenbank D_A ∈ F^n, Server B hält D_B ∈ F^n, sodass D = D_A + D_B (in F^n) die echten Mailbox-Inhalte enthält.

#### Virtuelles Adressierungsschema (wichtig!)

Jede Mailbox erhält eine **128-Bit virtuelle Adresse** (aus dem Adressraum [2^λ], mit λ ≈ 128) sowie eine kleinere physische Adresse (ca. 20 Bit). Die Server führen intern eine Page Table, die virtuelle auf physische Adressen abbildet. Der virtuellen Adressraum (2^128 Einträge) ist astronomisch groß im Vergleich zu den tatsächlich registrierten Mailboxen (~2^20 maximal).

**Konsequenz:** DPFs in EXPRESS operieren über den *virtuellen Adressraum* [2^λ], nicht über die Anzahl physischer Mailboxen n. Das ist der Schlüssel zum konstanten Kommunikations-Overhead.

#### Write-Protokoll (vollständig, aus Originaltext)

Ein Client, der Nachricht m ∈ {0,1}^|m| in die Mailbox mit virtueller Adresse v schreiben will:

**Schritt 1 – DPF-Generierung:**
Der Client generiert ein DPF-Schlüsselpaar (f_A, f_B) für die Punktfunktion f_{v,m}: [2^λ] → {0,1}^|m|, die an Stelle v den Wert m ausgibt und überall sonst 0. Die Schlüssel haben die Größe O(λ² + |m|) Bits (weil die Domäne 2^λ hat, ist die Tiefe des DPF-Baums λ, und jede Ebene kostet λ Bits für den Correction Word).

**Schritt 2 – Übertragung:**
Client sendet f_A an Server A, f_B an Server B.

**Schritt 3 – Server-Evaluation:**
Jeder Server evaluiert seinen DPF-Schlüssel an allen *aktiven virtuellen Adressen* (den physisch registrierten Mailboxen):
- Server A berechnet: w_A ← (f_A(V_1), ..., f_A(V_n))
- Server B berechnet: w_B ← (f_B(V_1), ..., f_B(V_n))

Da der virtuelle Adressraum riesig ist, gilt mit überwältigender Wahrscheinlichkeit: Der Client kennt die korrekte virtuelle Adresse v genau dann, wenn er sie gültig registriert hat.

**Schritt 4 – Datenbankupdate:**
D_A ← D_A + w_A  
D_B ← D_B + w_B

Korrektheit: An jeder Mailbox-Position j gilt w_A[j] + w_B[j] = f_{v,m}(V_j), was m ergibt wenn V_j = v und 0 sonst.

**Schritt 5 – Auditing (Disruption-Schutz):**
Server A und B führen gemeinsam das neue Audit-Protokoll durch (s. Abschnitt 2.2.2 unten), das verifiziert, dass (w_A + w_B) ein Vektor mit Hamming-Gewicht ≤ 1 ist – also höchstens eine Mailbox beschrieben wurde.

**Verschlüsselung:** Jede Mailbox-Position ist unter den Schlüsseln des Besitzers (k_A bei Server A, k_B bei Server B) verschlüsselt gespeichert. Nach jedem Write re-randomisieren die Server die Verschlüsselung, sodass ein Adversary durch Beobachtung aller Mailboxen zwischen zwei Writes *nichts darüber lernt*, welche Mailbox sich verändert hat.

#### Read-Protokoll (wichtige Korrektur gegenüber früheren Notizen)

**EXPRESS VERWENDET KEIN PIR FÜR LESEVORGÄNGE.** Das ist eine fundamentale Eigenschaft des Systems, die im Paper explizit herausgestellt wird:

> *"Express hides which client wrote into which mailbox but does not hide which client read from which mailbox."*

Der Read-Vorgang ist einfach:
1. Mailbox-Besitzer schickt (p, v) – physische Adresse p und virtuelle Adresse v – an Server A und B
2. Server prüfen, dass v ↔ p korrekt ist (Page Table), und senden ihre verschlüsselten Shares D_A[p] und D_B[p] zurück; danach setzen sie den Slot auf verschlüsselte Nullen zurück
3. Besitzer entschlüsselt: m_A + m_B = m

**Die Server sehen also, wer welche Mailbox liest.** Das ist im Whistleblowing-Kontext akzeptabel (der Journalist liest regelmäßig, das verrät nichts Sensitives). Für MetaCTI-Directed bedeutet das jedoch, dass reine Express-Reads keine Leser-Anonymität bieten.

#### 2.2.1 Kommunikationskomplexität (aus Tabelle 2 des Papers)

*Für n physische Mailboxen, Nachrichtengröße |m|, Sicherheitsparameter λ:*

| Partei | Kommunikation | AES-Evaluierungen | Feldoperationen |
|---|---|---|---|
| Client | O(λ² + \|m\|) Bits | O(λ + \|m\|) | O(1) |
| Server | O(λ) Bits | O(n(λ + \|m\|)) | O(n) |

**Konkrete Zahlen aus dem Paper (für 2^14 ≈ 16.000 Mailboxen, 160-Byte-Nachrichten):**
- Server-Kommunikation: 8,34 KB pro Write
- Client-Kommunikation: 5,39 KB pro Write
- Client-Rechenzeit: ~20 ms (C/Go), ~51 ms (JavaScript)
- Audit-Rechenzeit Client: < 5 Mikrosekunden (O(1), unabhängig von n!)

**Für 1 Million Mailboxen (2^20):** 101× weniger Client-Kommunikation als RIPOSTE, 195× weniger Server-Kommunikation.

#### 2.2.2 Das neue Audit-Protokoll

Das ist eine zentrale Contribution von EXPRESS gegenüber RIPOSTE. EXPRESS verwendet *Secret-shared Non-Interactive Proofs* (SNIPs), basierend auf Boyle et al. [CCS 2019], um zu prüfen, ob (w_A + w_B) Hamming-Gewicht ≤ 1 hat.

Das zu prüfende Polynom ist:
f(r_1,...,r_n) = (Σᵢ wᵢ rᵢ)² − m · (Σᵢ wᵢ rᵢ²)

Dieses Polynom ist genau dann null (über zufällige r_i), wenn (1) höchstens ein w_i ≠ 0 ist und (2) m = w_{i*} für den nichtnullen Eintrag i* ist.

**Protokollablauf:**
1. Server generieren gemeinsamen Zufall r (via shared Seed) und schicken r an Client
2. Server berechnen ihre Anteile von m_A, m_B (Summe der w-Einträge) und der Check-Werte c_A, c_B, C_A, C_B via innere Produkte
3. Client berechnet Check-Werte c*, C* und konstruiert SNIP-Beweis π = (π_A, π_B)
4. Client sendet π_A an Server A, π_B an Server B
5. Server verifizieren den Beweis (kommunizieren miteinander: 2 Multiplikationen: c·c und m·C)
6. Wenn gültig: Datenbankupdate; sonst: Anfrage verwerfen

**Eigenschaften:**
- *Completeness:* Wenn alle ehrlich, Audit akzeptiert immer
- *Soundness gegen malicious Clients:* Wenn w kein gültiger Write ist und beide Server ehrlich, lehnt Audit mit überwältigender Wahrscheinlichkeit ab
- *Zero-Knowledge gegen malicious Server:* Ein aktiv malicious Server lernt durch das SNIP-Protokoll nichts über den Write-Request w über die Tatsache hinaus, dass er gültig ist

**Kosten:** O(λ) Kommunikation zwischen Parteien (konstant!), O(1) Client-Arbeit, O(n) Server-Arbeit (DPF-Evaluation dominiert ohnehin).

#### 2.2.3 Cover Traffic und Plausible Deniability

Express muss *Cover Traffic* einsetzen, damit Server (und Netzwerk-Observer) nicht erkennen, welche Clients gerade real kommunizieren. Andernfalls würde allein die Tatsache, dass ein Client gerade eine Schreibanfrage stellt, verraten, dass er etwas mitteilen will.

**Wichtiger Unterschied zu RIPOSTE:** Express erfordert *keine synchronisierten Runden*. Cover Traffic muss nicht von jedem Teilnehmer selbst erzeugt werden. Das Paper schlägt vor, Cover Traffic durch **JavaScript-Clients auf kooperativen News-Websites** zu erzeugen: Besucher der Website des Journalisten generieren automatisch im Hintergrund fake Schreibanfragen an das Express-System. Diese sind aus Sicht der Server ununterscheidbar von echten Anfragen.

**Kosten eines Cover-Traffic-Writes (= Dummy-Write):** Identisch zu einem echten Write: O(λ² + |m|). Um ununterscheidbar zu sein, muss jede Dummy-Anfrage dieselbe Nachrichtengröße |m| verwenden wie echte Anfragen. Ein Dummy-Write schreibt in eine zufällige (nicht-existierende oder eigens dafür reservierte) Dummy-Adresse.

**Für MetaCTI:** Cover Traffic kann zentral durch den ISAC selbst oder durch eine kooperative dritte Partei generiert werden. ISAC-Mitglieder müssen nicht selbst kontinuierlich Dummy-Writes senden. Dies ist eine wesentliche operative Erleichterung gegenüber RIPOSTE.

#### 2.2.4 Sicherheitsmodell

- **Adversary:** Kontrolliert beliebig viele malicious Clients und bis zu einen malicious Server (von zweien)
- **Metadata-hiding:** Ein Adversary, der einen Server kontrolliert und das gesamte Netzwerk überwacht, lernt nichts darüber, welche Mailbox ein Write-Request beschreibt, es sei denn, er kontrolliert die Ziel-Mailbox selbst
- **Soundness:** Kein malicious Client kann eine Mailbox beschreiben, für die er keine gültige Adresse kennt
- **Nicht geschützt:** Wer welche Mailbox *liest* (explizit kein Ziel von Express)

---

### 2.3 Korrekturen gegenüber früheren Notizen

Beim Lesen des Originalpapers haben sich folgende Fehler in meinen früheren Darstellungen herausgestellt. Diese sind wichtig, damit das Paper korrekte Aussagen macht:

**Korrektur 1 – DPF-Domäne und Schlüsselgröße:**
*Früher:* DPF-Schlüsselgröße = O(λ · log n + |m|), wobei n = Anzahl Mailboxen  
*Korrekt:* DPF-Schlüsselgröße = O(λ² + |m|), weil die DPF-Domäne der virtuelle Adressraum [2^λ] ist (Tiefe = λ, nicht log n)

Für λ = 128: λ² = 16.384 Bit = 2.048 Bytes = 2 KB Overhead pro Schlüssel, 4 KB für beide. Die Kommunikationskosten sind **unabhängig von der Anzahl registrierter Mailboxen n**. Das ist der eigentliche Grund für die Skalierbarkeit.

**Korrektur 2 – PIR für Lesevorgänge:**
*Früher:* Express verwendet DPF-basiertes PIR für Lesevorgänge im Directed-Modus  
*Korrekt:* Express verwendet **kein PIR** für Lesevorgänge. Lesen ist explizit nicht privat – die Server sehen, wer welche Mailbox liest. Das ist eine bewusste Designentscheidung.

**Konsequenz für MetaCTI:** Die ursprünglich geplante „Directed-Modus mit PIR"-Architektur basierte auf einer falschen Annahme. Für Leser-Anonymität brauchen wir einen anderen Ansatz (s. Abschnitt 4.2).

**Korrektur 3 – Schreibkosten-Formel:**
*Früher:* „2 × M" pro Write  
*Korrekt:* „2 × (λ² + |m|)" = ca. 4 KB + 2|m| pro Write. Der 4-KB-Overhead ist für kleine Nachrichten (< 4 KB) dominant. Für STIX-Objekte ab ~10 KB ist er vernachlässigbar (<20%).

**Korrektur 4 – Dummy-Traffic-Pflicht:**
*Früher:* Jeder Teilnehmer muss in jeder Round einen Dummy-Write senden  
*Korrekt:* Express erfordert keine synchronisierten Runden. Cover Traffic kann von Dritten (oder zentral) generiert werden. Teilnehmer müssen nicht selbst kontinuierlich Dummy-Writes erzeugen.

---

### 2.4 Eskandarians Abuse-Reporting-Paper (USENIX Security 2024)

Erweitert Express und ähnliche Metadata-Hiding-Systeme um Abuse Reporting. Das Paper adressiert das Problem, dass bei vollständiger Sender-Anonymität kein Mechanismus existiert, um Missbrauch (z.B. Spam, illegale Inhalte) zu melden.

**Kernidee:** Beim Schreiben einer Nachricht wird ein kryptografischer Nachweis (basierend auf Secret Sharing) mitgeschickt, der im Missbrauchsfall von Empfänger und Servern gemeinsam zur Deanonymisierung verwendet werden kann. Im Normalfall bleibt die Anonymität vollständig erhalten.

**Relevanz für MetaCTI (C3a):** Dieses Protokoll löst das False-Positive/Poisoning-Problem – ein Angreifer, der unter dem Schutz der Anonymität vergiftete IOCs einschleust, kann nach Missbrauchsmeldung deanonymisiert werden, ohne dass der Schutzmechanismus für alle anderen Teilnehmer bricht.

---

## 2a. Formales Bedrohungsmodell (Contribution C1)

*Dieser Abschnitt ist als Grundlage für den Threat-Model-Abschnitt des Papers konzipiert. Alle Definitionen und Spiele sind als Ausgangspunkt zu verstehen – vor Einreichung ist eine formale Überprüfung durch einen Kryptographen empfohlen.*

---

### 2a.1 Systemmodell

#### Teilnehmer

Sei $\lambda \in \mathbb{N}$ der Sicherheitsparameter. Das MetaCTI-System besteht aus folgenden Parteien:

- **ISAC-Teilnehmer** $\mathcal{P} = \{P_1, \ldots, P_n\}$: Organisationen (Unternehmen, Behörden, CERTs), die CTI teilen und empfangen. Jede Partei $P_i$ ist bei beiden Servern registriert und hat eine öffentlich bekannte Identität (z.B. X.509-Zertifikat) – Registrierung ≠ Offenlegung der Submission-Aktivität.

- **Server $S_1$, $S_2$**: Zwei unabhängig betriebene Server, die gemeinsam die Write-Private-Datenbank verwalten. Sie teilen (per Annahme) keine Informationen miteinander. Praktisch realisierbar durch getrennte juristische Jurisdiktionen, z.B. ISAC als $S_1$, ein neutrales Sicherheitsforschungsinstitut als $S_2$.

- **Cover-Traffic-Dienst $\mathcal{CT}$**: Eine dritte Instanz (oder der ISAC-Betreiber selbst), die synthetische Dummy-Writes erzeugt. $\mathcal{CT}$ ist nicht der Adversary; ihre Dummy-Writes sind protokollkonforme, wohlgeformte Schreiboperationen auf zufällige virtuelle Adressen.

#### Kommunikationsmodell

- Alle Parteien kommunizieren über authentifizierte, verschlüsselte Kanäle (Punkt-zu-Punkt-TLS). Der Netzwerkinhalt ist für externe Beobachter unlesbar.
- Die nach jedem Batch publizierte Datenbank $\mathsf{DB}_e$ (Epoch $e$) ist öffentlich zugänglich.
- Der Adversary $\mathcal{A}$ kontrolliert das Netzwerk: er sieht alle Ciphertexte, Zeitstempel und Nachrichtengrößen auf allen Verbindungen (globaler passiver Beobachter). Er kann Nachrichten verzögern oder neu ordnen, aber nicht entschlüsseln.

#### Ausführungsmodell (Epoch-basiert)

MetaCTI operiert in Batches (Epochen). In Epoch $e$:

1. Teilnehmer $P_i$, die schreiben möchten, senden ihre DPF-Key-Shares $(k_i^{(1)}, k_i^{(2)})$ an $S_1$ bzw. $S_2$.
2. Der Cover-Traffic-Dienst $\mathcal{CT}$ sendet $c$ Dummy-Writes (ebenfalls als wohlgeformte DPF-Key-Paare), sodass die Gesamtzahl der Writes pro Epoch $w_e = |\{$echte Writes$\}| + c$ beträgt. Der Parameter $c$ ist öffentlich; er sorgt für ein konstantes (oder randomisiertes) Batch-Volumen.
3. Server $S_1$ und $S_2$ verarbeiten die Writes gemeinsam via SNIP-Audit (Wohlgeformtheitsprüfung) und akkumulieren die Datenbank.
4. $\mathsf{DB}_e$ wird veröffentlicht.

---

### 2a.2 Angriffsmodell

#### Adversary-Klassen

Wir betrachten drei orthogonale Adversary-Typen, die in MetaCTI relevant sind:

**Typ I – Korrumpierter Server (Semi-Honest):**
$\mathcal{A}_{\mathsf{SH}}$ korrumpiert genau einen der beiden Server, z.B. $S_1$. Er beobachtet alle eingehenden Shares $\{k_i^{(1)}\}$ an $S_1$ sowie alle Netzwerkmeta­daten (Zeitstempel, IP-Adressen der Verbindungen). Er folgt dem Protokoll korrekt, versucht aber, aus seiner Ansicht auf die Identität des Schreibers zu schließen.

*Begründung für Semi-Honest-Modell für Server:* Das Zwei-Server-Modell ist in der Praxis durch separate juristische Entitäten abgesichert. Ein Server, der aktiv vom Protokoll abweicht (z.B. manipulierte Datenbank veröffentlicht), ist für andere Teilnehmer detektierbar. Ein semi-honest korrumpierter Server ist das realistischere und härtere Angriffsziel für Anonymitäts­verletzungen.

**Typ II – Maliciöser Teilnehmer:**
$\mathcal{A}_{\mathsf{Mal}}$ korrumpiert eine Teilmenge $\mathcal{C} \subseteq \mathcal{P}$ von Teilnehmern (adaptiv, vor und während der Ausführung). Er kann:
- Protokollabweichungen vornehmen: mehrfache Writes pro Epoch, Writes an nicht-registrierte Mailboxes, Schreiben von Garbage-Daten.
- Andere Teilnehmer als Empfänger beobachten (welche Mailboxes werden gelesen?).
- Strategische "Probe"-Nachrichten einspeisen, um Reaktionen anderer Teilnehmer zu beobachten.

$\mathcal{A}_{\mathsf{Mal}}$ **kann nicht** gleichzeitig einen Server korrumpieren (Hybrid-Modell wäre stärker, aber unser Basis-Sicherheitsmodell erlaubt Korruption eines Servers **oder** einer Teilnehmergruppe, nicht beides).

**Typ III – Passiver Netzwerk-Beobachter:**
$\mathcal{A}_{\mathsf{Net}}$ kontrolliert das Netzwerk vollständig: sieht alle Ciphertexte, alle Verbindungen, alle Zeitstempel. Er ist computationell beschränkt (PPT). Er kann insbesondere Timing-Korrelationsangriffe versuchen: Korrelation zwischen dem Sendezeitpunkt eines Writes von $P_i$ und dem Erscheinen eines neuen Slots in $\mathsf{DB}_e$.

*Hinweis:* $\mathcal{A}_{\mathsf{Net}}$ ist der relevanteste Adversary für die operationelle Praxis – er entspricht einem Angreifer auf Netzwerkebene (z.B. ISP, staatlicher Akteur mit Netzwerkzugang).

#### Korrektionsmodell

Wir definieren eine Korrumpiertheitsmenge $\mathsf{Cor} = (\mathsf{Cor}_S, \mathsf{Cor}_P)$ mit:
- $\mathsf{Cor}_S \subseteq \{S_1, S_2\}$, $|\mathsf{Cor}_S| \leq 1$ (höchstens ein Server korrumpiert)
- $\mathsf{Cor}_P \subseteq \mathcal{P}$, $|\mathsf{Cor}_P| \leq n-2$ (mindestens zwei ehrliche Teilnehmer bleiben)

Die Grundannahme lautet: **$S_1$ und $S_2$ kolludieren nicht** – d.h. für alle PPT-Adversaries gilt, dass die gemeinsame Information von $S_1$ und $S_2$ nicht mehr ist als die Summe ihrer individuellen Ansichten (formalisiert durch das Non-Collusion-Assumption, NCA).

---

### 2a.3 Sicherheitseigenschaften und formale Definitionen

#### Eigenschaft 1: Schreiber-Anonymität (Write Anonymity, WA)

Schreiber-Anonymität besagt, dass kein Adversary $\mathcal{A}$ mit $|\mathsf{Cor}_S| \leq 1$ bestimmen kann, welcher ehrliche Teilnehmer eine gegebene Nachricht $m^*$ geschrieben hat – selbst wenn er alle Netzwerkmetadaten und die Ansicht eines korrumpierten Servers sieht.

**Formales Indistinguishability-Spiel IND-WA$(\lambda)$:**

```
Setup:
  - Challenger C führt MetaCTI.Setup(1^λ) aus.
  - C publiziert die öffentlichen Parameter.
  - A wählt eine Korrumpiertheitsmenge: einen Server S_b ∈ {S_1, S_2} und
    eine Teilnehmermenge Cor_P ⊆ P; C gibt A die korrespondierenden
    geheimen Zustände der korrumpierten Parteien.

Query-Phase (beliebig oft):
  - A darf Write-Orakelanfragen für beliebige (P_i, m) stellen;
    C führt die entsprechenden Protokollschritte aus und gibt A
    die resultierende Netzwerksicht (Ciphertexte, Zeitstempel).
  - A darf DB_e für beliebige Epochen e abrufen.

Challenge:
  - A wählt (m*, P_i*, P_j*) mit P_i*, P_j* ∉ Cor_P.
  - C wählt b ←_R {0, 1}.
  - C führt MetaCTI.Write(P_{(b=0: i*, b=1: j*}}, m*) aus.
  - C gibt A die resultierende Netzwerksicht für diese Write-Operation.

Guess-Phase:
  - A gibt b' aus.

A gewinnt, wenn b' = b.
Vorteil: Adv^{IND-WA}_A(λ) = |Pr[b' = b] - 1/2|
```

**Definition (Schreiber-Anonymität):** MetaCTI ist *schreiber-anonym* (write-anonym), wenn für alle PPT-Adversaries $\mathcal{A}$ gilt:
$$\mathsf{Adv}^{\mathsf{IND\text{-}WA}}_{\mathcal{A}}(\lambda) \leq \mathsf{negl}(\lambda)$$

*Beziehung zur EXPRESS-Sicherheit:* Die Write-Anonymität von MetaCTI erbt direkt aus der Write-Privacy von EXPRESS (Eskandarian et al., Theorem 1), sofern die CTI-spezifischen Erweiterungen (Chunking, Dual-Mode) keine zusätzliche Information über den Schreiber preisgeben. Der formale Beweis für die Erweiterungen ist Teil von Contribution C2d.

*Hinweis zum IND-WA-Spiel:* Das Spiel verlangt, dass beide Challenge-Sender $P_i^*$, $P_j^*$ ehrlich sind. Wenn $P_i^*$ korrumpiert ist, trivialerweise weiß $\mathcal{A}$ ob $P_i^*$ oder $P_j^*$ geschrieben hat. Das Spiel modelliert daher Sender-Anonymität innerhalb des Anonymitäts-Sets der ehrlichen Teilnehmer.

---

#### Eigenschaft 2: Epochen-Unlinkability (Epoch Unlinkability, EU)

Unlinkability besagt, dass kein Adversary Writes aus verschiedenen Epochen demselben Absender zuordnen kann – selbst wenn er alle Netzwerkdaten beobachtet. Dies ist stärker als bloße Schreiber-Anonymität, da es auch verhindert, dass ein Angreifer über Zeit ein Aktivitätsprofil einer Organisation aufbaut.

**Formales Spiel IND-EU$(\lambda)$:**

```
Setup: Identisch zu IND-WA.

Query-Phase: A stellt beliebig viele Write-Anfragen.

Challenge:
  - A wählt vier Tupel (m_0, P_i, m_1, P_j) mit P_i, P_j ∉ Cor_P.
  - C wählt b ←_R {0, 1}.
  - Fall b=0 (gleicher Sender):
      C führt MetaCTI.Write(P_i, m_0) in Epoch e_1 aus.
      C führt MetaCTI.Write(P_i, m_1) in Epoch e_2 > e_1 aus.
  - Fall b=1 (verschiedene Sender):
      C führt MetaCTI.Write(P_i, m_0) in Epoch e_1 aus.
      C führt MetaCTI.Write(P_j, m_1) in Epoch e_2 > e_1 aus.
  - C gibt A die Netzwerksicht beider Write-Operationen.

Guess-Phase: A gibt b' aus.

Vorteil: Adv^{IND-EU}_A(λ) = |Pr[b' = b] - 1/2|
```

**Definition (Epochen-Unlinkability):** MetaCTI ist *epochen-unverknüpfbar*, wenn für alle PPT-Adversaries $\mathcal{A}$ gilt:
$$\mathsf{Adv}^{\mathsf{IND\text{-}EU}}_{\mathcal{A}}(\lambda) \leq \mathsf{negl}(\lambda)$$

*Designbedingung:* Epochen-Unlinkability ist genau dann erfüllbar, wenn die virtuellen Adressen für verschiedene Writes unabhängig und frisch aus dem Adressraum $\{0,1\}^\lambda$ gezogen werden. In EXPRESS gilt dies per Konstruktion – die DPF-Funktion wird für jeden Write auf einer neu gesampleten Adresse $\alpha \xleftarrow{R} \{0,1\}^\lambda$ ausgewertet. Für MetaCTI erbt diese Eigenschaft direkt, sofern keine schreiberabhängige Adresswahl stattfindet.

*Schwächeres Pendant – k-Anonymität:* Die in der CTI-Literatur verwendete k-Anonymität (z.B. in Huff et al. 2024) ist strikt schwächer: Sie garantiert nur, dass der Schreiber in einer Menge von ≥k Verdächtigen liegt, sagt aber nichts über die Stärke dieser Unterscheidung oder über Unlinkability zwischen Epochen aus. IND-WA und IND-EU sind computationell-sichere Begriffe, nicht informationstheoretisch, aber unter kryptografischen Standardannahmen (PRF, DPF-Sicherheit) haltbar.

---

#### Eigenschaft 3: Batch-Volumen-Indistinguishabilität (Volume Hiding, VH)

Volume Hiding besagt, dass ein passiver Beobachter aus der Batch-Größe $w_e$ nicht auf die Anzahl echter (nicht-Cover-)Writes $r_e \leq w_e$ schließen kann.

**Informelles Spiel IND-VH$(\lambda)$:**

```
Challenge:
  - A wählt zwei verschiedene Submitter-Mengen R_0, R_1 ⊆ P
    mit |R_0| ≠ |R_1| (unterschiedliche Anzahl echter Writes).
  - C wählt b ←_R {0, 1}.
  - C führt eine Epoch mit echter Writes von R_b durch;
    Cover-Traffic-Dienst CT füllt auf w_e = |R_b| + c auf.
  - A sieht die Batch-Netzwerksicht (Gesamtzahl Pakete, Größen, Zeitstempel).

A gewinnt, wenn er korrekt auf |R_0| vs. |R_1| schließen kann.
```

**Bedingung für VH:** Batch-Volumen-Indistinguishabilität ist erfüllt, wenn das Gesamtbatch-Volumen $w_e$ unabhängig von $r_e$ konstant (oder aus einer öffentlich bekannten Verteilung) ist. Die Cover-Traffic-Rate $c$ muss daher so kalibriert sein, dass $w_e = r_{\max} + c$ oder $w_e$ ist eine öffentlich festgelegte Konstante.

*Praktische Konsequenz:* Falls $c$ zu klein gewählt wird und die Server-Logs zeigen Spitzen im Batch-Volumen zu Zeitpunkten mit bekannten Sicherheitsvorfällen, kann ein Angreifer durch statistische Korrelation Rückschlüsse ziehen. Die Wahl von $c$ ist ein sicherheitsrelevanter Parameter, der mit der erwarteten maximalen echten Write-Rate kalibriert werden muss.

---

#### Eigenschaft 4: Write-Integrität (Write Integrity, WI)

Write-Integrität besagt, dass kein Teilnehmer – auch nicht ein maliciöser – die Datenbank korrumpieren kann: Er kann nicht in mehr als eine Mailbox pro Epoch schreiben, keine anderen Teilnehmer überschreiben, und keine Garbage-Daten einschleusen, die nicht die Struktur wohlgeformter DPF-Keys haben.

**Informelle Definition:** Für alle PPT-Adversaries $\mathcal{A}_{\mathsf{Mal}}$ ist die Wahrscheinlichkeit, dass $\mathcal{A}_{\mathsf{Mal}}$ einen Write erzeugt, der den SNIP-Audit besteht, aber (a) in mehr als eine Mailbox schreibt oder (b) eine Mailbox $j$ schreibt, ohne für $j$ registriert zu sein, vernachlässigbar in $\lambda$.

*Grundlage:* Diese Eigenschaft erbt direkt aus dem SNIP-Protokoll (Express, §4). Der Nachweis verwendet die Bindungseigenschaft des zugrundeliegenden Commitment-Schemas und die Korrektheit des Secret-Shared Proofs.

*Relevanz für MetaCTI:* Write-Integrität ist die kryptografische Grundlage für Contribution C3 (Anti-Poisoning). Ohne WI könnte ein Angreifer unter dem Schutz der Anonymität unbegrenzt Garbage oder False-Positive-IOCs einschleusen. WI schränkt jede Submission auf eine wohlgeformte, einmalige Schreiboperation pro Epoch ein – ohne die Anonymität des Schreibers preiszugeben.

---

### 2a.4 Was das Modell explizit nicht schützt

Wissenschaftliche Sauberkeit erfordert, die Grenzen des Modells präzise zu benennen. Die folgenden Eigenschaften sind **nicht** Teil der MetaCTI-Sicherheitszusagen (zumindest nicht in der Basis-Version):

**Leser-Anonymität (Read Anonymity):**
EXPRESS verbirgt nur Writes, nicht Reads. Ein Angreifer – insbesondere ein korrumpierter Server oder Netzwerkbeobachter – kann sehen, welche Clients auf welche Mailboxen zugreifen. MetaCTI adressiert dies durch den uniformen DB-Download (alle Clients laden alle Slots, entschlüsseln lokal), was Leser-Anonymität durch ein uniformes Zugangsmuster approximiert. Eine formale Leser-Anonymitätsgarantie (vergleichbar mit IND-WA) bleibt ein offenes Problem (→ Forschungsfrage C2d).

**Forward Secrecy bei Server-Kompromittierung:**
Falls nachträglich beide Server korrumpiert werden (oder die Non-Collusion-Assumption verletzt wird), können historische Shares rekombiniert werden. Schutzmaßnahmen (z.B. Deletion der Shares nach Epochen-Abschluss, regelmäßiger Server-Key-Rotation) sind operationell, nicht protokollseitig.

**Inhaltliche Validität der CTI:**
MetaCTI schützt Metadaten, nicht Semantik. Ein Teilnehmer kann (innerhalb der WI-Grenzen) valide STIX-formatierte, aber inhaltlich falsche IOCs einschleusen. Dies wird durch C3 (Abuse Reporting + ZKP-Membership) adressiert, ist aber keine protokollinhärente Eigenschaft.

**Anonymität gegenüber dem ISAC als Membership-Verifier:**
Teilnehmer müssen sich zur Teilnahme registrieren. Die Tatsache der ISAC-Mitgliedschaft ist damit nicht anonym. MetaCTI schützt nur die Submission-Aktivität (was, wann, an wen geschrieben wurde), nicht die Mitgliedschaft an sich.

**Schutz gegen Traffic-Analyse auf Infrastrukturebene:**
Falls ein Angreifer beide Server kontrolliert **und** den Netzwerkverkehr beobachtet, kann er möglicherweise durch Timing-Korrelation zwischen eingehenden Client-Verbindungen und Batch-Inhalten Rückschlüsse ziehen. Dies ist das klassische Intersection-Attack-Problem im anonymen Kommunikationsbereich und erfordert Techniken jenseits von Express (z.B. Mix-Nets). MetaCTI erbt diese Schwäche von EXPRESS und dokumentiert sie explizit als Grenze.

---

### 2a.5 Einordnung in bestehende Sicherheitsbegriffe

| Begriff | Stärke | Verhältnis zu MetaCTI |
|---|---|---|
| k-Anonymität | Schwach (informatik-theoretisch) | MetaCTI ist stärker: computationell sichere IND-WA-Garantie |
| Tor-Anonymität | Mittel (heuristisch) | MetaCTI ist formal stärker, aber auf 2-Server-Modell beschränkt |
| DC-Net-Anonymität | Stark (informationstheoretisch) | Informationstheoretisch stärker, aber keine Abuse Prevention; MetaCTI ist gegen aktive Angreifer robuster |
| Express Write-Privacy | Äquivalent (für Basis-Writes) | MetaCTI erbt und erweitert diese Garantie auf CTI-spezifische Protokollmerkmale |
| Sender-Untraceability (Chaum) | Formal ähnlich | IND-WA entspricht dem Mix-Net-Anonymitätsbegriff, aber ohne Mix-Net-Overhead |

---

### 2a.6 Vertrauensannahmen zusammengefasst (Trust Model Summary)

Für das Paper klar zu dokumentieren:

1. **Non-Collusion-Assumption (NCA):** $S_1$ und $S_2$ teilen keine Information. *Praktisch gesichert durch:* getrennte juristische Entitäten, ggf. verschiedene Länder (Jurisdiktionsdiversität).

2. **PRF-Sicherheit:** Die dem DPF zugrundeliegende Pseudorandom Function (PRF) ist sicher unter der Standard-Annahme ($\mathsf{PRF}$ secure gegen PPT-Adversaries). *Standardannahme in der Kryptographie.*

3. **DPF-Sicherheit:** Die Distributed Point Function ist computationell sicher (folgt aus PRF-Sicherheit, siehe Boyle et al. 2016). *Direkt aus der DPF-Literatur.*

4. **SNIP-Korrektheit und -Soundness:** Das SNIP-Audit-Protokoll weist keine False Positives auf (wohlgeformte Writes bestehen immer) und hat vernachlässigbare False Negatives (maliciöse Writes werden mit Wahrscheinlichkeit $1 - \mathsf{negl}(\lambda)$ abgelehnt). *Aus dem Express-Paper, §4.*

5. **Authentizität der Registrierung:** Die Registrierungsphase (Teilnehmer registriert virtuelle Adresse) ist durch die ISAC-Mitgliedschaft authentifiziert (z.B. via PKI/X.509). Ein Angreifer kann keine fremden Mailboxen registrieren.

---

### 2a.7 Offene Formalierungsfragen (für C1 im Paper)

Folgende Punkte müssen vor der finalen Paperversion formal geklärt werden:

1. **Kompositionssicherheit:** Ist MetaCTI sicher, wenn Write-Anonymität, Unlinkability und Volume Hiding gleichzeitig gelten müssen? Oder erzeugt die Kombination neue Angriffsvektoren? (Hinweis: Kompositionssicherheit ist in der anonymen Kommunikation nicht selbstverständlich.)

2. **Adaptivität des IND-WA-Spiels:** Das skizzierte Spiel erlaubt nur eine Challenge-Phase. Ein stärkeres Modell erlaubt adaptive Challenges über mehrere Epochen. Gilt IND-WA auch für adaptive Adversaries ohne Einbußen?

3. **Sicherheitsreduktion auf DPF:** Die Write-Anonymität muss formal auf die DPF-Sicherheit reduziert werden. Der Beweis in Express (Theorem 1) liefert die Basis; für MetaCTI muss er auf die CTI-Erweiterungen ausgedehnt werden.

4. **Anonymitätsmenge bei Streaming-Writes:** Im Chunking-Modus schreibt ein Client in mehreren aufeinanderfolgenden Epochen. Bleibt IND-EU erhalten, wenn für denselben logischen Write-Vorgang mehrere Epochen-Writes notwendig sind? (Intuition: ja, wenn die Chunk-Adressen unabhängig gezogen werden – formaler Beweis steht aus.)

---

*Ende Abschnitt 2a – Bedrohungsmodell*

---

## 3. Wichtige Designentscheidung: DC-Netz-Hybrid wurde verworfen

### 3.1 Die Idee

Überlegung: Könnte man EXPRESS nur für die Verifikation (Nachweis, dass ein Client wohlgeformt schreibt) nutzen, den eigentlichen Datentransfer aber über ein effizienteres Plain-DC-Netz abwickeln?

Motivation: DC-Netze haben keinen Server-Bottleneck (Peer-to-Peer) und geringere Sendekosten (M statt 2M pro Client).

### 3.2 Warum der Ansatz verworfen wurde

**Technisch:** Die Verifikation in EXPRESS funktioniert genau deshalb, weil die Server die Shares halten und deren algebraische Struktur prüfen. In einem Plain-DC-Netz gibt es niemanden, der die Shares hält – die Verifikation müsste vor dem Datentransfer stattfinden (Phase 1: Commitment via EXPRESS, Phase 2: DC-Netz-Broadcast), was die Kommunikation nicht reduziert sondern erhöht. Der Nettovorteil ist minimal.

**Existierende Arbeit:** Dieser Ansatz ist als "Accountable/Verifiable DC-nets" bekannt (Dissent, Corrigan-Gibbs & Ford, CCS 2010). Dissent wurde von denselben Autoren wie RIPOSTE entwickelt und war der Vorgänger – RIPOSTE war die Antwort auf Dissents Performance-Probleme.

**Bandbreitenanalyse:** Der Spar-Effekt (M statt 2M senden) ist real, aber:
- Empfangskosten sind in beiden Systemen identisch: O(N × M)
- Die Verifikationsphase im Hybrid kostet zusätzlich
- DC-Netze erfordern striktere Synchronisierung und alle-zu-alle Konnektivität

**Fazit:** Für CTI-Sharing in ISAC-Settings (Firewall-Policies, keine echte P2P-Konnektivität, seltene malicious participants) ist EXPRESS einfacher, bewiesener und besser geeignet. DC-Netz-Hybrid könnte als Variante erwähnt werden, aber nicht als primärer Ansatz.

---

## 4. Schlüsselerkenntnis: Dual-Mode-Architektur

### 4.1 Die Einsicht

In CTI-Sharing gibt es zwei grundlegend verschiedene Sharing-Muster:

**Broadcast-Modus (TLP:WHITE, TLP:GREEN):** Jede Information soll alle Teilnehmer erreichen. Hier ist *Leser-Anonymität kein Ziel* – jeder soll ja alles wissen. Was geschützt werden muss: nur die Sender-Anonymität.

**Directed-Modus (TLP:AMBER, TLP:RED):** Information geht nur an ausgewählte Empfänger. Hier ist zusätzlich relevant, wer welche Information abruft (Leser-Anonymität).

### 4.2 Konsequenz für PIR

Im Broadcast-Modus braucht man **überhaupt kein PIR**. Die Datenbank kann nach jeder Round öffentlich heruntergeladen werden. Das:
- Eliminiert den rechenintensivsten Teil von EXPRESS (O(N×M) Server-Compute pro PIR)
- Vereinfacht das Protokoll erheblich
- Verändert die Performance-Charakteristik fundamental

Im Directed-Modus bleibt PIR notwendig, um zu verbergen, wer welche Mailbox liest.

### 4.3 Architekturkonsequenz

MetaCTI implementiert zwei Modi:

**MetaCTI-Broadcast:** Anonymer Write via EXPRESS (2-Server-Secret-Sharing), öffentlicher DB-Download. Kein PIR. Optimiert für das Gros des operativen CTI-Sharings.

**MetaCTI-Directed:** Vollständiges EXPRESS-Protokoll inkl. PIR. Für TLP:AMBER-Sharing wo auch Leser-Anonymität gefordert ist.

Das ist eine wichtige Differenzierung, die im Paper explizit herausgearbeitet werden sollte – kein bisheriges System macht diese Unterscheidung formell.

---

## 5. Bandbreiten- und Performanceanalyse

**Alle Zahlen sind Schätzungen zur Orientierung und müssen durch Benchmarks verifiziert werden. Empirische Messungen aus dem Express-Paper (Table 2, Section 7) sind als solche markiert.**

*Wichtige Korrekturen gegenüber früheren Notizen: (a) Write-Kosten sind nicht „2×M", sondern „4 KB + 2|m|" wegen DPF-Overhead. (b) Cover-Traffic muss nicht von ISAC-Mitgliedern erzeugt werden – er kann third-party oder vom ISAC-Betreiber generiert werden. (c) Express hat kein PIR für Reads; die alten Berechnungen für einen „Directed-Modus mit PIR" sind gestrichen.*

---

### 5.1 Tatsächliche Write-Kosten: DPF-Overhead

Die korrekte Write-Kostformel für Express ist:

```
Write-Kosten (pro Client, pro Write) = 2 × |DPF-Key| = 2 × (O(λ² + |m|))
```

Bei λ = 128 Bit und typischen STIX-Nachrichtengrößen:

- **DPF-Strukturkosten (unabhängig von |m|):** λ² Bits = 128² Bit = 16.384 Bit ≈ **2 KB** pro Key → **4 KB gesamt** (zwei Keys)
- **Nachrichtenanteil:** 2 × |m| (je ein Share pro Server)

**Konsequenz:** Für kleine Nachrichten (|m| < 4 KB) dominiert der DPF-Overhead. Für |m| = 10 KB sind die Gesamtkosten:

```
4 KB + 2 × 10 KB = 24 KB pro Write
```

Frühere Schätzung „2×M = 20 KB" unterschätzte die Kosten um ~20% für kleine Nachrichten. Für |m| ≥ 32 KB ist der 4 KB-Anteil ≤ 12% und vernachlässigbar.

**Empirische Referenz (Express-Paper, Table 2):**
- Bei |m| = 1 KB: Gesamte Client-Write-Zeit ≈ 0,13 ms; Kommunikation ≈ 4,1 KB (beide Server zusammen)
- Bei |m| = 10 KB: Gesamte Client-Write-Zeit ≈ 0,20 ms; Kommunikation ≈ 24 KB
- Bei |m| = 100 KB: Gesamte Client-Write-Zeit ≈ 0,75 ms; Kommunikation ≈ 204 KB

Diese Zahlen gelten auf einem einzelnen Rechner (Localhost-Experiment); Netzwerk-RTT kommt noch hinzu. Der Client-seitige Compute-Overhead ist in allen Fällen vernachlässigbar (< 1 ms).

---

### 5.2 Cover Traffic: Modell und tatsächlicher Overhead

**Korrigiertes Modell (nach Lektüre des Express-Papers):**

Express ist *asynchron* – es gibt keine synchronisierten Runden im Sinne von Riposte. Cover-Traffic muss vorhanden sein, um Timing-Korrelation zu verhindern, aber er muss nicht von den ISAC-Mitgliedern selbst erzeugt werden.

Express schlägt explizit vor, dass Cover-Traffic von Drittparteien generiert werden kann (§6.1: „cover traffic can be generated by a third party... clients in our system do not need to generate their own cover traffic"). Im CTI-Kontext bedeutet das:

- Der ISAC-Betreiber (oder ein dedizierter Cover-Traffic-Dienst) kann kontinuierlich synthetische Dummy-Writes erzeugen
- ISAC-Mitglieder schreiben *nur*, wenn sie etwas zu teilen haben (kein Zwang zum Dummy-Write)
- Aus Server-Sicht sind alle Writes ununterscheidbar (Cover-Writes und echte Writes haben identisches Format)

**Konsequenz für Overhead-Berechnung:**

Die Sendekosten für ISAC-Mitglieder sind nur die Kosten für *echte* Writes, nicht für Dummy-Writes. Das reduziert den Bandwidth-Overhead für seltene Sender erheblich gegenüber Riposte.

Der Cover-Traffic-Overhead fällt beim ISAC-Betreiber (oder Drittpartei) an und kann als Betriebskosten betrachtet werden, nicht als Teilnehmer-Overhead.

---

### 5.3 Beispielrechnung: Broadcast-Modus (korrigiert)

Annahmen:
- N = 100 Teilnehmer im ISAC
- Slot-Größe |m| = 10 KB (typisches STIX-Bundle mit wenigen IOCs)
- Cover-Traffic-Frequenz: 1 Dummy-Write pro Minute (third-party generiert, 1.440/Tag)
- Jede Organisation schreibt durchschnittlich 5× pro Tag

**Sendekosten pro ISAC-Mitglied pro Tag (nur echte Writes):**
```
5 × (4 KB + 2 × 10 KB) = 5 × 24 KB = 120 KB
```

**Cover-Traffic-Kosten (beim ISAC-Betreiber, für alle Slots):**
```
1.440 Dummy-Writes/Tag × 24 KB = ~33,75 MB/Tag
(für N=100 Slots gleichmäßig verteilt; der Betreiber trägt diese Last)
```

**Empfangskosten pro Mitglied (Broadcast: öffentlicher DB-Download):**
- DB wird nicht jede Minute neu geladen; sinnvoll ist ein periodisches Pull
- Bei 10-Minuten-Intervall: 144 DB-Downloads pro Tag
- DB-Größe bei N=100, |m|=10 KB: 100 × 10 KB = 1 MB
- Empfangskosten/Tag: 144 × 1 MB = 144 MB

Zum Vergleich – naives TAXII (ohne Anonymität):
- Sendekosten: ~50 KB/Tag (5 Writes × 10 KB, kein DPF-Overhead)
- Empfangskosten: Summe aller neu gemeldeten IOCs (typ. 1–10 MB/Tag bei aktivem ISAC)

**Fazit:** Der Overhead beim Sender ist minimal (120 KB vs. 50 KB, Faktor 2,4). Der Empfangs-Overhead (144 MB/Tag) ist das eigentliche Unterscheidungsmerkmal – er resultiert aus dem Broadcast-Modell (alle lesen alle Slots), nicht aus dem DPF-Mechanismus an sich.

---

### 5.4 Skalierungsanalyse: Broadcast-Modus

Alle Werte: Täglich, Broadcast-Modus, 10-Minuten-Pull-Interval, |m| = 10 KB, 5 Writes/Mitglied/Tag.

| N | Send-Kosten/Mitglied/Tag | DB-Größe | DB-Download/Tag/Mitglied |
|---|---|---|---|
| 50 | 120 KB | 500 KB | 72 MB |
| 100 | 120 KB | 1 MB | 144 MB |
| 200 | 120 KB | 2 MB | 288 MB |
| 500 | 120 KB | 5 MB | 720 MB |
| 1.000 | 120 KB | 10 MB | 1,44 GB |

**Kritische Beobachtung:** Die Sendekosten pro Mitglied skalieren **nicht** mit N – das ist der entscheidende Vorteil von Express gegenüber Riposte. Die DB-Download-Kosten skalieren linear mit N.

Für N > 500 wird der tägliche DB-Download (~720 MB) für Teilnehmer mit eingeschränkter Konnektivität problematisch. Mögliche Mitigationen:
1. Diff-basierter Download (nur geänderte Slots seit letztem Pull)
2. Erhöhung des Pull-Intervalls (z.B. stündlich statt 10-minütlich)
3. CDN-Caching der DB (statisch pro Epoch/Batch)

---

### 5.5 Skalierungsanalyse: Directed-Modus

Im Directed-Modus (TLP:AMBER/RED) ist die Empfängergruppe klein und bekannt. Die Empfänger laden nicht die gesamte öffentliche DB herunter, sondern greifen auf spezifische verschlüsselte Mailboxes zu.

**Wichtig:** Express verbirgt *Writes* (Sender-Anonymität), aber **nicht** *Reads*. Ein Angreifer kann beobachten, welche Mailbox ein Client abruft (§1, §6 des Express-Papers, explizit). Für den Directed-Modus muss die Read-Seite separat adressiert werden – entweder durch:
- Uniformes Herunterladen aller Mailboxes (Empfänger lädt alles, entschlüsselt lokal) → identisches Empfangsmuster wie Broadcast-Modus
- Ein separates PIR-Protokoll für Reads (bedeutende Zusatzkomplexität, nicht Teil von Express)
- Asymmetric Encryption mit öffentlichem Key der Empfängergruppe (Read-Metadaten entleakend, aber einfacher)

**Für die Beitragsbewertung:** Die fehlende Read-Anonymität in Express ist eine offene Designfrage für MetaCTI. Entweder wir schränken die Anonymitätszusagen für den Directed-Modus explizit ein (nur Sender-Anonymität) oder wir verbinden Express mit einem Read-Anonymisierungsmechanismus (Forschungsbeitrag C2b).

**Bandbreiten-Schätzung Directed-Modus (uniforme DB-Download-Strategie):**
Identisch mit Broadcast-Modus aus Empfänger-Sicht; Sender-Kosten ebenfalls identisch. Der Vorteil des Directed-Modus liegt nicht in der Bandbreite, sondern in der Zugangskontrolle (nur autorisierte Empfänger können entschlüsseln).

---

### 5.6 Server-Last

Die Server sind die zentralen Compute-Bottlenecks.

**Broadcast-Modus:**
- *Eingehend (je Server):* N Writes/Batch × (4 KB + 2|m|)
  Beispiel N=100, |m|=10 KB, 1 Batch/10 min: 100 × 24 KB = 2,4 MB/Batch = 346 MB/Tag eingehend
- *Compute pro Batch:* Server evaluiert alle N DPF-Keys auf physikalisch registrierten Adressen; bei Express O(n · λ) Operationen (n = Anzahl registrierter Mailboxes, λ = 128 bit)
- *Ausgehend (öffentliche DB):* Clients laden DB; bei CDN-Caching trägt der Express-Server kaum Auslieferungs-Last

**Empirische Referenz (Express-Paper, Section 7):**
- Auditing-Protokoll (SNIP-basiert): ~0.5 ms Server-Zeit pro Write
- Full-System-Experiment mit n=1 Mio. Mailboxes: Batch-Verarbeitungszeit ~2 s für 1.000 gleichzeitige Writes auf einem Commodity-Server

Für ISAC-Größen (N ≤ 1.000, n ≤ 10.000 registrierte Mailboxes) ist die Server-Last sehr moderat – weit entfernt von den Grenzen, die das Express-Paper untersucht.

---

### 5.7 Optimale Batch-Frequenz und Latenz-Trade-off

Express ist asynchron – es gibt keine fixe „Round-Frequenz" wie bei Riposte. Stattdessen akkumuliert der Server Writes und verarbeitet sie in Batches. Die Batch-Frequenz ist ein konfigurierbarer Parameter:

| Batch-Interval | Latenz (IOC bis Empfänger) | Dummy-Traffic-Rate (Betreiber) |
|---|---|---|
| 1 min | ~1–2 min | Hoch (1.440/Tag für plausible Deniability) |
| 10 min | ~10–15 min | Moderat (144/Tag) |
| 1 h | ~1–2 h | Niedrig (24/Tag) |
| 24 h | ~24 h | Minimal (1–2/Tag) |

Für operative CTI ist 10 Minuten ein guter Default: akzeptable Latenz für IOC-Sharing, moderate Betreiberlast.

Für strategische CTI (Reports, threat actor profiles) reicht ein tägliches Batch vollständig aus.

---

## 6. STIX-Objektgrößen und Chunking-Schwelle

### 6.1 Empirische Größenklassen von STIX-Objekten

**Hinweis:** Diese Werte basieren auf typischen Praxiserfahrungen und sollten mit einem realen CTI-Datensatz (z.B. MISP Community Feeds) verifiziert werden.

| STIX-Objekttyp | Typische Größe | Bewertung |
|---|---|---|
| `indicator` (einzelne IP/Hash/Domain) | 0,5–2 KB | ✅ Kein Chunking |
| `malware` (Beschreibung, Kill Chain) | 2–8 KB | ✅ Kein Chunking |
| `attack-pattern` / TTP | 3–15 KB | ✅ Kein Chunking |
| `STIX Bundle` (5–20 IOCs) | 5–30 KB | ✅ Kein Chunking |
| `report` (Incident-Zusammenfassung) | 20–150 KB | ⚠️ Chunking je nach Konfiguration |
| Bundle mit YARA/Sigma-Regeln | 30–300 KB | ⚠️ Chunking empfohlen |
| Großes `report` mit Relationships | 200 KB–1 MB | ❌ Chunking notwendig |
| Malware-Analyse mit Disassembly | 500 KB–5 MB | ❌ Chunking + ggf. Hybrid |
| Bundle mit base64-Binary (schlechte Praxis) | 1–50 MB | ❌ Nur Out-of-Band-Referenz |

### 6.2 Empfohlene Chunking-Schwelle

Praktischer Schwellwert: **32 KB** als Slot-Größe (M).

Begründung:
- Deckt ~90% des operativen IOC-Sharings ohne Chunking ab (einzelne IOCs, kleine Bundles)
- Hält DB-Größe bei N=100 auf 3,2 MB – handhabbar für öffentlichen Download
- Runde Potenz-von-2-Zahl (praktisch für Implementierung)

Für Objekte > 32 KB: Chunking in 32 KB-Blöcke, über mehrere Rounds verteilt.

### 6.3 Sicherheitsimplikation des Chunkings

**Problem:** Wenn ein Client in mehreren aufeinanderfolgenden Rounds denselben Slot befüllt (weil er ein großes Objekt in Chunks sendet), könnte ein Angreifer durch Round-übergreifende Beobachtung Timing-Korrelationen feststellen.

**Mitigation:** Chunks werden mit einem per-Chunk-Round-Robin-Schema über verschiedene Slots verteilt, und der Chunk-Schlüssel wird separat in der ersten Round übertragen. Die Sicherheitsimplikation dieser Erweiterung muss formal analysiert werden (Teil von C2d).

### 6.4 Drei-Stufen-Schema für große Objekte

**Stufe 1 (< 32 KB):** Direkter Express-Write. Kein Overhead.

**Stufe 2 (32 KB – 1 MB):** Chunking. Objekt wird in 32 KB-Blöcke zerlegt, symmetrisch verschlüsselt (Session-Key aus Stufe 1), Blöcke über mehrere Rounds verteilt.

**Stufe 3 (> 1 MB):** Out-of-Band-Referenz. Objekt wird symmetrisch verschlüsselt auf separatem Encrypted Object Store (z.B. S3-kompatibel) abgelegt. Über MetaCTI wird nur ein kleines STIX-Objekt mit URL + symmetrischem Schlüssel übertragen (<1 KB). Metadatenschutz gilt für den Referenz-Transfer; der Binär-Download ist nicht anonym aber kryptografisch gesichert. In den meisten Fällen akzeptabel, da aus dem Download eines verschlüsselten Blobs keine Rückschlüsse möglich sind.

---

## 7. Contribution-Übersicht und Argumentationskette

### 7.1 Warum das mehr ist als "EXPRESS auf CTI anwenden"

Die Adaptionen gehen substantiell über eine reine Anwendung hinaus:

1. **Threat Model (C1):** Erstmals formale Definition von Metadaten-Leakage im CTI-Kontext. Was verrät wann welche Information? Das ist domänenspezifisch und existiert so nicht.

2. **Dual-Mode-Architektur (C2):** Die Unterscheidung zwischen Broadcast-Modus (kein PIR) und Directed-Modus (mit PIR) ist eine genuine Design-Erkenntnis: Für den Broadcast-Fall vereinfacht sich das Protokoll erheblich und wird deutlich performanter. PIR-Kosten entfallen wo sie nicht nötig sind.

3. **Chunking mit Sicherheitsanalyse (C2a):** Round-übergreifendes Schreiben verlässt das EXPRESS-Sicherheitsmodell. Eine formale Analyse dieser Erweiterung ist notwendig und nicht trivial.

4. **Asynchrones Round-Management (C2c):** CTI-Sharing ist event-driven; EXPRESS ist für synchrones Messaging gebaut. Der Dummy-Traffic-Scheduler muss so gestaltet werden, dass er keine Metadaten durch Timing-Anomalien preisgibt.

5. **Abuse Prevention (C3):** Das False-Positive/Poisoning-Problem ist CTI-spezifisch. Die Integration von Eskandarians Abuse-Reporting-Mechanismus und ZKP-Membership-Nachweisen ist eine eigenständige Designleistung.

### 7.2 Positionierung im Paper

Das Paper argumentiert in drei Schichten:
- **Warum-Schicht:** Metadaten-Leakage ist das ungelöste Kernproblem in CTI-Sharing (motiviert durch Threat Model C1)
- **Was-Schicht:** MetaCTI-Protokoll mit formalen Garantien (C2)
- **Wie-gut-Schicht:** Performance ist für reale ISAC-Settings praktikabel (C4)

Die Abuse-Prevention (C3) ist der "Realist-Check": Man kann nicht nur zeigen, dass das System sicher ist, sondern auch, dass es nicht durch Anonymität missbrauchbar wird.

---

## 8. Offene Fragen (für weitere Recherche und Design)

### 8.1 Technisch zu klären

- **PIR-Schema-Wahl:** Welches konkrete PIR-Schema wird verwendet? DPF-basierte PIR (wie impliziert in EXPRESS) hat O(log N) Query-Kommunikation aber O(N×M) Server-Compute. Gibt es neuere Schemes mit besserem Server-Compute für unseren Anwendungsfall?

- **Chunk-Sicherheitsanalyse:** Formal zu zeigen: Multi-Round-Chunking verletzt die Sender-Anonymität nicht, wenn Chunks über zufällige Slots verteilt werden.

- **Dummy-Traffic-Scheduling:** Wie oft muss ein Client wirklich in jeder Round senden? Gibt es Relaxierungen (z.B. "1 von k Rounds aktiv sein") die weniger Overhead erzeugen aber trotzdem formale Anonymität behalten?

- **ZKP-Schema für Membership:** Welches konkrete ZKP-Schema ist am besten geeignet? Optionen: Merkle-Tree-basiertes Membership-Proof (einfach, etabliert), BBS+ (effizienter für mehrfache Nutzung), Pedersen-Commitment-basiert.

- **Round-Synchronisierung in der Praxis:** Wie wird sichergestellt, dass alle Clients synchron sind? NTP? Wie geht das System mit Ausfällen einzelner Clients um?

### 8.2 Empirisch zu erheben

- **Reale STIX-Objektgrößen:** Messung an öffentlichen MISP Community Feeds oder ähnlichen Datensätzen, um die Größenklassen-Tabelle zu validieren.

- **Typische CTI-Sharing-Frequenzen:** Wie viele IOCs teilt ein typisches ISAC-Mitglied pro Tag/Woche? Relevant für die Wahl der Round-Frequenz und Dummy-Traffic-Kalibrierung.

- **Akzeptable Latenz für operative CTI:** Befragung von CTI-Praktikern: Welche Submission-to-Visibility-Latenz ist bei welchen IOC-Typen akzeptabel?

### 8.3 Konzeptuell offen

- **Trust-Model für die Zwei-Server-Annahme:** Wer betreibt die zwei Server in der Praxis? ISAC + Forschungsinstitut? Zwei nationale CERTs? Die Governance ist eine Nicht-Trivialität.

- **Übergang zwischen TLP-Levels:** Wenn ein IOC erst TLP:AMBER und später TLP:GREEN wird, wie geht MetaCTI damit um, ohne die ursprüngliche Sender-Anonymität zu kompromittieren?

- **Incentive-Kompatibilität:** Schafft MetaCTI neue Anreize für Free-Riding? (Jeder profitiert, aber Dummy-Traffic kostet – lohnt es sich, einfach gar nicht teilzunehmen?)

---

## 9. Verworfene Ideen (mit Begründung)

### 9.1 DC-Netz-Hybrid (EXPRESS für Verifikation, DC-Netz für Datentransfer)

**Idee:** DC-Netze haben keinen Server-Bottleneck und geringere Sendekosten (M statt 2M). Wenn EXPRESS nur für die Integritätsprüfung verwendet wird und DC-Netze für den eigentlichen Transfer, könnte man Performance gewinnen.

**Warum verworfen:**
- Die Verifikation in EXPRESS und der Datentransfer sind in der Protokollstruktur nicht trennbar ohne ein zweites Protokoll zu bauen
- Das zweite Protokoll würde im Wesentlichen "Accountable DC-nets" (Dissent, Corrigan-Gibbs & Ford CCS 2010) sein – ein bekanntes und als zu langsam befundenes System (RIPOSTE war explizit die Reaktion auf Dissent)
- Der Netto-Vorteil (M statt 2M senden) wird durch den Overhead der Verifikationsphase aufgefressen
- DC-Netze erfordern All-to-All-Konnektivität, was in realen ISAC-Settings mit Firewall-Policies unrealistisch ist
- Kein klarer Performance-Gewinn für unsere Workloads; erhöhte Protokollkomplexität

---

## 10. Literatur-Stichpunkte für das Paper

**Für die Motivation (Gap-Argumentation):**
- SeCTIS 2024: explizit "connection anonymity" als Future Work → direkte Anknüpfung
- ENISA/CISA Berichte zu CTI-Sharing-Barrieren (Vertrauen, Datenschutz) → empirische Motivation
- Wagner et al. 2018: Erster Anonymitätsansatz für CTI, aber nur Tor → "wir gehen weiter"

**Für das Protokoll:**
- Eskandarian 2021 (EXPRESS): Basisprotokoll, 100× effizienter als Pung/RIPOSTE
- Corrigan-Gibbs 2015 (RIPOSTE): Vorgänger, Schutz gegen malicious participants etabliert
- Eskandarian 2024 (Abuse Reporting): Direkt übernehmbarer Mechanismus für C3a

**Für die Evaluation:**
- Öffentliche MISP Community Feeds für Workload-Charakterisierung
- Fischer ETH Thesis: Benchmark-Zahlen für FL-basierten Ansatz als Vergleichspunkt
- TAXII 2.1 Spec für Baseline-Protokoll

**Zu verifizieren:** Ob Corrigan-Gibbs & Ford, "Dissent" (CCS 2010) noch zusätzlich zitiert werden sollte – als Vorgänger von RIPOSTE der den Hybrid-Ansatz bereits versucht hat.
