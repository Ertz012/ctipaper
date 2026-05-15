# Exposé: Aggregate Metadata Privacy für Anonyme CTI-Bulletin-Boards

**Arbeitstitel:** *Beyond Sender Anonymity: Output-Privacy for Public Anonymous Bulletin Boards with Application to Cyber Threat Intelligence Sharing*

**Version:** 0.1 (April 2026) — erstes Exposé, noch zu konkretisieren

**Ziel des Dokuments:** Dieses Exposé positioniert eine bisher unbehandelte Forschungslücke an der Schnittstelle zwischen anonymer Kommunikation, Differential Privacy und CTI-Sharing. Es argumentiert, warum das Problem genuin ungelöst ist, skizziert einen formalen Rahmen, und schlägt konkrete Mechanismen sowie einen Evaluationsplan vor.

---

## 1. Zusammenfassung (One-Pager)

Alle etablierten Metadata-Hiding-Kommunikationssysteme (Riposte, Express, Pung, Blinder) wurden für das *Private-Messaging*-Szenario entworfen: Mailbox-Inhalte sind pro Empfänger privat, nur Sender-Metadaten werden versteckt. In diesen Systemen gibt es *keine öffentlich einsehbare Ausgabe*. Das CTI-Sharing stellt diese Annahme erstmals auf den Kopf: Die resultierende IOC-Datenbank muss *öffentlich zugänglich* sein, damit sie ihren Zweck erfüllt. Genau an dieser Schnittstelle entsteht ein neuer, bisher in der Literatur nicht adressierter Angriffsvektor:

> **Auch bei perfekter Sender-Anonymität leakt die veröffentlichte Datenbank selbst — ihre Größe, ihre Typ-Verteilung, ihre temporale Dynamik — strategische Metadaten, die einem Angreifer erlauben, Rückschlüsse auf Kompromittierungen im ISAC-Kollektiv zu ziehen.**

Wir nennen diesen Angriffsvektor **Aggregate Metadata Leakage (AML)**. Das Exposé skizziert ein Forschungsprogramm, das (i) AML als eigenständige Bedrohungsklasse formalisiert, (ii) ein angepasstes Differential-Privacy-Konzept für veröffentlichte anonyme Bulletin-Boards entwickelt (**Event-Level Differential Privacy over Anonymous Broadcast Streams, E-DP-ABS**), (iii) konkrete Obfuskationsmechanismen konstruiert, die IOC-Utility bewahren, und (iv) einen empirischen Utility-Privacy-Tradeoff an realen CTI-Workloads vermisst. Das Resultat ist eine komplementäre Schutzschicht zu MetaCTI, die den End-to-End-Anspruch — „von Submission bis Veröffentlichung keine verwertbaren Metadaten-Leaks" — erstmals geschlossen verteidigt.

---

## 2. Ausgangslage und Motivation

### 2.1 Die blinde Stelle der Metadata-Hiding-Literatur

Die letzte Dekade hat erhebliche Fortschritte in kryptographisch-anonymer Kommunikation gebracht. Systeme wie Riposte (Corrigan-Gibbs et al., S&P 2015), Express (Eskandarian et al., USENIX 2021), Blinder (Abraham et al., Oakland 2020) oder Atom (Kwon et al., SOSP 2017) bieten formal fundierte Garantien darüber, wer an welchem Kommunikationsakt beteiligt ist. All diese Arbeiten operieren jedoch im Private-Messaging-Modell: Ein Sender schreibt an einen *konkreten* Empfänger (Whistleblower ↔ Journalist; Nutzer ↔ Nutzer). Mailbox-Inhalte sind grundsätzlich privat, die Server sehen nur verschlüsselte Shares, und die Nachrichten werden von genau einer Entität gelesen — dem Mailbox-Besitzer.

Das CTI-Sharing ist strukturell anders. Die Idee eines CTI-Feeds ist per definitionem **Informationsverteilung an viele** (häufig an alle Mitglieder einer ISAC, manchmal an die gesamte Öffentlichkeit). Die Datenbank, die nach Abschluss einer Epoche veröffentlicht wird, ist *öffentlich* und *von ihrer Zweckbestimmung her auf Sichtbarkeit angewiesen*. Damit existiert ein statistisches Artefakt, das in den klassischen Metadata-Hiding-Systemen schlicht nicht vorhanden ist: ein öffentlicher Stream strukturierter Records mit Zeitstempel.

Dieser Stream ist selbst eine Metadaten-Quelle. Er verrät nicht direkt, *wer* submittet hat (das verbirgt die Write-Privacy-Schicht); er verrät aber sehr viel darüber, *was* gerade passiert — und durch geschickte Korrelation mit out-of-band-Information kann daraus wieder ein Link auf *wen* konstruiert werden. Dieses Problem ist in keiner der genannten Arbeiten formal behandelt, weil im Private-Messaging-Modell kein vergleichbares Artefakt öffentlich wird.

### 2.2 Illustrative Angriffsszenarien

Drei konkrete Szenarien verdeutlichen, dass AML nicht theoretisch, sondern praktisch relevant ist.

**Szenario 1 — Kampagnen-Observation:** Ein staatlich motivierter Akteur beobachtet den öffentlichen CTI-Feed eines nationalen Finanz-ISAC. Am Dienstag um 03:17 Uhr erscheinen plötzlich 38 IOCs des Typs `indicator:file-hash` mit hoher Ähnlichkeit. Er folgert ohne weiteres: „Eine Ransomware-Kampagne trifft gerade zeitgleich eine größere Zahl Finanz-Institute." Obwohl kein einziger Sender identifiziert werden kann, hat er strategische Information gewonnen — und kann seine eigene Operation taktisch darauf ausrichten.

**Szenario 2 — Out-of-Band-Korrelation:** Ein Angreifer weiß aus Presse oder aus eigenen Aufklärungsaktivitäten, dass er erfolgreich Org X kompromittiert hat. Er beobachtet den Feed auf das Erscheinen spezifischer IOCs, die nur aus seinem Angriff stammen können (etwa bestimmte C2-IP-Adressen oder eindeutige Payload-Hashes). Wenn innerhalb von 24 Stunden diese IOCs im Feed erscheinen, bestätigt ihm das: „Meine Operation wurde bei X detektiert." Die Sender-Anonymität hilft hier nicht — der Angreifer nutzt die *Kenntnis des eigenen Angriffs* als Seitenkanal.

**Szenario 3 — Differentielle Beobachtung:** Ein Angreifer compromittiert Org A am Montag. Er vergleicht den Feed vom Sonntag (vor-Angriff-Baseline) mit dem vom Dienstag (nach-Detektions-Fenster). Der Delta-Set — neu erschienene IOCs, die spezifisch zu seiner TTP-Kette passen — ist mit hoher Wahrscheinlichkeit das Reporting von Org A. Auch hier bleibt die Submission im formalen Sinn anonym, aber der Angreifer kann inferieren: *„A hat reagiert, meine Technik ist verbrannt."* Das liefert ihm wertvolle taktische Information, die die gesamte Motivation für anonymes CTI-Sharing unterläuft.

Alle drei Angriffe funktionieren, *ohne* die Schreib-Anonymität von MetaCTI zu brechen. Sie nutzen ausschließlich das öffentliche Artefakt — und damit einen Kanal, den das aktuelle Design überhaupt nicht schützt.

### 2.3 Warum der CTI-Kontext das Problem erstmals zwingend macht

Private Messaging hat keinen äquivalenten Angriffsvektor, weil Nachrichten *nur* vom Empfänger gelesen werden und ein externer Beobachter höchstens Nachrichten-Größen und -Zeitpunkte sieht, nicht aber Nachrichten-Semantik. CTI-Sharing ist per Konstruktion umgekehrt: Der Wert des Systems entsteht erst durch die Sichtbarkeit der Daten. Damit ist AML kein optionales Zusatzproblem, sondern eine strukturelle Konsequenz des Einsatzkontextes. Ein CTI-System, das Sender-Anonymität garantiert, aber AML ignoriert, leistet nur *die Hälfte* dessen, was seine eigene Motivation (Schutz vor dem Leakage-Druck, siehe §1.1 der Notes) beansprucht.

Diese Beobachtung ist die zentrale Intuition dieses Forschungsprogramms. Sie begründet nicht nur die Relevanz — sie liefert auch den narrativen Aufhänger eines Papers: *„Wir zeigen erstmals, dass die bisherige Anonymitätsverteidigung im CTI-Kontext unzureichend ist, definieren die fehlende Schutzschicht formal, und konstruieren Mechanismen, die sie etablieren."*

---

## 3. Verwandte Arbeit und Abgrenzung

Die nicht-Existenz eines direkten Vorgängers für dieses Forschungsprogramm ergibt sich aus der Schnittmenge mehrerer Teilgebiete, die je für sich etablierte Literatur haben, aber nicht zusammengeführt wurden.

### 3.1 Metadata-Hiding Communication

Riposte, Express, Pung, Blinder, Atom und verwandte Arbeiten formalisieren Sender- bzw. Empfänger-Anonymität. Sie treffen *keine* Aussagen über den öffentlich einsehbaren Gesamtzustand des Systems über Zeit, weil sie implizit annehmen, dass es einen solchen Zustand nicht gibt oder dieser kryptographisch versteckt bleibt. Die formale Sicherheits­definition (z.B. IND-WA in Express) ist pro-Submission, nicht pro-System-Beobachtung über Zeit. AML fällt damit außerhalb ihres Scopes.

### 3.2 Differential Privacy

Differential Privacy (Dwork et al., TCC 2006 und Folgearbeiten) hat sich als Standardformalismus für Datenbank-Privatheit etabliert. DP ist jedoch traditionell für **Query-Systeme** entworfen: Ein Analyst stellt Anfragen an einen vertrauenswürdigen Kurator, der mit Rauschen antwortet. DP über **veröffentlichte Datensätze** ist das Gebiet der *synthetischen Daten* und des *DP-Data-Release* (siehe etwa McSherry & Talwar, FOCS 2007; Hardt & Rothblum, FOCS 2010; PATE-GAN und Folgewerke). All diese Arbeiten operieren jedoch auf **statischen strukturierten Datensätzen** — nicht auf Streams anonym erzeugter Events, und nicht unter den spezifischen Utility-Constraints strukturierter CTI-Artefakte (IOCs müssen bit-genau sein, Rauschen auf einer IP-Adresse ist semantisch sinnlos).

Stream-basiertes DP (Dwork et al., „Pan-Private Streaming Algorithms", ICS 2010; Chan et al., „Private and Continual Release of Statistics", ICALP 2010) ist der näheste Verwandte. Diese Arbeiten behandeln jedoch *aggregierte Statistiken* (Zähler, Histogramme) über Streams, nicht die Veröffentlichung der Event-Records selbst. Ein IOC-Feed ist kein Histogramm; er ist eine Sequenz individuell wertvoller Objekte, deren *semantischer Inhalt* nicht verrauscht werden darf, wenn der Feed seinen Zweck erfüllen soll.

### 3.3 CTI Privacy

Die CTI-Privatheit-Literatur (SeCTIS 2024, Huff et al. 2024, Wagner et al. 2018, Fischer ETH) fokussiert auf Content-Privatheit (Federated Learning, Homomorphic Encryption, Anonymization of IOCs) oder auf Transport-Metadaten (Tor-Integration). Keines dieser Werke adressiert das Problem der Aggregat-Statistik-Leckage einer öffentlichen Datenbank. SeCTIS benennt „connection anonymity" als offenes Problem — aber auch dort wird die implizite Annahme getroffen, dass die Schutz-Garantien sich auf den Sender-Empfänger-Kanal beschränken.

### 3.4 Pattern-Leakage und Datenbank-Anonymisierung

Die k-Anonymity / l-Diversity / t-Closeness-Familie (Sweeney 2002, Machanavajjhala et al. 2007, Li et al. 2007) betrachtet Gruppen-Anonymisierung veröffentlichter Datensätze. Sie ist formal schwächer als DP und wurde vielfach als angreifbar nachgewiesen (siehe etwa „Robust De-anonymization of Large Sparse Datasets", Narayanan & Shmatikov, Oakland 2008). Sie behandelt jedoch *persistente tabellarische Daten*, nicht Event-Streams mit temporaler Dimension.

### 3.5 Fazit der Abgrenzung

Die Schnittstelle **„Differential Privacy über Streams veröffentlichter, anonym erzeugter, strukturierter Event-Records mit harter Utility-Constraint"** ist in der Literatur offen. Für den CTI-Kontext ist sie nicht einmal in der Anwendungsliteratur als Problem identifiziert. Beide Beobachtungen stützen die Neuigkeit des vorgeschlagenen Beitrags.

---

## 4. Bedrohungsmodell für AML

### 4.1 System- und Ausführungsmodell

Das zugrundeliegende System ist MetaCTI in seiner Broadcast-Variante (siehe notes §4): Sender schreiben anonym in eine DPF-basierte Write-Private-Datenbank, die am Ende jeder Epoche öffentlich publiziert wird. Die publizierte Datenbank pro Epoche $e$ ist eine Menge $\mathsf{DB}_e = \{r_1, r_2, \ldots, r_{k_e}\}$ von Records, wobei jeder Record $r_i$ einen strukturierten STIX-Artefakt enthält (IOC, TTP, Report etc.) zusammen mit einer semantischen Typisierung $\tau(r_i) \in \mathcal{T}$.

Der Adversary $\mathcal{A}_{\mathsf{AML}}$ ist ein **öffentlicher Beobachter**: er liest $\mathsf{DB}_e$ für jede Epoche $e \in \{1, 2, \ldots\}$. Er hat Zugriff auf die Publikations-Zeitstempel und auf unbeschränkt viele out-of-band Seitenkanäle (öffentliche Nachrichten, eigene Angriffs-Aufklärung, bekannte Sicherheitsvorfälle, etc.). Im stärksten Modell ist er computationell beschränkt, passiv, und kann keinen Server oder Client kompromittieren. Er nutzt ausschließlich den öffentlichen Feed.

Dieses Angreifermodell ist strikt *schwächer* als das der bisherigen MetaCTI-Analyse (die auch einen korrumpierten Server einbezieht). Genau darin liegt die Härte des Problems: Ein Angreifer, der *überhaupt nichts* Internes kontrolliert, erhält trotzdem verwertbare Metadaten. Die zusätzliche Schutzschicht muss gegen eine essentiell triviale Adversary-Klasse verteidigen.

### 4.2 Adversary-Ziele

Wir unterscheiden vier primäre Angriffsziele, die in der Literatur teilweise unter anderen Namen auftauchen, aber im AML-Kontext systematisch zusammengeführt werden müssen:

**Ziel 1 — Volume-Inference:** Der Adversary möchte die *Anzahl* der echten Submissions in einem Zeitfenster schätzen. Eine Spitze im Volumen über den Baseline kann einen Security-Event signalisieren. Formal: Gegeben $\mathsf{DB}_{e_1}, \ldots, \mathsf{DB}_{e_k}$, schätze die Anzahl $r_e$ der nicht-synthetischen Records pro Epoche.

**Ziel 2 — Type-Distribution-Inference:** Der Adversary möchte die *Verteilung* über STIX-Typen ermitteln. Eine Anomalie (z.B. 30% mehr Malware-Indicators als üblich) signalisiert eine laufende Kampagne eines bestimmten Typs. Formal: Schätze $\Pr[\tau(r) = t \mid r \in \mathsf{DB}_e]$ und identifiziere temporale Anomalien in dieser Verteilung.

**Ziel 3 — Event-Confirmation:** Der Adversary weiß, dass er eine bestimmte Angriffstechnik gegen bestimmte Ziele einsetzt, und möchte *bestätigen*, dass diese Technik detektiert wurde. Formal: Gegeben ein Muster $P$ (z.B. Set von IPs, Hashes, CVE-Referenzen), bestimme den Erwartungswert des Erscheinens von Records mit Matchen auf $P$ als Funktion der Angriffszeit.

**Ziel 4 — Cluster-Re-Identification:** Der Adversary möchte aus dem Stream ein *Cluster* zusammenhängender Records identifizieren (etwa „alle IOCs, die zu Kampagne X gehören") und die Cluster-Größe als Proxy für die Reichweite des Angriffs nutzen. Formal: Bestimme $|\{r \in \bigcup_e \mathsf{DB}_e : r \text{ korreliert mit Angriff } X\}|$.

Ziel 1–3 lassen sich direkt über Volume- und Type-Statistiken realisieren. Ziel 4 ist anspruchsvoller, weil es semantische Clustering-Fähigkeit voraussetzt — aber in der Praxis durch Hash-Gleichheit, IP-Überlappung oder TTP-Matching gut angenäherbar.

### 4.3 Beziehung zur bisherigen Threat-Model-Familie

Die in den Notes §2a definierten IND-WA und IND-EU-Spiele behandeln *Submission-Events individuell*: Können wir unterscheiden, welcher von zwei ehrlichen Teilnehmern eine konkrete Nachricht geschrieben hat? Das AML-Bedrohungsmodell operiert auf einer anderen Ebene: Es fragt nicht nach einzelnen Submissions, sondern nach *statistischen Eigenschaften der öffentlichen Ausgabe über Zeit*. Beide Ebenen sind komplementär und ergeben erst gemeinsam das vollständige Schutzbild. Das Paper würde das als Hauptbeitrag der Bedrohungsanalyse positionieren: die Separation der Sicherheitseigenschaften in **Submission-Level-Security** (bestehende IND-WA / IND-EU) und **Output-Level-Security** (neu einzuführendes E-DP-ABS).

---

## 5. Formales Framework: Event-Level Differential Privacy over Anonymous Broadcast Streams

### 5.1 Benachbarte Welten

Der Kern jeder DP-Definition ist der Begriff der Nachbarschaft: Zwei Welten $\mathcal{W}_0$ und $\mathcal{W}_1$, die sich in einem einzigen Ereignis unterscheiden, sollen im beobachtbaren Output kaum unterscheidbar sein. Für unseren Kontext schlagen wir die folgende Nachbarschafts­relation vor, die den operationellen Kern des CTI-Sharings trifft:

**Definition (Event-Nachbarschaft über Broadcast-Streams).** Seien $\mathcal{S}_0$ und $\mathcal{S}_1$ zwei Welten, die *exakt in einer* Submission eines einzelnen Teilnehmers differieren. Konkret: In $\mathcal{S}_0$ reicht Teilnehmer $P_i$ in Epoche $e^*$ keinen Record ein; in $\mathcal{S}_1$ reicht er einen Record $r^*$ ein. Alle anderen Submissions aller anderen Teilnehmer in allen Epochen sind identisch. Wir nennen $\mathcal{S}_0$ und $\mathcal{S}_1$ *event-benachbart*.

Diese Definition entspricht dem *event-level* DP-Modell (im Unterschied zum *user-level* Modell, bei dem das Differenz-Event alle Submissions desselben Nutzers umfassen würde). Event-Level ist im CTI-Kontext die relevante Granularität, weil einzelne IOCs das atomare Submission-Objekt sind. User-Level wäre strenger, würde aber den Utility-Spielraum unakzeptabel einschränken.

### 5.2 Publikationsmechanismus

Sei $\mathsf{Pub}$ ein randomisierter Mechanismus, der aus einer Welt $\mathcal{S}$ (d.h. der internen Folge der echten Submissions) die Folge der veröffentlichten Datenbanken $(\mathsf{DB}_1, \mathsf{DB}_2, \ldots)$ erzeugt. $\mathsf{Pub}$ repräsentiert den Gesamt-Output des Systems — er umfasst das anonyme Write-Protokoll, die Epoch-Accumulation, und die hier zu entwerfende *Output-Privacy-Schicht*, die Maßnahmen wie Delay-Randomisierung, Synthetic-Record-Injection, Typ-Shuffling oder Batch-Coarsening implementiert.

### 5.3 Zentrale Sicherheitseigenschaft

**Definition (E-DP-ABS).** Ein Publikationsmechanismus $\mathsf{Pub}$ ist *$(\varepsilon, \delta)$-Event-Level-Differential-Private über Anonymous Broadcast Streams*, falls für alle event-benachbarten Welten $\mathcal{S}_0, \mathcal{S}_1$ und alle messbaren Ausgabe-Mengen $Y$:
$$
\Pr[\mathsf{Pub}(\mathcal{S}_0) \in Y] \leq e^\varepsilon \cdot \Pr[\mathsf{Pub}(\mathcal{S}_1) \in Y] + \delta.
$$

Interpretation: Für einen externen Beobachter, der nur die publizierte Stream-Folge sieht, ist nicht unterscheidbar, ob ein zusätzlicher Record an einer bestimmten Stelle submittet wurde oder nicht — bis auf einen kontrollierten Parameter $\varepsilon$.

Bemerkung: Die Definition impliziert automatisch, dass auch die zeitliche Verschiebung einer Submission (ein Record, der statt in Epoche $e^*$ in $e^{*}+k$ erscheint) durch den Mechanismus verschleiert wird, solange diese Verschiebung aus der Folge der Benachbarschafts-Differenzen aufgebaut werden kann. Die Rolle von $\varepsilon$ ist damit ein kombiniertes Maß für Volume-Leakage, Timing-Leakage und Typ-Leakage.

### 5.4 Utility-Definition

Privatheit ohne Utility ist trivial erreichbar (veröffentliche die leere Datenbank). Die Forschungs-Substanz liegt in einem *expliziten Utility-Formalismus*, der mit E-DP-ABS in Beziehung gesetzt wird. Wir schlagen einen dreiteiligen Utility-Vektor vor:

**(U1) Präzision pro Record:** Jeder echte Submission-Record $r^*$ soll entweder *bit-genau* in der finalen $\mathsf{DB}$ erscheinen oder nachweisbar nicht-erscheinen. Anders als klassisches DP dürfen wir den *Inhalt* eines IOCs nicht verrauschen — die strukturelle Integrität ist semantisch nicht negotiabel.

**(U2) Aktualität:** Die Verzögerung zwischen Submission-Zeitpunkt $t(r^*)$ und Erscheinen in einer veröffentlichten DB $\mathsf{DB}_e$ soll einen kalibrierbaren Grenzwert $\Delta_{\max}$ nicht überschreiten — bedingt durch die CTI-typische Operationsanforderung (für operative IOCs: Minuten bis Stunden; für strategische: Tage).

**(U3) Gesamt-Precision & Recall über Zeit:** Für einen Konsumenten der Datenbank (z.B. ein SIEM, das IOCs als Blocklist lädt) soll die Rate falsch-negativer (echte Submissions nicht erscheinen) und falsch-positiver (synthetische Records verursachen Fehlalarme) Erkennungen quantitativ bounded sein.

Der technische Kern ist der *Tradeoff-Graph* zwischen $\varepsilon$ (E-DP-ABS-Parameter) und dem Utility-Vektor. Je stärker die Obfuskation (geringeres $\varepsilon$), desto stärker der Utility-Verlust. Die Bestimmung dieses Tradeoffs für realistische CTI-Workloads ist ein zentraler empirischer Beitrag.

### 5.5 Verhältnis zu bestehenden DP-Notionen

E-DP-ABS ist eng verwandt mit *Pan-Privacy* und *Continual-Release DP*, unterscheidet sich aber in drei wesentlichen Punkten:

1. Das veröffentlichte Objekt ist eine Sequenz *struktureller Records*, nicht aggregierter Zähler.
2. Die Utility-Anforderung ist *per-Record bit-exakt* (U1), was die übliche Noise-Addition ausschließt.
3. Die Submitter sind *anonym*, d.h. der Mechanismus darf den Record-Inhalt nicht zur Identifikation der optimalen Obfuskationsstrategie nutzen.

Diese drei Einschränkungen zusammen bilden das Novum der Definition. Sie zwingen zu einer fundamental anderen Klasse von Mechanismen — nicht Noise-Addition auf Record-Inhalt, sondern **temporale, typologische und mengen-bezogene Obfuskation auf der Stream-Oberfläche**.

---

## 6. Mechanismen: Lösungsraum

Die Definition von E-DP-ABS legt die Latte; die eigentliche Forschungsarbeit ist die Konstruktion *konkreter Mechanismen*, die die Definition erfüllen und gleichzeitig Utility bewahren. Wir skizzieren vier Mechanismen-Familien, die einzeln und in Kombination analysiert werden können.

### 6.1 Temporal Delay-Obfuscation (M1)

**Idee:** Jeder Submission-Record wird nicht in der unmittelbaren Epoche veröffentlicht, sondern nach einem zufälligen Delay $\delta \sim \mathcal{D}_{\mathrm{Delay}}$. $\mathcal{D}_{\mathrm{Delay}}$ ist eine publikationspolicy-definierte Verteilung (z.B. geometrisch, truncated-exponentiell). Die Zeitachse zwischen Submission und Veröffentlichung wird damit ein Privatheits-Parameter.

**Privatheits-Analyse:** Die Timing-Korrelation zwischen einem Out-of-Band-Event (z.B. bekannter Angriff) und dem Erscheinen einer passenden Response im Feed wird durch das Delay mit einer $\varepsilon$-proportional verringerten Wahrscheinlichkeit detektierbar. Formal: der Beitrag dieser Obfuskation zum $\varepsilon$-Gesamtbudget ist analytisch bestimmbar über die Tail-Wahrscheinlichkeit von $\mathcal{D}_{\mathrm{Delay}}$.

**Utility-Kosten:** Verlust an U2 (Aktualität). Muss gegen operative Toleranzgrenzen kalibriert werden — für IOC-Klassen mit niedriger Time-Sensitivity (z.B. Post-Incident-Reports, strategische Intelligence) ist die Toleranz hoch; für operative IOCs knapp.

**Variante (M1'):** Typ-spezifische Delays. Hash-basierte IOCs für aktive Malware-Kampagnen erhalten kleines Delay, während reputations­behaftete IP-Blocklist-Updates oder TTP-Beschreibungen länger verzögert werden.

### 6.2 Synthetic-Event-Injection (M2)

**Idee:** Der Publikationsmechanismus injiziert pro Epoche eine variable Anzahl synthetischer Records, die strukturell und semantisch von echten Submissions ununterscheidbar sind. Die Anzahl dieser synthetischen Events wird aus einer Verteilung gezogen, die zusammen mit der echten Submission-Rate eine öffentlich beobachtete Verteilung erzeugt, die wenig von der Vorhanden­sein einer zusätzlichen echten Submission abhängt.

**Privatheits-Analyse:** Die Gesamtmenge $k_e = r_e + s_e$ (echte + synthetische) hat eine Verteilung $D_{k_e}$, die E-DP-ABS bezüglich der Volume-Komponente erfüllt, wenn $s_e$ aus einer geeignet verschobenen Laplace- oder Gauss-Verteilung gezogen wird. Dies entspricht der direkten Anwendung des Laplace-Mechanismus auf die Zählung, mit einer Feinheit: Da wir nicht nur den Count, sondern *strukturelle Records* publizieren, muss der synthetische Inhalt von einem plausiblen Generator stammen.

**Generator-Problematik:** Synthetische IOCs müssen plausibel sein, damit sie ununterscheidbar wirken. Naive Zufallsgenerierung (zufällige IP-Adressen, zufällige Hashes) würde von Konsumenten sofort als Rauschen erkannt. Zwei Ansätze sind hier denkbar:

*(a) Historischer Pool:* Der Publikationsmechanismus hält einen Pool archivierter, nicht-mehr-aktueller IOCs aus vergangenen Kampagnen. Synthetische Records werden aus diesem Pool gezogen und leicht perturbiert. *Problem:* Zuordnung eines historischen IOCs zu einer neuen Epoche kann selbst eine Information leaken.

*(b) Generative Modellierung:* Ein ML-Modell (z.B. sequence-to-sequence auf STIX-Schemas) wird auf historischen CTI-Daten trainiert und generiert strukturell konsistente, aber nicht-existierende IOCs. *Problem:* Generator-Sicherheit gegen Detection (haben die synthetischen Records einen statistisch erkennbaren Fingerprint?).

Beide Ansätze verdienen eigene Teiluntersuchungen; die Synthetic-Event-Generation ist potenziell ein Teilpaper für sich.

**Utility-Kosten:** Verlust an U3 (Precision). Konsumenten müssen synthetische Records filtern, was entweder vertrauensseitig (Markierung durch den Operator, aber dann kann der Angreifer filtern!) oder struktur­seitig (strukturelle Unterscheidungsmerkmale, aber dann entsteht Leckage) lösbar ist. Das ist eine zentrale offene Frage und ein Schwerpunkt des Forschungsplans.

### 6.3 Typ-Bucketing und kategorielle Aggregation (M3)

**Idee:** Anstatt STIX-Typen granular zu publizieren, werden Records auf einer gröberen Kategorien-Ebene bekannt gemacht. Das verhindert Type-Distribution-Inference.

**Konkretisierung:** Statt 15 Unter­typen von `indicator` (IP, Hash, Domain, URL, ...) werden Records in 3–4 Meta-Kategorien aggregiert (network-observable, file-observable, behavioral-observable). Die Feinkategorie bleibt nur im Record-Körper enthalten, aber nicht im öffentlichen Metadaten-Summary.

**Privatheits-Analyse:** Die Entropie der kategoriellen Verteilung wird reduziert; eine Spitze in einer Unterkategorie (die z.B. eine spezifische Kampagne anzeigen würde) verschwindet in der Meta-Kategorie. E-DP-ABS-Garantie bezüglich Ziel 2.

**Utility-Kosten:** Keine für individuelle Record-Konsumenten, die den Body lesen; aber Verlust von Aggregat-Statistiken (z.B. kann ein Konsument nicht mehr trivial zählen, wie viele Hash-Indicators er pro Tag bekommt). Das ist ein milder Utility-Verlust.

### 6.4 Batch-Coarsening (M4)

**Idee:** Statt kurzer Epochen (10 Minuten) werden Meta-Batches gebildet (z.B. 6 Stunden), innerhalb derer die Reihenfolge der einzelnen Record-Inkludierungen randomisiert wird.

**Privatheits-Analyse:** Die temporale Korrelation zwischen Sub-Minute-Ereignissen und Publikation wird zerstört; die Timing-Granularität des Adversaries wird auf den Batch-Zeitpunkt reduziert.

**Utility-Kosten:** Kombiniert mit M1. Die effektive Latenz für den Record-Konsumenten entspricht der halben Batch-Größe im Mittel.

### 6.5 Kombinierte Analyse

Die Mechanismen sind nicht exklusiv; eine Kombination $\mathcal{M} = \mathsf{M1} \circ \mathsf{M2} \circ \mathsf{M3} \circ \mathsf{M4}$ ist der realistische Einsatzfall. Die Kompositions-Analyse (Basic Composition Theorem von DP, Advanced Composition, Moments Accountant) liefert die zusammengesetzten Privatheits-Budgets. Ein zentraler analytischer Beitrag des Papers wäre: Ableitung der *Pareto-Frontier* zwischen $\varepsilon$-Budget und Utility-Vektor über alle vier Mechanismen, als Funktion der öffentlich publizierbaren Rate-Verteilung.

---

## 7. Integration in MetaCTI

### 7.1 Architektonische Verortung

Der Output-Privacy-Layer ist als *separate Schicht oberhalb der MetaCTI-Write-Schicht* konzipiert. Die Trennung ist wichtig, weil beide Schichten gegen unterschiedliche Adversary-Klassen schützen und in der formalen Analyse getrennt behandelbar sein sollen:

- **Write-Layer (MetaCTI / Express-basiert):** Schützt gegen Sender-Identifikation durch Server oder Netzwerk-Beobachter.
- **Output-Layer (AML-Schutz):** Schützt gegen Aggregat-Inferenz durch öffentliche Stream-Beobachter.

Das Gesamtprotokoll erzeugt als Pipeline:
```
Client → Write-Layer (Express-DPF+SNIP) → Epoch-Buffer → Output-Layer (M1+M2+M3+M4) → Öffentliche DB
```

### 7.2 Wer betreibt den Output-Layer?

Die Output-Layer-Implementierung muss drei Vertrauensanforderungen erfüllen:
- Sie darf die Sender-Anonymität nicht brechen (d.h. sie darf pro Record keine Submitter-Identifikation nutzen — was in MetaCTI ohnehin garantiert ist, weil der Record im anonymen Buffer liegt).
- Sie muss zuverlässig synthetische Events generieren können.
- Sie sollte nicht monopolistisch einer einzelnen Partei vertraut sein (sonst wäre das ISAC-Monopol die Schwachstelle).

Drei Deployment-Modelle sind denkbar:

*(a) Zentralisiert beim ISAC-Betreiber:* Einfach, aber schafft Vertrauensengpass.

*(b) Verteilt auf die beiden Write-Server:* Eleganter, weil ohnehin bereits non-colluding. Beide Server erzeugen unabhängig synthetische Events und fügen sie vor Publikation zusammen. Reverse-engineerbar nur bei Kollusion.

*(c) Verteilt auf Client-Side:* Clients erzeugen pro Submission zusätzliche synthetische Records. Scheitert an Koordination und ist operativ unattraktiv, aber kryptographisch am saubersten.

Die Analyse der Vertrauenstrade-offs für diese Modelle ist eigenständiger Teil des Forschungsbeitrags.

### 7.3 Interaktion mit den bereits definierten Eigenschaften

E-DP-ABS ist *komplementär*, nicht ersetzend zu IND-WA (Write-Anonymität) und IND-EU (Epoch-Unlinkability). Eine zentrale analytische Aufgabe ist zu zeigen, dass die Output-Layer-Mechanismen die Write-Layer-Garantien nicht unterlaufen. Beispielsweise darf M2 (Synthetic-Injection) keine Korrelation mit den DPF-Write-Requests haben, weil sonst ein kompromittierter Server durch Korrelations-Analyse Meta-Information gewinnen könnte.

Der formal zu beweisende Main-Theorem hat in etwa die Form:

> **Theorem (informell).** Sei $\mathsf{Pub}$ der kombinierte Publikationsmechanismus aus MetaCTI-Write-Layer + Output-Layer $\mathcal{M}$. Unter den Non-Collusion-Annahmen von Express und der Unabhängigkeit der Synthetic-Event-Generation von den Write-Requests erfüllt $\mathsf{Pub}$ sowohl IND-WA($\lambda$) als auch $(\varepsilon, \delta)$-E-DP-ABS.

Der formale Beweis ist eine zentrale Contribution — er zeigt die *kompositionelle Sicherheit* der beiden Schichten und ist das, was bei Reviewern den Eindruck einer vollständigen Sicherheits-Analyse hinterlässt.

---

## 8. Empirische Evaluation

### 8.1 Workload-Charakterisierung

Eine Voraussetzung für belastbare Aussagen über das Utility-Privacy-Tradeoff ist ein realistischer CTI-Workload. Der Plan umfasst:

*(E1)* Empirische Messung an öffentlichen MISP Community Feeds (mehrere Monate) und, wenn möglich, Zugang zu einem realen ISAC-Feed unter NDA. Extraktion von: Submission-Raten pro Zeit, Typ-Verteilungen, typischen Burst-Muster.

*(E2)* Synthetische Workload-Generation basierend auf den empirischen Parametern, parametrisiert nach ISAC-Größe ($N \in \{50, 100, 500, 1000\}$), Kampagnen-Intensität und Typ-Mischung.

### 8.2 Utility-Privacy-Tradeoff

Für jede Parameter-Kombination und für jede Mechanismen-Kombination wird das Tripel $(\varepsilon, \text{Utility-Vektor}, \text{Kosten})$ vermessen. Die resultierende Pareto-Frontier ist das zentrale empirische Artefakt. Plots:

- $\varepsilon$ vs. $\Delta_{\text{Latenz}}$ für verschiedene IOC-Klassen
- $\varepsilon$ vs. Precision/Recall für verschiedene Synthetic-Ratio-Werte
- Budget-Composition für kombinierte Mechanismen
- Sensitivitäts-Analyse: Wie ändert sich die Frontier mit der ISAC-Größe?

### 8.3 Adversary-Simulation

Um die Garantien empirisch zu validieren, werden die vier Angriffsziele als konkrete Angriffe implementiert:

- Volume-Inference: Statistischer Hypothesen-Test (Chi-Quadrat) auf Anomalien in $k_e$
- Type-Distribution-Inference: Kolmogorov-Smirnov-Test auf Typ-Verteilungs-Änderungen
- Event-Confirmation: Optimaler Bayes-Klassifikator gegen künstlich eingeführte „Ground-Truth-Events"
- Cluster-Re-Identification: Graph-Clustering auf IOC-Ähnlichkeit

Die Erfolgsrate dieser Angriffe ohne und mit Output-Layer-Schutz quantifiziert die praktische Stärke der Verteidigung.

### 8.4 Baseline-Vergleich

Natürlicher Baseline ist MetaCTI *ohne* Output-Layer (d.h. der bisherige Stand) sowie klassische CTI-Feeds (MISP/TAXII ohne jede Output-Obfuskation). Der Vergleich zeigt den neu hinzugewonnenen Schutz.

---

## 9. Arbeitspakete und Zeitplan

Die Arbeit lässt sich in acht überlappende Arbeitspakete gliedern:

| AP | Titel | Dauer | Output |
|---|---|---|---|
| **AP1** | Bedrohungsmodell AML: Formalisierung der vier Adversary-Ziele, Angriffs-Taxonomie, Abgrenzung zur Submission-Level-Security | 4 Wochen | Formaler Abschnitt, integrierbar in §2a der Notes |
| **AP2** | Definition E-DP-ABS, Abgrenzung zu Pan-Privacy und Continual-Release DP, Grund-Lemmata (Komposition, Post-Processing) | 4 Wochen | Paper-Abschnitt zu formalem Framework |
| **AP3** | Mechanismen-Design M1–M4: präzise Konstruktion jedes Mechanismus mit Privatheits-Analyse und Utility-Kostenfunktion | 8 Wochen | Mechanismus-Spezifikationen, Privatheits-Beweise |
| **AP4** | Kompositions-Analyse: kombinierter $\varepsilon$-Budget über alle vier Mechanismen, kompositionelle Sicherheit mit IND-WA/IND-EU | 4 Wochen | Main-Theorem + Beweis |
| **AP5** | Synthetic-Event-Generator: Pool- und Generativer-Ansatz, Detektions­resistenz-Analyse | 6 Wochen | Generator-Prototyp + Evaluation |
| **AP6** | Workload-Charakterisierung: MISP-Feed-Analyse, Workload-Parameter-Ableitung, synthetischer Workload-Generator | 4 Wochen | Datensatz + Workload-Spec |
| **AP7** | Prototyp-Implementierung: Integration Output-Layer in MetaCTI-Pipeline, Messinfrastruktur | 8 Wochen | Codebase |
| **AP8** | Empirische Evaluation: Tradeoff-Frontier-Vermessung, Adversary-Simulation, Baseline-Vergleich, Fallstudien | 6 Wochen | Benchmark-Ergebnisse, Paper-Evaluations-Abschnitt |
| **AP9** | Paper-Writing, Review-Vorbereitung | 6 Wochen | Draft |

Gesamt ca. **50 Wochen**. Die AP1–AP4 und AP6 sind parallelisierbar; AP5 hängt von den Datenanalyse-Ergebnissen aus AP6 ab; AP7 kann nach AP3 gestartet werden.

---

## 10. Risiken und Mitigationen

Ein ehrliches Exposé benennt die Risiken, die das Programm zum Scheitern bringen können.

**R1 — Utility-Kollaps:** Das Schlimmste, was passieren kann, ist empirisch: Die Mechanismen erreichen starke $\varepsilon$-Garantien, aber der Utility-Verlust ist für operative CTI-Nutzung inakzeptabel (zu große Latenz, zu hohe False-Positive-Rate durch Synthetics). *Mitigation:* Frühe AP8-Teilstudien, um die realistischen Parameter-Bereiche zu identifizieren und gegebenenfalls den Scope auf strategische CTI (höhere Latenz-Toleranz) zu fokussieren.

**R2 — Synthetic-Generator-Detektion:** Wenn synthetische IOCs statistisch erkennbar bleiben, bricht M2 zusammen. *Mitigation:* AP5 als eigenständiger Schwerpunkt; bei Scheitern Rückfall auf reine M1+M3+M4-Kombination und Anpassung der Utility-Ziele.

**R3 — Formalisierungs-Abwehr-Mismatch:** Die E-DP-ABS-Definition könnte entweder zu stark sein (kein Mechanismus erfüllt sie mit relevanter Utility) oder zu schwach (Reviewer sehen sie als artifiziell). *Mitigation:* Kontinuierliche Rückkopplung mit einem Kryptographen; Vergleich mit alternativen Definitionen (bayesisch, Information-Theoretisch) als Validierung.

**R4 — Scope-Konflikt mit MetaCTI:** Wenn AML zu einem eigenständigen Paper wird, droht MetaCTI selbst in der Substanz zu dünn zu werden. *Mitigation:* Entweder Integration als *der* Haupt­beitrag des MetaCTI-Papers (und MetaCTI wird zur Anwendungs-Plattform); oder AML als Follow-up-Paper nach MetaCTI.

**R5 — Empirischer Datenzugang:** Reale ISAC-Feeds sind oft vertraulich. *Mitigation:* Frühzeitig Kooperation mit einem ISAC initiieren; parallel Nutzung öffentlicher Feeds (MISP Community, AlienVault OTX, Abuse.ch) als Fallback.

---

## 11. Positionierung im Gesamt-Paper und Alternativen

Zwei strategische Optionen für die Einbettung in die Gesamt-Arbeit:

### Option 1: AML als integraler Haupt­beitrag von MetaCTI

Das MetaCTI-Paper wird neu ausgerichtet: Sender-Anonymität (Express-Adaption) wird zur *Protokoll-Grundlage*, und AML-Schutz wird zum *Hauptbeitrag*. Der narrative Bogen: Wir zeigen, dass Sender-Anonymität für CTI-Sharing *nicht ausreicht*, identifizieren die Lücke (AML), definieren das fehlende Framework (E-DP-ABS), konstruieren Mechanismen und evaluieren. MetaCTI ist dann der Test-Vehikel für das eigentliche Konzept.

*Vorteile:* Ein Paper mit klarem, neuartigem Kern-Beitrag. Höhere Chancen auf ein Applied-Crypto- oder Security-Top-Venue. Die Threshold-Deanonymisierung bleibt als Nebenbeitrag mit drin.
*Nachteile:* Verzögerung der Publikation, weil der AML-Anteil substantielle zusätzliche Arbeit erfordert.

### Option 2: MetaCTI zuerst, AML als Follow-up

Das MetaCTI-Paper wird als Protokoll-Beitrag in einem Mid-Tier-Venue publiziert (ESORICS, ACSAC, DIMVA), und AML wird als eigenständiges Follow-up in einem Privacy-Top-Venue (PETS, PoPETs) oder Security-Top-Venue angegangen.

*Vorteile:* Zwei Papers statt einem, kürzere Zeit bis zur ersten Publikation. MetaCTI-Paper hat klareren, engeren Scope.
*Nachteile:* Höhere Gesamt-Arbeit für zwei Papers, Gefahr, dass der MetaCTI-Kern als zu inkrementell abgelehnt wird (vgl. frühere Bewertung).

### Empfehlung

**Option 1** ist strategisch stärker. Das MetaCTI-Paper ohne AML steht auf wackeligen Füßen (keine originäre kryptographische Innovation, wie in der letzten Einschätzung bereits festgestellt). Mit AML bekommt es ein Rückgrat: eine neu identifizierte Angriffsklasse mit formalem Framework und empirischer Validierung. Das ist das Profil eines publizierbaren Security-Papers.

Die Zeit-Investition ist zusätzlich, aber das resultierende Paper steht auf einem grundsätzlich anderen Niveau.

---

## 12. Offene Konzept-Fragen für die Diskussion

Einige zentrale Punkte, die vor dem Fortschreiten geklärt werden müssen:

**F1:** *Ist Event-Level-DP die richtige Granularität, oder sollte User-Level-DP gewählt werden?* User-Level ist strenger (Schutz aller Submissions einer Org zusammen), aber utility-feindlicher. Für CTI mit vielen Submissions pro Org ist das ein echter Tradeoff.

**F2:** *Soll die Synthetic-Event-Generation vom ISAC-Betreiber, von den Servern, oder von Clients geleistet werden?* Jede Option hat unterschiedliche Vertrauens- und Operations-Implikationen.

**F3:** *Wie wird die Detektions­resistenz synthetischer Events empirisch gemessen?* Adversarielle Evaluation mit einem spezialisierten Detektor, oder verteilungstheoretisch?

**F4:** *Soll der Output-Layer auf alle TLP-Level angewandt werden, oder nur auf die öffentlichen (TLP:WHITE/GREEN)?* Für TLP:AMBER in geschlossenen Empfängergruppen ist AML weniger kritisch, weil der Stream nicht öffentlich ist — aber andererseits ist das Vertrauen in die Gruppenmitglieder nicht notwendigerweise perfekt.

**F5:** *Inwieweit kann E-DP-ABS mit anderen Privatheits-Notionen (z.B. Pufferfish, Concentrated DP, Rényi DP) verschärft oder verglichen werden?* Das ist eine theoretische Abgrenzungsfrage, die die formale Sauberkeit des Beitrags stärkt.

Diese Fragen sind nicht blockierend, aber ihre frühe Klärung prägt das Profil des Papers.

---

## 13. Fazit

Das vorgeschlagene Forschungsprogramm adressiert eine bisher in der Metadata-Hiding-Literatur nicht identifizierte Lücke: die Privatheit des *öffentlichen Ausgabe-Artefakts* anonymer Bulletin-Boards. Das Problem entsteht strukturell durch die Kombination aus anonymer Submission und öffentlicher Publikation — eine Kombination, die erst durch den CTI-Anwendungskontext in den Vordergrund tritt, aber darüber hinaus generalisiert (öffentliche Whistleblowing-Plattformen, anonyme Bug-Bounty-Disclosures, Zensur-Resistenz-Foren mit Archiv-Funktion).

Die vorgeschlagene Formalisierung (E-DP-ABS), die Mechanismen-Familie (M1–M4), die Utility-Tradeoff-Analyse und die empirische Evaluation bilden zusammen einen publizierbaren wissenschaftlichen Beitrag mit klarem Novelty-Claim und konkreter, prüfbarer Substanz. Er hebt MetaCTI von einem Engineering-Paper auf das Niveau eines Research-Papers mit eigenständiger konzeptioneller Innovation.

Die zentrale strategische Entscheidung, die jetzt ansteht, ist die zwischen Option 1 (Integration in MetaCTI) und Option 2 (Follow-up). Beide sind valide; Option 1 ist aber meines Erachtens die, die das beste Gesamtpaket ergibt — sowohl für die Publikationschancen als auch für die wissenschaftliche Kohärenz.

---

*Ende Exposé v0.1*

*Nächste Schritte: Entscheidung Option 1 vs. 2 mit Betreuer; bei Option 1 Umarbeitung des `research_plan.md` entlang dieser Struktur; parallel Beginn AP1 (Bedrohungsmodell-Formalisierung) und AP6 (MISP-Feed-Analyse) als voneinander unabhängige Einstiegs-APs.*
