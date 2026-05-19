# CHORUS Protocol Specification (v0.2 — Spectrum-based)

**System name (working):** *CHORUS* — *Cryptographic Hidden-Origin Reporting Under Spectrum*: ein rundenbasiertes anonymes CTI-Bulletin-Board-Protokoll auf Basis von Spectrum, mit STIX-Fingerprint-Deduplikation und client-seitiger Threshold-Verifikation.

**Status:** Designspezifikation v0.2 — implementierungsleitend. **Ersetzt v0.1 vollständig.** Die vorherige Express-basierte Variante wurde verworfen; das aktuelle Design basiert auf Spectrum (Newman, Servan-Schreiber, Devadas, NSDI 2022).

**Begründung für den Wechsel:** Express ist ein Mailbox-Modell (jeder Sender hat einen privaten Slot beim Empfänger). Spectrum ist ein *echtes Broadcast-Modell*: wenige berechtigte Sender broadcasten an viele Empfänger, mit Anonymität gegenüber der Gesamt-Client-Menge. Das matcht die CTI-Realität deutlich besser: in einer typischen Epoche möchten nur wenige Mitglieder einer ISAC tatsächlich teilen, alle anderen sind Empfänger und liefern Cover-Traffic. Spectrum verlagert die Per-Request-Serverarbeit von $O(N)$ auf $O(L)$, wobei $L \ll N$ die Anzahl simultaner Broadcaster ist — eine substantielle Performance-Verbesserung für unseren Use-Case.

**Wissenschaftliche Contributions, die CHORUS trägt:**

1. **Rundenbasiertes Per-Round-Broadcaster-Rotation-Schema** *(neu)*. Spectrum sieht *langlebige* Broadcaster vor, die einmalig registriert sind. CTI braucht *episodisches* Broadcasting: ein Mitglied teilt vielleicht heute etwas, in zwei Wochen wieder, dazwischen nichts. Wir entwickeln ein zwei-phasiges Round-Modell: leichtgewichtige Bootstrap-Phase (Riposte) für die anonyme Broadcaster-Anmeldung pro Window, gefolgt von einer Sequenz von Main-Phasen (Spectrum) innerhalb des Windows. Window-basierte Channel-Persistenz reduziert Bootstrap-Overhead.

2. **STIX-Fingerprint-Modul** *(neu)*. Konstruktion eines normalisierten Fingerprints über die atomischen Observable-Fields eines STIX-Bundles. Zwei semantisch gleiche Submissions (gleiche IOC-Menge) ergeben denselben Fingerprint, auch wenn die menschenlesbaren Beschreibungen abweichen. Der Fingerprint dient als Duplikat-Detektor.

3. **Content-Bound Linkable Pseudonyms mit Post-Aggregation-Verifikation** *(neu)*. Jeder Broadcaster bettet in seinen Channel-Payload ein *linkbares Pseudonym* $P = H_\mathsf{fp}^{k_i^{(w)}}$ ein, zusammen mit einem Zero-Knowledge-Beweis $\pi$, der zwei Aussagen macht: (a) der Submitter besitzt einen geheimen Skalar $k_i^{(w)}$, dessen Public-Key $g^{k_i^{(w)}}$ im publizierten Member-Roster liegt (Ring-Membership), und (b) $P$ ist korrekt aus diesem $k_i^{(w)}$ und dem im Payload deklarierten Fingerprint berechnet. Nach Spectrum-Aggregation rekonstruiert ein Verifier (Consumer oder dedizierter Service) den Channel-Klartext, prüft $\pi$, prüft das Self-Binding gegen $\mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})$, und pflegt eine Blacklist über $P$-Werte. Eigenschaften: (i) verschiedene Member produzieren verschiedene $P$ für dasselbe IOC (mehrere unabhängige Reports möglich), (ii) derselbe Member produziert dasselbe $P$ für dasselbe IOC innerhalb einer Woche (Duplikat-Block), (iii) das ZKP versteckt die Submitter-Identität im Ring — Anonymität bleibt intakt, auch gegenüber einem honest-but-curious Verifier.

4. **Client-seitige Threshold-Verifikation** *(neu)*. Konsumenten zählen lokal, wie oft ein Fingerprint innerhalb eines rolling window von mehreren Submittern *unabhängig* gemeldet wurde. Erst ab einem konfigurierbaren Schwellwert $T$ (typisch 3) wird der zugehörige IOC als verifiziert behandelt und ins SIEM gespeist. Dies ist eine epidemiologische Wahrheits-Aggregation: Falsche IOCs eines einzelnen maliciösen Submitters werden ignoriert, weil keine unabhängige Korroboration auftaucht.

**Orthogonale Forschungslinie (nicht Teil von v0.2).** Aggregate-Metadata-Leakage über die publizierte Bulletin-Board-DB — also Informationslecks an einen passiven Beobachter aus Publikations-Timing, Type-Verteilungen oder Volumen-Mustern — wird als eigenständige Forschungsrichtung in `expose_output_privacy.md` (E-DP-ABS-Framework) behandelt. CHORUS-v0.2 macht hierzu keine Aussage; die Spezifikation ist so geschnitten, dass eine spätere AML-Schicht orthogonal aufsetzen kann (siehe §18.2).

**Vereinfachung gegenüber v0.1.** Der heavy threshold-deanonymization-Mechanismus aus v0.1 entfällt. Die client-seitige Threshold-Verifikation (Contribution 4) macht eine kryptographische Identitäts-Aufdeckung im Normalfall überflüssig: gefälschte IOCs eines einzelnen Akteurs werden statistisch herausgefiltert, ohne dass jemand deanonymisiert werden muss. Threshold-Deanonymisierung bleibt als optionale Erweiterung dokumentiert (§18) für Szenarien, in denen Reputations- oder Sanktionsmechanismen ein konkretes Outing erfordern.

---

## Inhaltsverzeichnis

1. Designprinzipien und Architekturüberblick
2. Notation und kryptographische Bausteine
3. Systemrollen und Vertrauensannahmen
4. Parameter und Konfiguration (inkl. §4.3 Long-Term Member State)
5. Zwei-Phasen-Architektur: Window-Struktur
6. Bootstrap-Phase (Riposte-basiert)
7. Main-Phase (Spectrum-basiert) — Submit, Audit, Post-Aggregation-Verifier
8. STIX-Fingerprint-Modul (inkl. §8.4 offenes Partial-Overlap-Problem, §8.5 ZKP-basiertes Self-Binding)
9. Pseudonym-Blacklist und Cover-Traffic
10. Operative Publikations-Pipeline (Batch-Coarsening, Cover-Traffic)
11. Client-Seitige Threshold-Verifikation
12. Wire-Formate und Datenstrukturen (inkl. §12.5 Verifier-State)
13. Zustandsmaschinen (Klient, Spectrum-Server, Verifier, Consumer)
14. Sicherheitseigenschaften (inkl. Theorem 7 Honest-but-Curious Verifier)
15. Implementierungs-Roadmap
16. Mapping zur Spectrum-Referenzimplementierung
17. Testvektoren und Akzeptanzkriterien
18. Geklärte Designentscheidungen, Future Work, und Diskussion

---

## 1. Designprinzipien und Architekturüberblick

### 1.1 Designprinzipien

- **P1 — Asymmetrie nutzen.** CTI-Sharing ist inhärent asymmetrisch: viele Empfänger, wenige aktive Sender pro Zeitraum. Spectrum nutzt diese Asymmetrie für Server-Effizienz. CHORUS macht sie explizit zum Architektur-Prinzip.
- **P2 — Schichtenseparation.** Bootstrap-, Main-, Publish- und Consume-Phasen sind klar getrennt. Jede hat eigene Schnittstellen, Sicherheitsannahmen und Performance-Charakteristiken.
- **P3 — Bit-genaue Veröffentlichung des Inhalts.** Wo Records publiziert werden, sind sie bit-genau. Die operative Publikations-Pipeline (§10) führt höchstens reine Batch- und Ordering-Operationen aus und manipuliert keine Record-Inhalte.
- **P4 — Defense in Depth gegen Poisoning.** Mehrere Verteidigungsschichten gegen falsche IOCs: (a) Spectrum-Audit gegen Disruption, (b) Hash-Blacklist gegen Multi-Submission durch einen Submitter, (c) Fingerprint-Robustheit gegen "kosmetisch verändertes Re-Submit", (d) Client-Threshold gegen Single-Source-Behauptungen.
- **P5 — Implementierungs-Robustheit vor kryptographischer Eleganz.** Wir nutzen erprobte Primitiven (BLAKE3, Curve25519, AES-PRG) statt experimenteller Konstrukte.

### 1.2 System-Übersicht

```
                ┌──────────────────────────────────────────────────────┐
                │                  CHORUS System                      │
                │                                                      │
   Members      │  ┌─────────┐    ┌─────────┐    ┌─────────┐          │
   (Alice,      │  │ Alice   │    │  Bob    │ …  │ Member  │          │
    Bob, …)     │  └────┬────┘    └────┬────┘    └────┬────┘          │
                │       │              │              │                │
                │       │ every BOOTSTRAP_ROUND every MAIN_ROUND       │
                │       │              │              │                │
                │       ▼              ▼              ▼                │
                │  ┌────────────────────────────────────────────┐     │
                │  │  Bootstrap Phase                           │     │
                │  │  (Riposte-style anonymous channel claim)   │     │
                │  │  Output: published list of L g^α channels  │     │
                │  └────────────────┬───────────────────────────┘     │
                │                   │ valid for one window            │
                │                   ▼                                 │
                │  ┌────────────────────────────────────────────┐     │
                │  │  Main Phase (Spectrum)                     │     │
                │  │  - DPF-share writes to L channels          │     │
                │  │  - Carter-Wegman MAC for access control    │     │
                │  │  - Fingerprint hash H(fp) attached         │     │
                │  │  - Cover clients send random hash          │     │
                │  └────────────────┬───────────────────────────┘     │
                │                   │ aggregated channels             │
                │                   ▼                                 │
                │  ┌────────────────────────────────────────────┐     │
                │  │  Hash Blacklist Check                      │     │
                │  │  (weekly rotating bloom/set)               │     │
                │  └────────────────┬───────────────────────────┘     │
                │                   │ deduplicated                    │
                │                   ▼                                 │
                │  ┌────────────────────────────────────────────┐     │
                │  │  Publikations-Pipeline                     │     │
                │  │  (Batch-Coarsening, signierte Veröffentl.) │     │
                │  └────────────────┬───────────────────────────┘     │
                │                   ▼                                 │
                │  ┌────────────────────────────────────────────┐     │
                │  │  Public Bulletin Board (signed by both)    │     │
                │  └────────────┬───────────────────────────────┘     │
                │               │                                     │
                │               ▼                                     │
                │       ┌────────────────────────────┐                │
                │       │  Consumer                  │                │
                │       │  - Parse, normalize, fp    │                │
                │       │  - Fingerprint counter     │                │
                │       │  - Threshold-T verification│                │
                │       │  - Emit to SIEM            │                │
                │       └────────────────────────────┘                │
                └──────────────────────────────────────────────────────┘
```

### 1.3 Hauptphasenfluss

Window-Granularität (z.B. 6 Stunden):

```
[Bootstrap-Phase] ─► [Main-Phase #1] ─► [Main-Phase #2] ─► … ─► [Main-Phase #36] ─► [Bootstrap-Phase #2] ─► …
                          (10 Min)         (10 Min)              (10 Min)
```

Pro Window: 1 Bootstrap, danach 36 Main-Phasen (bei 10-min-Main-Phase und 6-h-Window).

---

## 2. Notation und kryptographische Bausteine

### 2.1 Notation

| Symbol | Bedeutung |
|---|---|
| $\lambda$ | Sicherheitsparameter, $\lambda = 128$ |
| $\mathcal{P} = \{P_1, \ldots, P_n\}$ | registrierte Mitglieder, statische Liste |
| $S_A, S_B$ | die beiden Spectrum-Server (non-colluding) |
| $L$ | Anzahl Broadcaster-Channels pro Window, fix konfiguriert |
| $w$ | Window-Index |
| $r$ | Main-Round-Index innerhalb eines Windows, $r \in \{1, \ldots, R\}$ |
| $\alpha_j$ | Broadcast-Key für Channel $j$ |
| $g^{\alpha_j}$ | öffentlicher Verifikations-Key für Channel $j$ |
| $\mathbb{F}$ | endlicher Körper für Spectrum-MAC, hier $\mathbb{F}_p$ mit $p$ prime von $\approx 2^{128}$ |
| $\mathbb{G}$ | zyklische Gruppe (Curve25519-Punkte) für $g^{\alpha}$-Operationen |
| $|m|$ | Nachrichten-Größe in Bytes (≤ 32 KB für CHORUS) |
| $\mathsf{fp}(m)$ | STIX-Fingerprint, $\{0,1\}^{256}$ |
| $H$ | kryptographische Hash-Funktion (BLAKE3) |
| $\mathsf{BL}_w$ | Hash-Blacklist für Window $w$ |
| $T$ | client-seitiger Verifikations-Threshold (typisch $T=3$) |

### 2.2 Kryptographische Bausteine

| Baustein | Konkrete Wahl (v0.2) | Quelle |
|---|---|---|
| Anonymous Broadcast (Main) | Spectrum 2-Server | Newman et al., NSDI 2022 |
| Anonymous Bootstrap | Riposte (single-channel, low-bandwidth) | Corrigan-Gibbs et al., S&P 2015 |
| Distributed Point Function | 2-Server DPF mit AES-PRG | Boyle-Gilboa-Ishai 2016 |
| Access Control MAC | Carter-Wegman MAC über $\mathbb{F}$ | Carter & Wegman 1981 |
| Audit-Verifikation | Spectrum blind audit via $\mathbb{G}$-Operationen | Spectrum §3.1 |
| Audit-Attack-Defense | BlameGame (verifiable encryption + Byzantine broadcast) | Spectrum §4.3 |
| Hash-Funktion | BLAKE3 (für Fingerprint-Hash und PRGs) | O'Connor et al. 2020 |
| PRG | AES-CTR-128 | NIST SP 800-38A |
| Anonymous Credentials (Membership) | BBS+ Signatures | Au-Susilo-Mu 2006 |
| Signaturen (Server-Publication) | Ed25519 | RFC 8032 |
| Public-Key-Encryption (Setup) | NaCl `box` über Curve25519 | Bernstein |

### 2.3 Notations-Kürzel

```
DPF.Gen(1^λ, m, j) → (k_A, k_B)        Spectrum-DPF für Channel j mit Nachricht m
DPF.Eval(k) → m_vec ∈ F^L              Auswertung über alle L Channels
MAC.Tag(α, m) = α·m ∈ F                Carter-Wegman MAC
MAC.Share(t) → (t_A, t_B)              additives Sharing der Tag
ServerAudit(m_A, m_B, t_A, t_B,        Spectrum Audit:
            g^α_1, ..., g^α_L)         prüft ∏ g^β_i = 1
fp(stix) → bytes32                     Fingerprint (siehe §8)
BL.Contains(h) / BL.Add(h)             Blacklist-Operationen
H(x) = BLAKE3(x)                       Hash
PRG(seed, n) → bytes                   Pseudo-random byte stream
```

---

## 3. Systemrollen und Vertrauensannahmen

### 3.1 Rollen

**Mitglieder $\mathcal{P}$ (Members).** Jede Organisation, die am ISAC teilnimmt. In jeder Phase (Bootstrap und Main) sind sie *immer* aktiv. Pro Window kann ein Mitglied wahlweise als *Broadcaster* (will senden) oder als *Subscriber* (nur Empfangen + Cover) auftreten. Diese Rolle ist pro Window aufs Neue wählbar.

**Server $S_A, S_B$.** Zwei unabhängig betriebene Server. Verarbeiten DPF-Shares, führen Audits durch, publizieren ihre aggregierten Shares. Pseudonym-Blacklist und post-aggregation Verifikation laufen im *Verifier* (siehe §7.3.3, §12.5), nicht in den Spectrum-Servern.

**ISAC-Authority $\mathcal{I}$.** Vergibt BBS+-Credentials bei Member-Onboarding. Nicht in Bootstrap/Main involviert.

**Consumer.** Liest die publizierte DB. Können Mitglieder sein (die meisten Subscriber sind selbst Consumer ihrer Peers) oder externe Subscriber (z.B. nationale CERTs).

### 3.2 Vertrauensannahmen

- **A1 — Server-Non-Collusion.** Mindestens *einer* von $S_A, S_B$ ist ehrlich. Spectrum-Standard. Praktisch: getrennte juristische Entitäten.
- **A2 — Network-Adversary.** Adversary sieht alle TLS-verschlüsselten Verbindungen, aber kann Klartexte nicht entschlüsseln.
- **A3 — Member-Adversary.** Beliebige Teilmenge $\mathcal{C} \subset \mathcal{P}$ kann maliciös sein. Sie können maliciöse DPF-Schlüssel schicken (Disruption-Attacke), gezielte Cover-Traffic-Muster, oder false IOCs broadcasten (Poisoning).
- **A4 — Standard-Crypto-Annahmen.** DDH in $\mathbb{G}$ (Curve25519), AES-PRG-Sicherheit, BLAKE3 als Random Oracle.
- **A5 — Setup-Free-Initialization.** Wir akzeptieren die Spectrum-Annahme: das System hat einmaliges öffentliches Setup (PKI für Server, BBS+-Authority-Key). Kein anhaltendes Vertrauen in $\mathcal{I}$ nach Issuance.

### 3.3 Adversary-Modelle

| Adversary | Kontrolliert | Schutzziel | Defense |
|---|---|---|---|
| $\mathcal{A}_{\mathrm{Server}}$ | $S_A$ ODER $S_B$ (nicht beide) | Sender-Anonymität | Spectrum-Anonymity (Theorem 1) |
| $\mathcal{A}_{\mathrm{Member}}^{\mathrm{Disrupt}}$ | maliciöse Members senden ill-formed shares | Liveness | Spectrum-Audit + BlameGame |
| $\mathcal{A}_{\mathrm{Member}}^{\mathrm{Poison}}$ | maliciöse Members broadcasten falsche IOCs | DB-Qualität | Hash-Blacklist + Client-Threshold |
| $\mathcal{A}_{\mathrm{Pub}}$ | passiver Beobachter der publizierten DB | Aggregate-Metadata-Leakage | *außerhalb des CHORUS-v0.2-Scope; orthogonale Forschungslinie, siehe §18.2 und `expose_output_privacy.md`* |
| $\mathcal{A}_{\mathrm{Net}}$ | Network-Adversary | Anonymity-Set-Information | Konstante $L$ + immer-aktive Member |

---

## 4. Parameter und Konfiguration

### 4.1 Globale Konfiguration

```yaml
# chorus-config.yaml

system:
  name: "CHORUS"
  version: "0.2"
  base_protocol: "Spectrum (NSDI 2022)"
  bootstrap_protocol: "Riposte (S&P 2015)"

security:
  lambda: 128
  field_prime: "2^130 - 5"        # Curve25519 base prime, Spectrum-compatible
  hash: "BLAKE3"
  prg: "AES-CTR-128"
  curve: "Curve25519 / Ristretto255"

window:
  duration_hours: 1                 # v0.2 default; future work: empirical tuning
  main_rounds_per_window: 6        # = 1h / 10min
  bootstrap_duration_minutes: 2    # one-shot per window

main_round:
  duration_seconds: 600            # 10 min
  max_message_size_bytes: 32768
  channels_L: 20                   # maximum simultaneous broadcasters
                                   # per window; fixed at system level

bootstrap_round:
  underlying_system: "riposte"
  message_size_bytes: 64           # broadcast-key g^α + channel claim
  audit_required: true

fingerprint:
  function: "structured_digest_v1"  # see §8.2
  output_bytes: 32

pseudonym:                          # NEW in v0.2 (replaces two-hash construction)
  group: "ristretto255"
  hash_to_curve: "RFC 9380"         # for H_fp = HashToCurve(fp)
  pseudonym_function: "P = H_fp^{k_i^(w)}"
  zkp_statement: "∃ x : g^x ∈ Member-Roster ∧ P = H_fp^x"
  zkp_scheme: "BBS+_bound"          # alt: "schnorr_or_proof", "groth-kohlweiss"
  client_scalar_k_i_lifecycle: "issued_at_onboarding_rotated_weekly"

verifier:
  position: "consumer_side"         # default in v0.2
  optional_dedicated_verifier: true # may be deployed as separate service
  trust_model: "honest_but_curious"

blacklist:
  retention_window: "weekly"
  reset_period_seconds: 604800     # 7 days
  storage: "in_memory_bloom_filter_with_persistent_backup"

output_privacy:
  enabled: true
  m1_delay_distribution:
    type: "geometric_truncated"
    mean_rounds: 2
    max_rounds: 6
  m2_synthetic_channel_injection:
    enabled: false                 # REMOVED in v0.2 per design decision —
                                   # all members send every round (real or cover),
                                   # so synthetic channel filling is unnecessary.
  m3_type_bucketing:
    bucket_count: 4
  m4_batch_coarsening:
    rounds_per_meta_batch: 6

client_threshold:
  default_T: 3                     # consumer trust threshold
  evidence_window_rounds: 6        # one full window of evidence (1h)
  decay: "exponential_weekly"

abuse:
  legacy_threshold_deanon: false   # disabled in v0.2; see §18
```

### 4.2 Parameter-Begründung

- **$L = 20$:** typische CTI-Aktivität in ISAC mit $n = 50$–$500$ Mitgliedern: < 10 simultane Broadcaster pro 10-min-Fenster. $L = 20$ gibt Puffer.
- **Window = 1h (v0.2 Default):** Bootstrap-Amortisation: ein anonymes Riposte-Setup pro Stunde, dann 6 Main-Rounds. Reduziert Setup-Overhead vs. Pro-Round-Setup um Faktor 6. Kurzes Window minimiert die Intra-Window-Linkability (Submissions desselben Channels sind während des Windows linkbar — siehe §14.2). *Future Work:* Optimale Window-Länge empirisch zu bestimmen; siehe §18.2.
- **Main-Round = 10 min:** akzeptable Latenz für operative IOCs.
- **$T = 3$:** epidemiologische Wahrheits-Schwelle. Bei $T = 3$ muss ein Angreifer drei Window-Slots auf drei verschiedenen Identitäten gleichzeitig kontrollieren, um eine False-IOC durchzubringen.
- **Content-Bound Linkable Pseudonym:** $P = H_\mathsf{fp}^{k_i^{(w)}}$ wird im DPF-Payload (nicht plaintext!) mitgeschickt. Ein post-Aggregation-Verifier prüft das ZKP $\pi$ und das Self-Binding gegen den re-computeten Fingerprint. Deterministisch in (Member, IOC, Woche), Server-überprüfbar via Ring-Membership-Proof, kollisionsresistent gegen DDH. Cover-Submissions enthalten keinen Pseudonym-Wert — sie sind Spectrum-Zero-Shares und tragen nach Aggregation keinen verwertbaren Inhalt.

### 4.3 Long-Term Member State und Schlüssel-Lifecycle

Jedes Mitglied $P_i$ verwaltet folgende langlebigen Geheimnisse, die im Onboarding angelegt werden:

```
Onboarding (one-time, mit ISAC-Authority I):

  1. P_i authentifiziert sich klassisch bei I (X.509, Identitätsprüfung, ...).
  2. I weist P_i eine member_id zu (öffentlich, gehört in Member-Roster).
  3. P_i wählt clientseitig (niemals I bekannt):
       K_i_master  ← random_bytes(32)
  4. I führt BBS+ blind issuance aus, wobei k_i als verstecktes Attribut
     gebunden wird:
       k_i ← scalar_from_K_master(K_i_master, "chorus-base-scalar")
              // k_i ∈ Z_q (Skalar in der Ristretto255-Gruppe)
       cred_i ← BBS+.Sign(sk_I,
                          attributes = (member_id,
                                        commit(k_i),
                                        sector, jurisdiction))
     Hier ist commit ein Pedersen-Commitment, sodass I den Wert k_i nicht
     lernt, aber das Credential ihn bindet.
  5. P_i bewahrt (cred_i, K_i_master, k_i) privat auf.
  6. Public-Key pk_i ← g^{k_i} wird in das Member-Roster aufgenommen.

Pro Woche w (automatisch, ohne Interaktion mit I):

  k_i^(w) ← scalar_from(HKDF(K_i_master,
                              salt = "chorus-week-" || encode(w),
                              info = "chorus-week-scalar-v1",
                              length = 64))
            // 64 Bytes → modular reduzieren auf Z_q für Bias-Vermeidung
  pk_i^(w) ← g^{k_i^(w)}
  // Member publiziert pk_i^(w) zu Beginn der Woche an die Server.
  // Die Server aggregieren alle pk_j^(w) zu einem signierten
  // "Weekly Roster" R^(w).
```

**Eigenschaften:**

- $K_i^{\text{master}}$ ist ein Long-Term-Geheimnis pro Mitglied; nie an die ISAC-Authority weitergegeben (per BBS+ blind issuance).
- $k_i^{(w)}$ ist der *operative* DH-Skalar für die Woche $w$. Daraus werden alle Pseudonyme abgeleitet: $P = H_\mathsf{fp}^{k_i^{(w)}}$.
- Wöchentliche Rotation verhindert Cross-Week-Linkability: Pseudonyme verschiedener Wochen sind kryptographisch entkoppelt, auch für dasselbe Mitglied und denselben Fingerprint.
- Bei Kompromittierung von $K_i^{\text{master}}$: alle vergangenen $k_i^{(w)}$ können rekonstruiert werden. Mitigation: periodisches $K_i^{\text{master}}$-Refresh über die ISAC-Authority (z.B. jährlich oder bei Anomalie-Detektion) — als Future-Work-Item dokumentiert.
- **Single-Identity-Assumption (kritisch).** Die Sicherheit des Threshold-Schutzes (§11) hängt davon ab, dass ein Angreifer höchstens $T - 1$ Member-Identitäten kontrolliert. Diese Sybil-Resistenz ist Aufgabe des ISAC-Onboardings (Identitätsprüfung, X.509, etc.), nicht des Submission-Protokolls. Ohne Sybil-Resistenz kann ein Angreifer $T$ verschiedene $k_i$ kontrollieren und damit selbst-bestätigte False-IOCs einschleusen.

---

## 5. Zwei-Phasen-Architektur

### 5.1 Window-Struktur

Ein **Window** $w$ ist die Persistenz-Einheit für Broadcaster-Channels. Innerhalb eines Windows sind die in der Bootstrap-Phase registrierten Broadcaster-Channels gültig und können in jeder Main-Round genutzt werden.

```
T_0 ─ Bootstrap_w ─ Main_w_1 ─ Main_w_2 ─ … ─ Main_w_6 ─ Bootstrap_{w+1} ─ …
       (2 min)      (10 min)   (10 min)       (10 min)   (2 min)
       |←─────────────────  Window w (1h)  ────────────→|
```

### 5.2 Rollen pro Window

Vor jedem Window entscheidet jedes Mitglied $P_i$ unabhängig:

- **Broadcaster-Rolle:** Hat Content zu teilen → meldet sich in Bootstrap an, broadcastet in beliebigen Main-Rounds des Windows.
- **Subscriber-Rolle:** Will nur konsumieren → schickt Cover-Traffic in Bootstrap und allen Main-Rounds.

**Wichtig:** Diese Rollen-Wahl wird *innerhalb des Bootstrap-Protokolls anonym getroffen*. Ein Mitglied sendet entweder eine echte Channel-Claim-Nachricht oder eine Zero-Cover-Nachricht. Aus Server-Sicht sind beide ununterscheidbar.

### 5.3 Window-Limits

Pro Window gibt es höchstens $L$ Channels. Wenn $> L$ Mitglieder broadcasten wollen, müssen die Überschuss-Anwärter warten (Lotterie via shared PRG, siehe §6.3). Wenn $< L$ sich anmelden, bleiben die freien Channel-Slots schlicht leer — *keine* synthetische Befüllung. Konsequenz: Die effektive Anzahl Channels pro Window $L_r \le L$ ist eine *beobachtbare* Größe für externe Beobachter. Volume-Hiding wird stattdessen durch die Pflicht-Teilnahme aller $N$ Mitglieder als Cover-Subscriber abgesichert (Spectrum-Anonymity über das volle Anonymity-Set).

---

## 6. Bootstrap-Phase (Riposte-basiert)

### 6.1 Zweck

Die Bootstrap-Phase erfüllt zwei Funktionen:

1. **Channel-Key-Registrierung:** Mitglieder, die im kommenden Window broadcasten wollen, schicken einen frisch generierten Broadcast-Key $g^{\alpha_j}$ anonym an die Server.
2. **Channel-Index-Assignment:** Jeder Broadcaster erfährt anonym, welche Channel-Nummer $j \in \{1, \ldots, L\}$ ihm zugewiesen ist.

### 6.2 Bootstrap-Protokoll

```
Algorithm 1: Bootstrap.Run(window w, member P_i)

Input:
  - role: "broadcaster" oder "subscriber" (intern entschieden)
  - cred_i: BBS+ membership credential
  - new_key:  α ∈ Z_p, fresh per window if role=broadcaster
  - claim_idx: j ∈ {1, ..., L} (optional, sonst random)

Steps:

B1.  IF role = "broadcaster":
         payload ← serialize(g^α, claim_idx, nonce_b)
     ELSE:
         payload ← random_bytes(64)            // cover

B2.  // ZK-Proof π_B: "ich bin valides Mitglied"
     π_B ← BBS+.Prove(cred_i, ε)

B3.  // Riposte write
     (shareA, shareB) ← Riposte.Encode(payload)
     send_to(S_A, { window=w, shareA, π_B })
     send_to(S_B, { window=w, shareB, π_B })

B4.  // Server-Side (siehe Alg. 2)
     ...

B5.  // Server publiziert Channel-Liste
     CL_w ← receive_from_server()

B6.  IF role = "broadcaster":
         find own (g^α, j) in CL_w
         store (α, j) locally for use in main rounds
     ELSE:
         CL_w ist nur für Audit relevant
```

```
Algorithm 2: Bootstrap.Server.Aggregate(window w)

Steps:

S1.  Beide Server akzeptieren während der Bootstrap-Phase Submissions.

S2.  Validieren π_B (BBS+ Membership) für jede eingehende Submission.

S3.  Riposte-Aggregation: Server XOR ihre Anteile und erhalten die
     L Schreibvorgänge in einer öffentlich publizierten Tabelle.
     Slots mit kollidierenden claim_idx werden via Tie-Breaking aufgelöst
     (deterministisch via Hash der Inhalte).

S4.  Resultat: Liste CL_w = [(g^α_1, j=1), ..., (g^α_L', j=L')]
     mit L' = Anzahl tatsächlicher Broadcaster-Submissions.

S5.  KEIN Synthetic-Channel-Injection (Designänderung v0.2). Wenn L' < L,
     bleibt CL_w einfach kleiner. Channels ohne Anmeldung sind in den
     Main-Rounds inaktiv (Ø).

S6.  Beide Server signieren CL_w gemeinsam:
        σ_w ← Ed25519.Sign(sk_A, CL_w) || Ed25519.Sign(sk_B, CL_w)
     Veröffentlichung: (CL_w, σ_w).

S7.  Initialisierung des Main-Round-Zustands für Window w mit den L' aktiven
     Channels.
```

### 6.3 Channel-Index-Tie-Breaking

Wenn zwei Mitglieder denselben `claim_idx` $j$ wählen (selten, aber möglich bei zufälliger Wahl), gewinnt deterministisch derjenige mit dem niedrigeren $H(g^{\alpha} \| \mathrm{nonce})$. Der Verlierer wird einem freien Slot zugewiesen. Falls alle Slots besetzt: Verlierer ist diesem Window kein Broadcaster und muss im nächsten Bootstrap erneut versuchen.

### 6.4 Sicherheitseigenschaften der Bootstrap-Phase

- **Anonymität:** Riposte garantiert Sender-Anonymität gegenüber $\mathcal{A}_{\mathrm{Server}}$ und $\mathcal{A}_{\mathrm{Net}}$. Server sehen $L'$ Channel-Anmeldungen, aber nicht, wer sie eingereicht hat.
- **Membership-Soundness:** BBS+-Proof verhindert, dass Nicht-Mitglieder einen Channel claimen.
- **Volume-Beobachtbarkeit:** $L'$ pro Window ist *beobachtbar*. Das ist eine bewusst akzeptierte Schwäche zugunsten der operativen Klarheit (siehe Designentscheidung in §5.3). Eine Behandlung der dadurch entstehenden Aggregat-Leckage ist nicht Teil von v0.2; sie ist als orthogonale Folgearbeit positioniert (§14.4, §18.2).

### 6.5 Bandbreiten-Analyse Bootstrap

Pro Mitglied: 64-Byte-Payload + 5-KB-BBS+-Proof + Riposte-Overhead $O(\sqrt{N})$. Bei $N = 100$ ist Bootstrap-Cost pro Mitglied $\approx 7$ KB. Bei 4 Windows/Tag = 28 KB/Tag pro Mitglied — vernachlässigbar.

---

## 7. Main-Phase (Spectrum-basiert)

### 7.1 Pro-Round-Submission

Pro Main-Round $r$ innerhalb Window $w$ submittet jedes Mitglied $P_i$ eine Submission. Wenn $P_i$ in Window $w$ als Broadcaster (Channel $j$, Key $\alpha_j$) registriert ist, kann es eine reale Nachricht $m$ schicken; andernfalls schickt es eine Cover-Submission ($m = 0$).

```
Algorithm 3: Main.Submit(window w, round r, role, stix_bundle, j, α_j)

Input:
  - w, r:        Window/Round-Indizes
  - role:        "broadcast" or "cover"
  - stix_bundle: STIX bundle (only if broadcasting), size ≤ slot_size - overhead
  - j, α_j:      channel and key (only if broadcasting)
  - k_i^(w):     client's weekly DH scalar (from §4.3)
  - R^(w):       signed weekly member roster (list of pk_j^(w))
  - cred_i:      BBS+ membership credential (from §4.3)

Steps:

M1.  IF role = "broadcast":
         y, j' ← α_j, j
         fp        ← Fingerprint.Compute(stix_bundle)
         H_fp      ← HashToCurve(fp)              // RFC 9380, in Ristretto255
         P         ← H_fp^{k_i^(w)}               // linkable pseudonym
         π         ← ZKProof.Prove(
                       statement = (R^(w), fp, P, g, H_fp),
                       witness   = (k_i^(w), index_in_roster, cred_i),
                       relation  = "∃ x : (g^x ∈ R^(w))
                                   AND  (P = H_fp^x)
                                   AND  (x is the k-attribute of cred_i)"
                     )
         // π hat eine BBS+-bound Konstruktion: ~1-2 KB, ~50 ms generate
         m_payload ← serialize(stix_bundle, fp, P, π)
                     // assembled into ≤ slot_size bytes via length prefixes
     ELSE:
         y, j' ← 0, 0
         m_payload ← 0_F^L                          // Spectrum zero share

M2.  // DPF-Generation (Spectrum §3.2 / §4.2)
     IF role = "broadcast":
         (k_A, k_B) ← DPF.Gen(1^λ, m_payload, j')
     ELSE:
         (k_A, k_B) ← DPF.Gen(1^λ, 0, 0)             // dummy DPF

M3.  // Carter-Wegman MAC-Tag (Spectrum unchanged)
     IF role = "broadcast":
         t ← y · m_payload                            // ∈ F
     ELSE:
         t ← 0
     (t_A, t_B) ← Share(t)

M4.  // Submission packets — NO plaintext metadata about content
     msg_A ← { w, r, k_A, t_A }
     msg_B ← { w, r, k_B, t_B }

M5.  send_to(S_A, msg_A)
     send_to(S_B, msg_B)
```

**Wichtige Anmerkungen:**

*(a) Was im Payload steckt.* Der Broadcaster bettet *vier* Werte in den Channel-Payload ein: das eigentliche STIX-Bundle, das explizite `fp` (zur Self-Binding-Überprüfung), das Pseudonym $P$, und den ZKP $\pi$. Alle vier sind via DPF secret-shared — kein einzelner Server sieht sie pre-Aggregation.

*(b) Was die Server pre-Aggregation sehen.* Nur DPF-Shares und MAC-Tag-Shares. Beide sind durch Spectrum's Konstruktion pseudozufällig. Es gibt *keine* plaintext Pseudonym- oder Hash-Metadaten — damit kann auch ein malicious Server keine Submission↔Channel-Linkage über solche Metadaten herstellen.

*(c) Sybil-Annahme.* Die Soundness des Mechanismus hängt davon ab, dass ein Member nicht mehrere $k_i^{(w)}$ kontrolliert. Der ZKP zwingt dazu, dass $g^{k_i^{(w)}} \in R^{(w)}$ ist und an das BBS+-Credential gebunden ist. Da $R^{(w)}$ aus den Onboardings der ISAC-Authority kommt, ist Sybil-Resistenz eine Onboarding-Eigenschaft, kein Protokoll-Eigenschaft.

*(d) Cover-Submissions.* Spectrum-Zero-Shares — kein Pseudonym, kein ZKP. Da Spectrum's Audit-MAC bei Cover-Submissions automatisch $t = 0$ erzwingt und ehrliche Subscriber keinen gültigen $\alpha_j$ kennen, werden Cover-Submissions strukturell von echten Broadcasts unterschieden — *aber* nicht ihren Submittern zugeordnet (Spectrum-Theorem 1).

### 7.2 Server-Side: Audit and Aggregation

**Wichtige Architektur-Änderung in v0.2:** Die Verifikation (ZKP-Check, Self-Binding, Blacklist) findet *nicht* auf den Spectrum-Servern $S_A, S_B$ statt, weil diese nur ihre eigenen Aggregations-Shares publizieren und nicht untereinander aggregieren. Stattdessen findet die Verifikation *post-Aggregation* statt — entweder bei einem dedizierten Verifier-Service oder direkt beim Consumer. Beide Optionen sind unter einer honest-but-curious Annahme sicher (§14.x).

```
Algorithm 4a: Spectrum.Server.Process(round r, batch of submissions)
              [running on S_A; analog für S_B]

Steps:

P1.  Für jede Submission { k_A, t_A } in dieser Round:
     P1.1  m_i ← DPF.Eval(k_A) ∈ F^L
     P1.2  // Spectrum audit using channel verification keys
            β ← ∏_{j=1}^{L'} (g^{α_j})^{m_i[j]} · g^{-t_A}
     P1.3  Wenn die Audit-Check ∏ g^β = 1 fehlschlägt:
            Submission ablehnen, BlameGame initiieren (§7.5).
     P1.4  Andernfalls: aggregieren in agg_A[r]

P2.  Nach Verarbeitung aller Submissions:
     P2.1  agg_A[r] ← Σ_{i passed audit} m_i_A ∈ F^{L'}
     P2.2  Server S_A publiziert agg_A[r] (signiert) auf seinem öffentlichen
            Endpunkt. Analog: S_B publiziert agg_B[r].
            → Keine Inter-Server-Kommunikation der aggregierten Shares!

P3.  Initialer Round-Output:
     channels_raw[r] = { agg_A[r], agg_B[r] } öffentlich abrufbar.
     → Die finale Aggregation channels[r] = agg_A[r] + agg_B[r]
       findet beim Verifier/Consumer statt.
```

```
Algorithm 4b: Verifier.ProcessRound(round r)
              [running at dedicated verifier OR at each consumer]

Steps:

V1.  Lade agg_A[r] von S_A und agg_B[r] von S_B (mit signature checks).

V2.  Aggregiere finale Channel-Inhalte:
     channels[r] ← agg_A[r] + agg_B[r] ∈ F^{L'}

V3.  Für jeden non-empty channel j in channels[r]:
     V3.1  // Parse Payload-Struktur
            (stix_bundle, fp_claimed, P, π) ← deserialize(channels[r][j])

     V3.2  // SELF-BINDING-CHECK
            fp_recomputed ← Fingerprint.Compute(stix_bundle)
            IF fp_recomputed ≠ fp_claimed:
                Markiere channel als "self-binding-fail".
                Channel bleibt in der publizierten DB, aber wird mit
                Marker versehen. Konsumenten/SIEM-Filter ignorieren ihn.
                CONTINUE next channel.

     V3.3  // ZKP-VERIFIKATION
            valid ← ZKProof.Verify(
                       statement = (R^(w), fp_claimed, P, g, H_fp_claimed),
                       proof = π
                    )
            IF NOT valid:
                Markiere channel als "zkp-fail".
                Konsumenten/SIEM-Filter ignorieren ihn.
                CONTINUE next channel.

     V3.4  // BLACKLIST-CHECK (Duplikat-Detektion)
            IF P ∈ B^(w):
                Markiere channel als "duplicate".
                → KEIN Ban, kein Verbannen. Channel bleibt in der DB,
                  aber Konsumenten zählen ihn nicht im Threshold-Counter.
                  (Konsequenz: derselbe Member kann denselben fp
                  innerhalb der Woche nur einmal in den
                  Threshold-Counter einbringen.)
            ELSE:
                B^(w).add(P)

     V3.5  Channel j ist gültig (oder mit Markierung versehen).
            → Wird publiziert, ggf. mit Markierung "self-binding-fail",
              "zkp-fail", "duplicate".

V4.  Verifizierte Round-Publikation:
     verified_publication[r] = { channels[r] mit pro-Channel-Markierungen,
                                  Verifier-Signatur }
```

**Was passiert bei "Schummeln" konkret:**

- Falls **Self-Binding-Fail**: Der Submitter hat $\mathsf{fp}_\mathsf{claimed}$ angegeben, das nicht zu seinem stix_bundle passt. Konsument kann sehen, *dass* etwas nicht stimmt, *kann aber nicht* identifizieren, *wer* es war (anonym im Ring). Der Channel ist als "self-binding-fail" markiert und wird vom SIEM-Filter ignoriert.
- Falls **ZKP-Fail**: Der ZKP ist mathematisch ungültig. Analoge Behandlung. (Sollte praktisch nie auftreten, weil ein ehrlicher Submitter immer einen gültigen ZKP konstruieren kann; ein böser kann unter Soundness-Annahme keinen gültigen für eine falsche Behauptung produzieren.)
- Falls **Duplikat**: Derselbe Member hat denselben fp diese Woche bereits eingereicht. Channel bleibt in der DB (für Audit-Trail), aber wird nicht zum Threshold-Counter gezählt.

**Kein expliziter Member-Ban mehr.** Da Verifier nicht weiß, wer der Submitter ist (Ring-Anonymität), kann er auch nicht "permanent verbannen". Konsequenz ist Channel-Slot-Verschwendung + öffentliche Markierung. Threshold-Mechanismus (§11) übernimmt den eigentlichen Schutz.

### 7.3 Pseudonym-Konstruktion und Anonymitäts-Garantie

CHORUS verwendet **content-bound linkable Pseudonyme** mit ZKP-basierter Soundness und post-Aggregation-Verifikation. Die Konstruktion löst alle drei zentralen Anforderungen simultan:

1. **Member-spezifisch:** Pseudonym $P = H_\mathsf{fp}^{k_i^{(w)}}$ hängt von $k_i^{(w)}$ ab. Verschiedene Member produzieren verschiedene $P$ für dasselbe IOC.
2. **Inhalts-gebunden:** $P$ ist deterministisch in $\mathsf{fp}$. Derselbe Member produziert dasselbe $P$ für dasselbe IOC — Blacklist-Match.
3. **Anonymitätswahrend:** Das ZKP versteckt, *welches* $k_i^{(w)}$ aus dem Ring verwendet wurde. $P$ ist DDH-pseudozufällig.

### 7.3.1 Soundness-Argument

**Behauptung 1 (Inhalts-Bindung):** Ein Submitter kann nicht $P = H_\mathsf{fp'}^{k_i^{(w)}}$ für ein $\mathsf{fp'} \ne \mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})$ über den Self-Binding-Check schmuggeln.

*Beweisskizze:* Der Verifier rechnet $\mathsf{fp}_\mathsf{recomputed} = \mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})$ aus dem aggregierten Channel-Inhalt. Self-Binding prüft $\mathsf{fp}_\mathsf{claimed} \stackrel{?}{=} \mathsf{fp}_\mathsf{recomputed}$. Das ZKP-Statement bindet $P$ an $\mathsf{fp}_\mathsf{claimed}$ (Bedingung 2 des Statements). Damit: $P = H_{\mathsf{fp}_\mathsf{recomputed}}^{k_i^{(w)}}$.

**Behauptung 2 (Member-Bindung):** Ein Submitter kann nicht ein anderes $k_j^{(w)}$ für seine Submission verwenden als das, das im Member-Roster registriert ist und ihm gehört.

*Beweisskizze:* Das ZKP-Statement verlangt $g^x \in R^{(w)}$ (Ring-Membership). Wenn der Submitter ein $x$ wählt, muss $g^x$ in der publizierten Liste sein. Die Liste enthält die $\mathsf{pk}_j^{(w)}$ aller Mitglieder. Ein Submitter kennt:
- Sein eigenes $k_i^{(w)}$ — darf er verwenden ✓
- Andere $k_j^{(w)}$ — kennt er nicht (Discrete-Log-Annahme verhindert Inversion von $\mathsf{pk}_j^{(w)}$)
- Frische $k^*$ — $g^{k^*}$ wäre nicht im Roster, ZKP-Ring-Membership scheitert

Damit: $P = H_\mathsf{fp}^{k_i^{(w)}}$ für genau dieses $k_i^{(w)}$. Das Pseudonym ist deterministisch in (Member, $\mathsf{fp}$, Woche).

**Behauptung 3 (Anonymität gegen honest-but-curious Verifier):** Aus $(\mathsf{stix\_bundle}, \mathsf{fp}_\mathsf{claimed}, P, \pi)$ kann der Verifier die Submitter-Identität nicht extrahieren.

*Beweisskizze:* Das ZKP ist Zero-Knowledge bezüglich $k_i^{(w)}$ und damit bezüglich des Index im Ring. $P$ ist unter DDH von einem zufälligen Gruppenelement ununterscheidbar. Damit ist die Sicht des Verifiers simulierbar aus public Information, ohne Kenntnis der Member-Identität.

### 7.3.2 Was die Konstruktion *nicht* leistet (akzeptierte Schwächen)

- **Sybil-Resistenz.** Ein Angreifer, der $T$ Member-Identitäten kontrolliert (z.B. durch kompromittiertes Onboarding), kann $T$ verschiedene $k_i^{(w)}$ verwenden und damit $T$ unabhängige $P$ für denselben fp erzeugen — der Threshold wird erfüllt. Verteidigung: Onboarding-Prüfung der ISAC-Authority.
- **Verifier-Verfügbarkeit.** Der Verifier (Consumer oder dedizierter Service) muss zuverlässig arbeiten. Bei Ausfall des Verifiers funktioniert die Blacklist-Logik nicht. Mitigation: Verifikation ist replizierbar (jeder Consumer kann selbst verifizieren).
- **Verifier-Konsistenz.** Bei Consumer-Side-Verifikation pflegt jeder Consumer seine eigene Blacklist. Verschiedene Consumer könnten leicht abweichende Sichten haben (z.B. wenn ein Consumer eine Round verpasst). Für einen einzelnen Consumer ist die Konsistenz innerhalb seiner Sicht garantiert.

### 7.3.3 Verifier-Position (Architektur-Optionen)

Die Verifikation kann an drei Stellen stattfinden:

**Option A (v0.2 Default): Consumer-Side.** Jeder Consumer lädt $\mathsf{agg}_A, \mathsf{agg}_B$, aggregiert lokal, verifiziert ZKPs und pflegt seine eigene Blacklist. Vollständig dezentral. Honest-but-curious Consumer können sich nicht gegenseitig deanonymisieren, weil sie ZKP/Pseudonyme nur post-Aggregation sehen.

**Option B: Dedicated Verifier-Service.** Eine dritte Partei lädt Shares, aggregiert, verifiziert, publiziert die verifizierte DB inkl. zentraler Blacklist-Sicht. Effizienter (Verifikations-Arbeit wird nicht repliziert), aber führt eine neue Vertrauenseinheit ein. Trust-Modell: honest-but-curious — Verifier sieht denselben Klartext wie jeder Consumer, kann aber nicht deanonymisieren (siehe Behauptung 3).

**Option C: Hybrid.** Dedicated Verifier als Performance-Default; Consumer können bei Bedarf selbst nachverifizieren.

Die initiale CHORUS-Implementierung verwendet Option A. Optionen B und C sind über das gleiche Verifier-Modul bedienbar (es läuft entweder beim Consumer oder als Service).

### 7.4 Spectrum-Audit-Subroutinen

Diese sind 1:1 aus Spectrum übernommen und in der Referenzimplementierung verfügbar:

- **`AccessControlCheck`** (Spectrum §3.1): Carter-Wegman MAC verification über $\mathbb{G}$.
- **`DPFAudit`** (Spectrum §4.2): blind audit of DPF well-formedness.

### 7.5 BlameGame

Falls ein Server beim Audit eine Submission ablehnt, kann der andere Server vermuten, dass entweder (a) der Klient maliciös war, oder (b) der ablehnende Server lügt. **BlameGame** (Spectrum §4.3) löst das auf:

- Jede Submission ist verifiable encryption committed.
- Bei Audit-Failure: Server publizieren ihre Decryption-Proofs.
- Server, deren Decryption fehlerhaft ist, werden als bad markiert.
- Klient, dessen Submission tatsächlich invalid war, wird dropped.

Dies ist 1:1 aus Spectrum übernommen.

### 7.6 Pro-Round-Bandbreiten-Analyse

| Partei | Pro-Round-Kommunikation |
|---|---|
| Klient → Server (je) | $O(\sqrt{L} + |m|)$ (Spectrum 2-Server-DPF) — bei $L=20$, $|m|=32$ KB: ca. 32 KB |
| Server-zu-Server (Audit) | $O(\lambda)$ = ca. 70 Byte pro Submission |
| Server → Public (publication) | $O(L \cdot |m|)$ pro Round = ca. 640 KB bei $L=20, |m|=32$KB |

Bei $N = 100$, $L = 20$, $|m| = 32$ KB, 10-min-Rounds, 24h/Tag = 144 Rounds:

- Klient-Submit: $100$ Klienten × $32$ KB × $144$ = $\approx 460$ MB upload per ISAC per day
- Public-Download per Consumer: $L \cdot |m| \cdot 144 = 92$ MB/Tag (alle Channels, alle Rounds)

---

## 8. STIX-Fingerprint-Modul

Dies ist das *Kern-Innovationsmodul* von CHORUS über Spectrum hinaus.

### 8.1 Anforderungen

- **Inhalts-Sensitivität:** Zwei Records mit unterschiedlichen IOC-Sets müssen unterschiedliche Fingerprints haben.
- **Beschreibungs-Robustheit:** Zwei Records desselben Vorfalls mit gleichen IOCs aber abweichenden Texten/Metadaten müssen identische Fingerprints haben.
- **Deterministisch:** Gleicher Input → gleicher Output, auf jedem System.
- **Effizient:** Berechnung in < 10 ms pro Record.
- **Stabil unter STIX-Versions-Upgrade.**

### 8.2 `structured_digest_v1` Algorithmus

```
Algorithm 5: Fingerprint.Compute(stix_bundle b)

Steps:

F1.  // Extract canonical observables
     observables ← []
     for each object o in b.objects:
         if o.type = "indicator":
             pattern ← parse_stix_pattern(o.pattern)
             observables.extend(extract_atomic_ioc(pattern))
         else if o.type in ["file", "ipv4-addr", "ipv6-addr",
                            "domain-name", "url", "email-addr",
                            "windows-registry-key"]:
             observables.append(canonicalize_observable(o))
         else if o.type = "attack-pattern":
             // MITRE ATT&CK technique
             observables.append("mitre:" + o.external_references[
                where source_name = "mitre-attack"].external_id)
         else if o.type = "vulnerability":
             observables.append("cve:" + o.name)

F2.  // Normalize each observable
     normalized ← [normalize(obs) for obs in observables]
     // Normalize rules:
     //   - IPv4: dotted quad, no leading zeros
     //   - IPv6: RFC 5952 canonical form
     //   - Domain: lowercase, no trailing dot, IDN decoded
     //   - URL: scheme lowercased, host lowercased, path normalized,
     //          fragment removed, default ports removed
     //   - Hash: lowercase hex, no separators
     //   - CVE/MITRE: uppercase identifier
     //   - File path: case-preserving on UNIX, lowercase on Windows

F3.  // Deduplicate and sort
     normalized ← sorted(unique(normalized))

F4.  // Concatenate with separator
     concat ← join(normalized, "\x1F")    // 0x1F = unit separator

F5.  // Hash
     fp ← BLAKE3(concat)[0..32]

F6.  return fp
```

### 8.3 Was bewusst NICHT in den Fingerprint einfließt

- **Submitter-Identität, Zeitstempel**, `created_by_ref`, `created`, `modified` — sind submission-spezifisch, würden Inkonsistenz erzeugen.
- **`description`, `name`** — natürliche Sprache, variiert zwischen Submittern.
- **`labels`, `confidence`** — subjektive Bewertungen.
- **`valid_until`** — kann pro Submitter variieren.
- **TLP-Marking** — orthogonale Dimension.
- **Granular STIX-Metadaten** wie Object-Refs zwischen STIX-Objekten — strukturabhängig, nicht inhaltsdefinierend.

### 8.4 Offenes Problem: Partial-Overlap und semantische Äquivalenz

**Problemstellung (zu lösen in zukünftiger Iteration):**

Zwei Submitter, die *denselben Cyber-Angriff* beobachten, produzieren oft STIX-Bundles, die sich strukturell unterscheiden, obwohl sie semantisch denselben Vorfall beschreiben. Konkrete Manifestationen:

**(a) Unterschiedliche IOC-Teilmengen.** Submitter A erkennt 3 C2-IPs, Submitter B erkennt 4 (inkl. der 3 von A + 1 weitere, die A nicht sah). Beide melden korrekt, beide sehen denselben Angriff, aber:
$$\mathsf{fp}(\text{A's Bundle}) \ne \mathsf{fp}(\text{B's Bundle})$$
Der clientseitige Threshold-Counter wird sie nicht zusammenführen.

**(b) Heterogene Indikator-Typen.** A meldet primär Datei-Hashes (sieht den Payload), B meldet primär Netzwerk-IPs (sieht den C2-Traffic). Beide beschreiben dieselbe Malware-Kampagne, aber ihre IOC-Sets sind disjunkt.

**(c) Ableitungs-Asymmetrien.** A meldet eine Domain, B meldet die zugehörige IP (per DNS-Lookup zugänglich, aber in STIX-Felder anders kodiert).

**(d) Zeitversetzte Sichtungen.** A sieht den Angriff in seiner Frühphase (Reconnaissance-IPs), B in der Spätphase (Exfiltration-Endpunkte). Beide korrekt, aber andere IOCs.

**Anforderung an die Lösung:**

> *Es soll möglich sein, aus zwei STIX-Bundles, die denselben Angriff beschreiben, mit einer cleveren Technik denselben Fingerprint zu erzwingen — auch wenn die Bundles strukturell differieren.*

**Warum die naheliegenden Lösungen nicht trivial sind:**

- *MinHash / Locality-Sensitive Hashing:* würde Teil-Übereinstimmung erkennen, aber liefert keinen *deterministischen* gemeinsamen Fingerprint. Threshold-Counting würde dann nicht über eindeutige FPs funktionieren, sondern über "FP-Cluster" — was eine zweite Konflikt-Schicht ist (Cluster-Definition, Cluster-Boundary-Drift).
- *Canonical Attack Identifier (z.B. MITRE-Campaign-ID):* würde funktionieren, *wenn* Submitter denselben Identifier verwenden. In der Praxis benennen verschiedene Analysten Angriffe oft unterschiedlich.
- *Server-seitige IOC-Korrelation:* würde Anonymität potenziell brechen, weil Server entscheiden, welche Submissions "zum gleichen Angriff" gehören.

**Status v0.2:** *Problem dokumentiert, Lösung vertagt.* Eine semantik-bewahrende Fingerprint-Konstruktion, die zwei STIX-Bundles desselben Angriffs auf einen gemeinsamen Fingerprint zwingt — im Folgenden als *Semantic Attack Fingerprinting* bezeichnet — wird in einer zukünftigen Iteration ausgearbeitet.

**Übergangslösung v0.2:** Der Consumer-seitige Threshold-Counter ist um eine **atomare IOC-Zähl-Schicht** ergänzt (siehe §11.3). Dort werden nicht nur Fingerprints, sondern auch einzelne atomare Observable (IPs, Hashes, Domains) gezählt. Damit erfassen wir Teil-Übereinstimmungen auf der IOC-Ebene, ohne den Fingerprint zu erweitern. Akzeptiertes Schwächeprofil: ein Angreifer könnte einen False-IOC mit echten, bereits korrobierierten IOCs bündeln und so die atomare Zählung "huckepack" verwenden. Die formale Analyse dieses Risikos ist ebenfalls Teil der Future Work.

### 8.5 Fingerprint-Self-Binding (gelöst in v0.2)

**Problem:** Wie verhindern, dass ein Submitter zwei Submissions desselben STIX-Inhalts mit verschiedenen Member-Spezifischen Tags durchbringt? Das würde den Threshold-Schutz untergraben (Member kann sich selbst $T$-fach bestätigen).

**Lösung v0.2: ZKP-gebundenes Pseudonym + Self-Binding-Verifikation post-Aggregation.** Der Broadcaster bettet vier Werte in den Channel-Payload ein: `stix_bundle`, `fp_claimed`, `P`, `π`. Der Verifier prüft nach Aggregation zwei Bindungen:

$$
\textbf{Bindung 1 (Self-Binding):}\quad \mathsf{fp}_\mathsf{claimed} \stackrel{?}{=} \mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})
$$

$$
\textbf{Bindung 2 (ZKP):}\quad \pi\ \text{is valid for}\ (R^{(w)}, \mathsf{fp}_\mathsf{claimed}, P)
$$

Bindung 1 erzwingt, dass `fp_claimed` der tatsächliche Fingerprint des `stix_bundle` ist. Bindung 2 erzwingt, dass $P$ aus diesem `fp_claimed` und einem Ring-registrierten $k_i^{(w)}$ konstruiert wurde. Zusammen: $P = H_{\mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})}^{k_i^{(w)}}$ für genau das $k_i^{(w)}$ des Submitters.

Konsequenz: Ein Submitter kann seinen $P$ nicht von seinem stix_bundle entkoppeln. Zwei Submissions desselben Inhalts ergeben *zwingend* dasselbe $P$ → Blacklist-Match.

**Warum kein klassisches "Pre-Aggregation Self-Binding via separater Hash" mehr?**

Die naive Konstruktion (separater HMAC-Hash plus embedded Hash) hat einen subtilen Soundness-Bug: weil der Server $K_i^{(w)}$ nicht kennt, kann er den separaten HMAC nicht gegen den embedded Hash verifizieren. Ein bösartiger Submitter konnte beliebigen Müll als separaten Hash senden — und damit denselben Fingerprint mehrfach durchbringen. Der ZKP-basierte Ansatz löst genau dieses Problem: der ZKP zwingt die Bindung kryptographisch, ohne dass der Verifier $k_i^{(w)}$ kennen muss.

**Sanktionspolitik (geändert in v0.2):** Bei Self-Binding-Fail oder ZKP-Fail wird der Channel als ungültig *markiert*, nicht verworfen oder aus der DB entfernt. Konsumenten/SIEM-Filter ignorieren markierte Channels für die Threshold-Zählung. Es gibt **keinen expliziten Member-Ban**, weil der Verifier den Submitter aufgrund der Ring-Anonymität nicht identifizieren kann. Das Ban-Modell ist gegen die hier eingesetzte Anonymitäts-Architektur nicht durchsetzbar — Konsumenten entscheiden lokal über den Umgang mit markierten Channels.

**Bemerkung zur Verifier-Konsistenz:** Verschiedene Verifier (Consumer-Side oder dedizierte Services) müssen dieselbe `Fingerprint.Compute`-Implementation und dasselbe ZKP-Verifikations-Verfahren nutzen, um zu konsistenten Markierungen zu kommen. Bei Versions-Mismatch könnten Konsumenten unterschiedliche Sichten haben — was bei einem dezentralen Modell akzeptabel, aber dokumentations-relevant ist.

**Verbleibendes Schwächeprofil:** Ein Submitter kann zwei *verschiedene* Angriffe in zwei verschiedenen Windows melden — das produziert verschiedene $\mathsf{fp}$ und damit verschiedene $P$. Aber das ist gewünschtes Verhalten. Was das System verhindert, ist ausschließlich: ein Submitter berichtet *dasselbe* IOC zweimal innerhalb einer Woche.

### 8.6 Implementierungshinweise

- Parser für STIX 2.1 verwenden: z.B. `mitre/cti` oder `oasis-open/cti-python-stix2`.
- `extract_atomic_ioc` muss STIX-Pattern-Sprache parsen (`[file:hashes.SHA-256 = '...']`).
- Performance-Ziel: < 10 ms für STIX-Bundle ≤ 32 KB.

---

## 9. Pseudonym-Blacklist und Cover-Traffic

### 9.1 Pseudonym-Blacklist-Datenstruktur

Die Blacklist enthält Pseudonyme $P \in \mathbb{G}$ (Ristretto255-Punkte) statt rohe Hash-Werte. Sie wird beim Verifier gepflegt — entweder lokal pro Consumer (Default in v0.2) oder zentral bei einem dedizierten Verifier-Service.

```
struct PseudonymBlacklist {
    week_index:          u64
    initialized_at:      timestamp
    expires_at:          timestamp                // = initialized_at + 7 days
    storage:             HashSet<bytes32>         // serialized Ristretto255 points
    item_count:          u64
}

Operations:
  PB.add(P: GroupElement)
  PB.contains(P: GroupElement) → bool
  PB.reset() → void                              // weekly
```

**Speicherwahl:**
- Bei kleinem ISAC ($N < 1000$, < 1M Submissions/Woche): einfaches `HashSet<[u8; 32]>` (komprimierter Ristretto-Encoding) ≈ 32 MB max.
- Bei größerem ISAC: Bloom Filter mit $\varepsilon = 2^{-30}$ False-Positive-Rate.

**Wöchentlicher Reset:** Jeden Sonntag um 00:00 UTC wird `PB` neu initialisiert (parallel zur Rotation von $k_i^{(w)} \to k_i^{(w+1)}$, §4.3). Konsequenz: ein Member kann denselben Fingerprint nach Wochen-Wechsel erneut einreichen (gewünscht, für saisonale/persistente Bedrohungen).

### 9.2 Cover-Traffic-Strategie

In der Pseudonym-Architektur ist Cover-Traffic wesentlich einfacher als die alte Zwei-Hash-Konstruktion: **Cover-Submissions enthalten kein Pseudonym und keinen ZKP** — sie sind reine Spectrum-Zero-Shares mit korrektem MAC-Tag $t = 0$.

**Indistinguishability gegen externe Beobachter und Server:**

Aus Sicht eines pre-Aggregation-Beobachters (z.B. malicious Server) sieht jede Submission gleich aus: ein DPF-Share + MAC-Tag-Share, beide pseudozufällige Bit-Strings. Spectrum's Theorem 1 garantiert, dass Cover und Broadcast für *einen* korrumpierten Server ununterscheidbar sind.

Aus Sicht eines post-Aggregation-Verifiers sieht man:
- Reale Broadcaster-Channels: enthalten `(stix_bundle, fp, P, π)` als Klartext.
- Cover-Submissions sind *strukturell* von Broadcasts unterschieden, *aber* nicht ihren Submittern zugeordnet — der Verifier weiß ja nicht, wer die N-L' Cover-Submissions geliefert hat.

**Warum braucht es keinen "Cover-Hash" mehr?** Die alte Konstruktion brauchte Cover-Hashes, weil pre-Aggregation Hash-Werte plaintext mitgesendet wurden — ohne Cover-Hash wären Cover-Submissions identifizierbar gewesen. In der Pseudonym-Konstruktion werden *gar keine* Klartext-Hashes mehr pre-Aggregation gesendet — die Pseudonyme stecken im DPF-verschlüsselten Payload. Damit gibt es kein Indistinguishability-Problem pre-Aggregation.

### 9.3 Bandbreiten-Berechnung

Pro Submission (Broadcaster oder Cover): nur DPF-Key + MAC-Tag — keine zusätzlichen Klartext-Hashes wie in der alten Konstruktion. Submissions sehen pre-Aggregation alle gleich aus.

Verifier-Storage pro Woche: ca. $L' \cdot R \cdot 7$ Pseudonyme = bei $L' = 20$, $R = 168$ (Windows/Woche), 7 Tage = ca. 23.500 Einträge × 32 B = **~750 KB pro Woche** pro Verifier. Sehr klein.

### 9.4 Adversarielle Angriffe gegen Pseudonym-Blacklist

**Attacke 1 — Pseudonym-Burning durch Pre-Image-Wahl:** Ein Angreifer versucht, ein $P$ zu konstruieren, das einem zukünftigen $H_\mathsf{fp}^{k_j^{(w)}}$ eines anderen Members entspricht (Pre-Blocking).

*Verteidigung:* Um ein solches $P$ zu konstruieren, müsste der Angreifer $k_j^{(w)}$ kennen oder $H_\mathsf{fp}^{k_j^{(w)}}$ aus $\mathsf{pk}_j^{(w)} = g^{k_j^{(w)}}$ ableiten. Beides ist unter Computational Diffie-Hellman (CDH) hart. Außerdem würde der Angreifer das ZKP nicht für ein fremdes $k_j^{(w)}$ produzieren können (er kennt es ja nicht).

**Attacke 2 — Multi-Identity-Pseudonym-Spam:** Ein Sybil-Angreifer mit mehreren $k_i$ kann mehrere $P$ für denselben fp erzeugen. Das ist genau der Sybil-Angriff aus §4.3: die Schutzgrenze ist hier $T - 1$ Identitäten. Über diese Grenze hinaus bricht der Threshold-Schutz, nicht die Blacklist selbst.

**Attacke 3 — Honest-but-Curious Verifier:** Ein Verifier könnte versuchen, Pseudonyme zu deanonymisieren.

*Verteidigung:* $P = H_\mathsf{fp}^{k_i^{(w)}}$ ist DDH-pseudozufällig. Ohne $k_i^{(w)}$ kann der Verifier es keinem konkreten Member zuordnen. Das ZKP ist Zero-Knowledge bezüglich $k_i^{(w)}$. Damit: honest-but-curious Verifier ist sicher.

**Attacke 4 — Verifier-Server-Manipulation:** Ein malicious Verifier-Service könnte gezielt Pseudonyme aus der Blacklist entfernen oder hinzufügen, um Konsumenten zu täuschen.

*Verteidigung:* Konsumenten können bei Bedarf selbst nachverifizieren (Option C aus §7.3.3). Außerdem ist die Verifier-Signatur über die finalisierte DB nachverfolgbar — Inkonsistenzen sind erkennbar.

---

## 10. Operative Publikations-Pipeline

Dieses Kapitel beschreibt zwei Aspekte der Publikations-Pipeline, die keine kryptographischen Anonymitäts-Garantien begründen, aber für ein deploybares System spezifiziert sein müssen: die operative Batch-Granularität der Veröffentlichung und den Cover-Traffic-Mechanismus auf Submit-Seite.

**Abgrenzung.** Aggregate-Metadata-Leakage (AML) — also Informationslecks, die ein passiver Beobachter aus Publikations-Timing, Type-Verteilungen oder Volumen-Mustern *über mehrere Rounds hinweg* extrahieren könnte — ist eine eigenständige, orthogonale Forschungslinie und nicht Teil der CHORUS-v0.2-Kernspezifikation. Die zugehörige Mechanismen-Familie (Temporal Delay, Type Bucketing, Differential-Privacy-Komposition über Anonymous-Broadcast-Streams) ist in einem separaten Exposé (`expose_output_privacy.md`) ausgearbeitet und wird in §18.2 als Future-Work-Strang referenziert.

### 10.1 Batch-Coarsening *(operativ, nicht anonymitätsrelevant)*

**Zweck.** Vereinfacht die Schnittstelle zwischen Verifier und Konsument, reduziert API-Roundtrips und glättet die per-Round-Burstigkeit der publizierten Records.

**Mechanismus.** $B$ aufeinanderfolgende Main-Rounds eines Windows werden vom Verifier zu einem Meta-Batch zusammengefasst. Innerhalb eines Meta-Batches wird die Ausgabe-Reihenfolge der Records durch einen deterministischen Shared-PRG permutiert (Seed: $(w, \mathsf{batch\_index})$, abgeleitet aus der signed Konfiguration). $B$ ist Konfigurationsparameter, Default $B = 4$.

**Was dies leistet.** Vorhersagbare API-Last für Consumer-Side-Threshold-Engines; deterministische Reihenfolge über alle Verifier-Instanzen (wichtig bei Consumer-Side-Verifier-Deployment, damit zwei Verifier in zwei Organisationen für denselben Window dieselbe Reihenfolge publizieren — relevant für Reproduzierbarkeit und Audit).

**Was dies *nicht* leistet.** Keine kryptographische Verschleierung von Submission-Timing. Innerhalb eines Meta-Batches wird die feinkörnige Round-Zuordnung aufgegeben, aber die Verifier-Output-Frequenz bleibt aus extern beobachtbar. Batch-Coarsening ist eine Engineering-Maßnahme, kein Anonymisierungs-Primitive.

### 10.2 Cover-Traffic-Mechanismus

In CHORUS gibt es einen einzigen Cover-Mechanismus, der direkt aus der Spectrum-Konstruktion folgt:

**Subscriber-Cover-Traffic (Pflicht).** Jedes Mitglied $P_i$ schickt pro Main-Round genau eine Spectrum-Submission. Wenn $P_i$ in dem aktuellen Window Broadcaster ist, ist es eine echte Submission auf den ihm zugewiesenen Channel; andernfalls sendet $P_i$ eine $m = 0$ Spectrum-Cover-Submission. Aus Sicht eines korrumpierten Servers (höchstens einer) und externer Netzwerkbeobachter sind echte und Cover-Submissions ununterscheidbar — Cover-Indistinguishability ist strukturell durch die DPF+MAC-Konstruktion von Spectrum gegeben (Spectrum Anonymity Theorem 1).

**Konsequenz.** Es ist *kein* separater Cover-Hash-Mechanismus, kein synthetisches Channel-Injection und keine weitere Plaintext-Cover-Logik nötig. Die Anonymitäts-Garantie der Main-Phase reduziert sich vollständig auf die Spectrum-Annahmen plus die Pflichtteilnahme aller Mitglieder pro Round.

**Akzeptierte Beobachtbarkeit.** Die effektive Anzahl realer Broadcaster pro Window $L'$ ist als beobachtbare Größe akzeptiert: ein externer Beobachter kann nach Verifier-Output zählen, wie viele Channels in einem Window non-empty Klartext-Records produzierten. Verschleierung dieser Größe (Volume-Hiding) wäre nur via synthetischer Records erreichbar, was operativ und haftungstechnisch nicht tragbar ist (insbesondere für SIEM-Konsumenten, die ein synthetisches IOC nicht von einem echten unterscheiden könnten). $L'$-Beobachtbarkeit wird als bewusste Designentscheidung zugunsten operativer Sauberkeit dokumentiert (siehe §5.3, §6.4).

---

## 11. Client-Seitige Threshold-Verifikation

### 11.1 Konzept

Der Consumer-Client führt clientseitig eine **Wahrheits-Aggregation** durch. Konzeptionell wichtig: der Threshold zählt *unabhängige Member-Reports* desselben Fingerprints — und "unabhängig" wird über die *Pseudonyme* $P$ definiert, weil verschiedene Member für denselben fp verschiedene $P$ produzieren.

```
Naive consumer (without threshold):
   for each new verified record in published DB: emit to SIEM

CHORUS consumer:
   distinct_pseudonyms_per_fp: map<fp, set<P>>
   already_emitted: set<fp>

   for each verified record in published DB:
       // Verifier hat bereits self-binding + zkp + blacklist gecheckt;
       // markierte Channels (duplicate, self-binding-fail, zkp-fail)
       // werden hier ignoriert.
       if record.verification_status ≠ ok:
           continue

       fp ← record.fp_claimed             // already self-binding-verified
       P  ← record.P                      // already ZKP-verified

       distinct_pseudonyms_per_fp[fp].add(P)

       if |distinct_pseudonyms_per_fp[fp]| >= T_local AND fp ∉ already_emitted:
           emit_to_siem(record)
           already_emitted.add(fp)
```

**Warum Pseudonyme statt nur fp zählen?** Wenn ein Member denselben fp zweimal einreichen würde, wäre $P$ in beiden Submissions identisch — die Set-Datenstruktur dedupliziert automatisch. Damit zählt der Counter nur *verschiedene* Member-Reports. Das ist die Eigenschaft, die der gesamte Pseudonym-Mechanismus durchsetzt.

### 11.2 Threshold-Politik

Der Client entscheidet **lokal** über sein Threshold $T_{\mathrm{local}}$. Mögliche Politiken:

- $T = 1$: traditionelles Verhalten (jeder Record direkt vertraut)
- $T = 2$: zwei unabhängige Quellen erforderlich
- $T = 3$: dreifache Korroboration (Standard-Empfehlung)
- $T = \lceil 0.05 \cdot N \rceil$: 5% des ISACs muss berichten (große ISACs)

Die Wahl trifft jedes Mitglied selbst, in Abhängigkeit von der eigenen Risiko-Toleranz und der Kritikalität des IOC-Typs.

### 11.3 Erweiterung: IOC-Level-Threshold

Statt nur über *Fingerprints* zu zählen, kann der Consumer auch über *atomische IOCs* zählen:

```
For each record r in published DB:
    for each atomic_ioc in r.observables:
        ioc_counter[atomic_ioc] += 1
        if ioc_counter[atomic_ioc] >= T_atomic AND not already_emitted_atomic[ioc]:
            emit_atomic_to_siem(atomic_ioc)
            already_emitted_atomic[ioc] = true
```

Damit werden auch *teilweise überlappende* Berichte korrobortativ. Wenn Submitter A drei IPs meldet und Submitter B zwei davon teilt, werden die zwei überlappenden IPs als doppelt bestätigt eingestuft.

Das ist eine **bewusste Komposition zweier Threshold-Schichten**:
- Fingerprint-Level: für "exakt gleiche Incidents"
- IOC-Level: für "überlappende Indikatoren in verschiedenen Reports"

### 11.4 Evidence Window

Der Counter wird über ein **Evidence Window** (default = 1 Window = 6h) akkumuliert. Nach Window-Ende decay:

```
counter[fp] ← counter[fp] · 0.5   // exponential decay
```

Damit "altes" Evidence verblasst graduell — sinnvoll, weil ein älterer IOC mit der Zeit an Aktualitäts-Relevanz verliert.

### 11.5 Defense-in-Depth-Argument

Die Threshold-Verifikation **verteidigt nicht** gegen ein vollständig kompromittiertes ISAC (wo viele Mitglieder kolludieren). Sie verteidigt aber sehr effektiv gegen:

- Einzelne malicious Members (1-of-N): Threshold $T = 3$ erzwingt $\geq 3$ Witnesses.
- Externe Akteure, die Channels per Setup-Round-Phishing übernommen haben: solange < $T$ Channels in einer Hand sind, kein Effekt.
- "Realistischere Angreifer-Stärke": typische Insider-Angriffe (< 5% des ISAC kompromittiert) werden durch $T = 3$ neutralisiert.

---

## 12. Wire-Formate und Datenstrukturen

### 12.1 Bootstrap-Submission

```
struct BootstrapSubmission {
    uint16 version;
    uint64 window;
    bytes riposte_share;             // shareA or shareB
    bytes32 membership_proof_hash;   // optional preview; full proof in payload
    ZKProof bbs_plus_proof;          // membership credential proof
}

// Payload contained in riposte_share (for broadcasters):
struct BroadcasterClaim {
    bytes32 g_alpha;                 // Curve25519 point
    uint16 claim_idx;                // {1, ..., L}
    bytes16 nonce;
}
```

### 12.2 Main-Round-Submission

```
struct MainSubmission {
    uint16 version;
    uint64 window;
    uint32 round;
    DPFKey dpf_key;                  // ~ √L for 2-server DPF (Spectrum)
                                     // For broadcaster: encodes payload =
                                     //   serialize(stix_bundle, fp, P, π)
                                     // For cover: encodes 0
    bytes16 mac_tag_share;           // t_A or t_B ∈ F (16 bytes for F_{2^128})
    Signature client_signature;      // Ed25519 over all above
                                     // NOTE: no plaintext content metadata
                                     // — all binding lives inside the
                                     // DPF-encrypted payload.
}

// Inside the DPF-encrypted payload (broadcaster):
struct ChannelPayload {
    uint16  format_version;          // 1
    uint16  fp_len;                  // 32
    bytes32 fp_claimed;              // explicit fingerprint declaration
    uint16  P_len;                   // 32
    bytes32 P;                       // compressed Ristretto255 point
    uint16  pi_len;                  // ~1-2 KB depending on ZKP scheme
    bytes   pi;                      // ZKP serialization
    uint32  stix_bundle_len;
    bytes   stix_bundle;             // STIX bundle, fills remaining slot
    // Total ≤ slot_size; typical: stix ~28 KB, overhead ~3-4 KB
}
```

### 12.3 Published Channel-Slot

```
struct PublishedChannel {
    uint64 window;
    uint32 round;
    uint8  channel_index;
    uint16 payload_size;
    bytes  stix_bundle;              // STIX bundle (variable size)
    bytes32 fp_claimed;              // explicit fingerprint from submitter
    bytes32 P;                       // pseudonym (compressed Ristretto)
    bytes   pi;                      // ZKP serialization
    bytes32 record_hash;             // SHA-256 of full payload for integrity

    // verifier-added markings:
    uint8   verification_status;     // 0 = ok
                                     // 1 = self-binding-fail
                                     // 2 = zkp-fail
                                     // 3 = duplicate
}

struct PublishedRound {
    uint64 window;
    uint32 round;
    uint64 published_at_unix;
    PublishedChannel[] channels;     // length = L' (actual active channels)
    bytes32 prev_round_hash;         // append-only chain
    Ed25519Signature sig_a;
    Ed25519Signature sig_b;
    Ed25519Signature sig_verifier;   // (optional) if dedicated verifier exists
}
```

### 12.4 Spectrum-Server-Internal State (S_A, S_B)

```
struct SpectrumServerState {
    K_coord:        bytes32          // shared with peer server (publication coord)
    K_batch:        bytes32          // derived from K_coord; seeds Batch-Coarsening PRG (§10.1)

    current_window: u64
    window_channels: [(j, g_alpha_j)]                  // length = L'

    // NOTE: Spectrum servers do NOT hold the pseudonym blacklist —
    //       that lives at the verifier (consumer or dedicated service).
    //       Spectrum servers only do DPF audit + aggregate-share
    //       publication. Verification and blacklist logic is post-aggregation.

    
    member_list: [MemberID]
    pk_t: -                           // (unused in v0.2)
    bbs_isac_pk: BBSPlusPublicKey
    
    long_term_signing_key: Ed25519SecretKey
    peer_signing_pk: Ed25519PublicKey
    
    state_hash_chain: [bytes32]
}
```

### 12.5 Verifier-Internal State (Consumer-Side oder Dedicated Service)

```
struct VerifierState {
    current_week: u64

    weekly_roster_R: [bytes32]               // pk_j^(w) of all members,
                                             // signed by ISAC authority
    pseudonym_blacklist: PseudonymBlacklist  // §9.1 weekly-reset structure
    bbs_isac_pk: BBSPlusPublicKey            // for ZKP verification
    ristretto_params: GroupParams

    cached_aggregations: map<round, AggregatedChannels>
                                             // for batch-coarsening (§10.1) & threshold

    // (only if dedicated verifier service)
    long_term_signing_key: Ed25519SecretKey
    verified_publications: AppendOnlyLog
}
```

---

## 13. Zustandsmaschinen

### 13.1 Klient (pro Window)

```
Window Start
       │
       ▼
┌─────────────────┐
│ DecideRole      │  Broadcaster | Subscriber
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ BootstrapSubmit │  Algorithm 1
└──────┬──────────┘
       │ CL_w received
       ▼
┌─────────────────┐
│ ReceiveChannel  │  if Broadcaster: store (α_j, j)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ MainLoop        │
│  for r = 1..R   │
│   Submit (Alg.3)│
│   Consume(opt.) │
└──────┬──────────┘
       │ window ended
       ▼
  Window End ─► next Window
```

### 13.2 Spectrum-Server (S_A, S_B; pro Window)

```
Window Start
       │
       ▼
┌────────────────────┐
│ BootstrapRound     │  collect Riposte shares, aggregate
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ PublishChannelList │  CL_w → public
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ MainRound r        │  for r = 1..R
│  Audit (Alg. 4a)   │  Spectrum DPF audit + BlameGame
│  Aggregate         │  Σ shares per server
│  Publish agg_X[r]  │  each server publishes its aggregate share
└────────┬───────────┘
         │
         ▼
   next Window
```

### 13.2b Verifier (pro Round; Consumer-Side oder Dedicated)

```
Round r ends
       │
       ▼
┌────────────────────┐
│ DownloadAggregates │  fetch agg_A[r], agg_B[r] (signed)
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ FinalAggregate     │  channels[r] = agg_A[r] + agg_B[r]
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ ParseEachChannel   │  extract (stix_bundle, fp, P, π)
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ SelfBindingCheck   │  fp == Fingerprint.Compute(stix_bundle)?
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ ZKPVerify          │  π valid for (R^(w), fp, P)?
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ BlacklistCheck     │  P ∈ PB^(w)? if yes → mark duplicate
│                    │  else PB^(w).add(P)
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ BatchCoarsening    │  (§10.1) deterministic PRG-permutation
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ EmitVerifiedDB     │  ggf. mit Verifier-Signatur
└────────────────────┘
```

### 13.3 Consumer

```
   Idle
    │
    │ new verified DB published
    ▼
┌─────────────────────┐
│ DownloadVerifiedDB  │
│  fetch & verify sigs│
│  (Spectrum + Verifier
│   signatures)       │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ FilterMarked        │
│  skip channels with │
│  self-binding-fail, │
│  zkp-fail, duplicate│
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ AccumulatePseudonyms│
│  for each ok channel:
│    fp ← record.fp   │
│    P  ← record.P    │
│    P_per_fp[fp].add(P)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│ ThresholdCheck      │
│  for fp with        │
│   |P_per_fp[fp]| ≥ T│
│    emit to SIEM     │
└────────┬────────────┘
         │
         ▼
   wait for next round

(Note: if consumer runs its own embedded verifier, the
"DownloadVerifiedDB" stage is replaced by "DownloadShares +
Aggregate + Verify locally"; see §13.2b.)
```

---

## 14. Sicherheitseigenschaften

### 14.1 Sender-Anonymität

**Theorem 1 (informell):** Für jeden PPT-Adversary $\mathcal{A}$, der einen Server und beliebig viele Members kontrolliert (aber nicht beide Server), gilt: $\mathcal{A}$ kann nicht zwischen den Welten "ehrliches Member $P_i$ broadcastet $m$ in Channel $j$" und "ehrliches Member $P_k$ broadcastet $m$ in Channel $j$" unterscheiden, solange $P_i, P_k \notin \mathcal{C}$.

**Beweisskizze:** Folgt direkt aus Spectrum Anonymity Theorem 1 (Spectrum §6.2). In v0.2 werden pre-Aggregation *keine* Klartext-Metadaten gesendet (kein separater Hash, kein Pseudonym als Plaintext) — alle inhaltsbindenden Elemente $(\mathsf{fp}, P, \pi)$ liegen im DPF-verschlüsselten Payload. Damit ist die Sicht eines korrumpierten Servers identisch zu Vanilla-Spectrum, und der Anonymitäts-Simulator von Spectrum gilt 1:1.

### 14.2 Bootstrap-Anonymität

**Theorem 2 (informell):** Riposte-basierte Bootstrap-Submissions sind sender-anonym unter denselben Annahmen wie Riposte (Corrigan-Gibbs et al. 2015 §6).

### 14.3 Volume-Beobachtbarkeit

**Beobachtung.** Die Anzahl realer Broadcaster pro Window $L'$ ist beobachtbar. Synthetische Channel-Injection als Volume-Hiding-Mechanismus wurde in v0.2 explizit verworfen (operativ und haftungstechnisch nicht tragbar für SIEM-Konsumenten); Volume-Hiding ist damit nicht Teil der Garantien dieser Spezifikation.

### 14.4 Aggregate-Metadata-Leakage *(außerhalb des Scope)*

Informationslecks an einen passiven Beobachter der publizierten Bulletin-Board-DB über Publikations-Timing, Type-Verteilungen oder Korrelationen über mehrere Windows hinweg sind im aktuellen Threat-Modell *nicht* abgedeckt. Diese Klasse von Lecks (Aggregate-Metadata-Leakage, AML) wird als eigenständige Forschungslinie in `expose_output_privacy.md` (E-DP-ABS-Framework) behandelt. Die CHORUS-v0.2-Spezifikation ist so geschnitten, dass eine zukünftige AML-Schicht orthogonal aufgesetzt werden kann (siehe §18.2).

### 14.5 Write-Integrität

**Spectrum-MAC-Audit** verhindert Disruption-Attacken. **BlameGame** schützt gegen aktive Server-Manipulation des Audits. Beides 1:1 aus Spectrum.

### 14.6 Pseudonym-Bindung (Self-Binding-Soundness)

**Theorem 4 (informell):** Ein PPT-Adversary kann mit Wahrscheinlichkeit höchstens $\mathsf{negl}(\lambda)$ zwei syntaktisch unterschiedliche STIX-Records mit demselben Fingerprint produzieren (Kollisionsresistenz von BLAKE3 + `structured_digest_v1`).

**Theorem 5 (informell — content-bound pseudonym soundness):** Ein PPT-Adversary, der einen Channel mit valider Self-Binding- und ZKP-Verifikation produziert, hat das Pseudonym $P$ deterministisch in $(k_i^{(w)}, \mathsf{fp}_\mathsf{recomputed})$ konstruiert, wobei:
- $k_i^{(w)}$ einem im Roster $R^{(w)}$ registrierten Public-Key entspricht (ZKP-Bedingung 1)
- $\mathsf{fp}_\mathsf{recomputed} = \mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})$ (Self-Binding)
- $P = H_{\mathsf{fp}_\mathsf{recomputed}}^{k_i^{(w)}}$ (ZKP-Bedingung 2)

*Beweisskizze:* Soundness des Schnorr-Sigma-Protokolls (bzw. BBS+-bound proof). Ein malicious Submitter, der $P \ne H_{\mathsf{fp}_\mathsf{claimed}}^{k_i^{(w)}}$ behauptet, kann den ZKP nicht produzieren außer mit Wahrscheinlichkeit $\mathsf{negl}(\lambda)$. Wenn er $\mathsf{fp}_\mathsf{claimed} \ne \mathsf{fp}_\mathsf{recomputed}$ setzt, scheitert der Self-Binding-Check.

**Theorem 6 (informell — single-member-per-fp-per-week):** Ein einzelner Member kann pro Woche denselben $\mathsf{fp}$ höchstens einmal in den Threshold-Counter eines ehrlichen Konsumenten einbringen.

*Beweisskizze:* Aus Theorem 5: $P = H_\mathsf{fp}^{k_i^{(w)}}$ ist deterministisch. Bei einer Re-Submission desselben fp in derselben Woche wird *exakt dasselbe* $P$ produziert. Der Verifier sieht $P \in \mathsf{PB}^{(w)}$ und markiert den Channel als "duplicate". Konsumenten zählen markierte Channels nicht. ✓

### 14.7 Threshold-Soundness (Informelle Aussage)

Ein Adversary, der $k < T$ Member-Identitäten kontrolliert, kann keine False-IOC durchs Consumer-Threshold bringen:
- Pro Member kann er nur *einmal* pro Woche denselben fp einreichen (Theorem 6).
- Damit hat er maximal $k$ unabhängige Pseudonyme pro fp.
- Threshold $T$ verlangt $\ge T$ unabhängige Pseudonyme.
- Bei $k < T$: nicht erreichbar. ✓

**Anmerkung zur Sybil-Annahme:** Der Schutz hängt explizit von der Annahme $k < T$ ab. Bei kompromittiertem Onboarding (mehr als $T - 1$ Member-Identitäten in einer Hand) bricht der Schutz. Sybil-Resistenz ist Onboarding-Eigenschaft, nicht Protokoll-Eigenschaft.

### 14.8 Honest-but-Curious-Verifier-Sicherheit

**Theorem 7 (informell):** Ein honest-but-curious Verifier (Consumer oder Dedicated Service) kann aus seiner Sicht auf $(\mathsf{stix\_bundle}, \mathsf{fp}_\mathsf{claimed}, P, \pi)$ pro Channel die Submitter-Identität nicht extrahieren.

*Beweisskizze:* Konstruktion eines Simulators, der aus dem publik bekannten Member-Roster $R^{(w)}$ und dem fp einen Simulanten-View erzeugt:
- $P_\mathsf{sim}$ wird zufällig aus $\mathbb{G}$ gezogen (DDH-pseudozufällig)
- $\pi_\mathsf{sim}$ wird mit ZK-Simulator erzeugt (Standard-ZK-Eigenschaft)
- Real-View und Simulator-View sind computationell ununterscheidbar unter DDH

Damit lernt der Verifier keine Information über $k_i^{(w)}$ oder den konkreten Submitter aus dem Ring.

---

## 15. Implementierungs-Roadmap

### 15.1 Iteration 1 — Skelett auf Spectrum-Basis (Wochen 1–3)

- Forke die Spectrum-Referenzimplementierung (Rust, ca. 8000 Zeilen, Open Source)
- Anpasse die Datenstrukturen für die CHORUS-Wire-Formate
- Implementiere ChannelPayload-Serialisierung (mit Platzhaltern für fp, P, π)
- **Akzeptanzkriterium:** End-to-end Spectrum-Roundtrip mit Dummy-Payload funktioniert; agg_A[r] und agg_B[r] werden korrekt publiziert.

### 15.2 Iteration 2 — Bootstrap-Phase (Wochen 4–7)

- Riposte-Integration als Bibliothek (oder leichtgewichtige eigene Implementierung)
- BBS+-Proof-Integration
- Channel-Tabellen-Aggregation und Publikation
- **Akzeptanzkriterium:** N=10 Klienten führen Bootstrap durch, Server publiziert valide `CL_w`.

### 15.3 Iteration 3 — Fingerprint-Modul (Wochen 8–10)

- STIX 2.1 Parser einbinden (Rust: `stix2-rust` oder eigene Parser für die wichtigsten Objekttypen)
- `structured_digest_v1` implementieren
- Test-Suite mit realen STIX-Beispielen
- **Akzeptanzkriterium:** 100 Test-STIX-Bundles produzieren reproducierbare Fingerprints; semantisch gleiche Reports produzieren identische Fingerprints.

### 15.4 Iteration 4 — Pseudonym-Konstruktion, ZKP, Verifier-Modul (Wochen 11–15)

- **Pseudonym-Generierung im Klienten:** $H_\mathsf{fp} \leftarrow \mathsf{HashToCurve}(\mathsf{fp})$, $P \leftarrow H_\mathsf{fp}^{k_i^{(w)}}$ über Ristretto255-Bibliothek.
- **ZKP-Modul:** BBS+-bound Ring-Membership-Proof. Empfehlung: bestehende Rust-BBS+-Crate (z.B. `pairing-plus`-basiert) plus Schnorr-OR-Composition für die fp-Bindung. Alternative für kleines $N$: naiver Schnorr-OR-Proof (Cramer-Damgård-Schoenmakers 1994).
- **Verifier-Modul (Consumer-Side Default):**
  - In-memory Pseudonym-Blacklist mit `HashSet<[u8; 32]>` (komprimierter Ristretto-Encoding).
  - Wöchentlicher Reset-Scheduler.
  - Pipeline: agg_A + agg_B → Self-Binding-Check → ZKP-Verify → Blacklist-Lookup → Markierung.
- **Verifier-Modul (Dedicated Service, optional):** Gleiche Logik, plus signierte Veröffentlichung der verifizierten DB an Consumer.
- **Sanktionspolitik:** Channels mit `self-binding-fail`, `zkp-fail` oder `duplicate` werden mit dem entsprechenden Marker in der publizierten DB stehen gelassen. *Kein expliziter Member-Ban* — Konsumenten entscheiden lokal über die Verwendung markierter Channels.
- **Akzeptanzkriterien:** (a) ZKP-Proof-Größe ≤ 5 KB; (b) Verify ≤ 30 ms; (c) Doppelte Submission desselben Fingerprints durch denselben Member führt zu `duplicate`-Markierung; (d) Submissions verschiedener Member desselben Fingerprints führen zu zwei verschiedenen, beide gültigen Channels.

### 15.5 Iteration 5 — Publikations-Pipeline (Wochen 14–18)

- Batch-Coarsening (§10.1) mit konfigurierbarem $B$ und deterministischer Intra-Batch-Permutation
- Cover-Traffic-Konformität (§10.2): Tests, dass jedes Mitglied pro Main-Round genau eine Submission produziert (echt oder Cover) und dass Cover-Indistinguishability gegen einen halbehrlichen Server hält
- **Akzeptanzkriterium:** (a) deterministische, reproduzierbare Output-Reihenfolge bei zwei unabhängigen Verifier-Instanzen für denselben Window; (b) $L'$-Stabilität bei konstanter Member-Pflichtteilnahme.

### 15.6 Iteration 6 — Consumer-Threshold (Wochen 19–20)

- Consumer-Client mit Fingerprint-Counter
- Konfigurierbare $T$-Wahl
- SIEM-Integration (CEF, STIX-Output-Format)
- **Akzeptanzkriterium:** Consumer ignoriert Single-Source-False-IOCs bei $T = 3$; korrekt korroborbierte IOCs gelangen ins SIEM.

### 15.7 Iteration 7 — Evaluation Harness (Wochen 21–26)

- Workload-Generator (basierend auf MISP Community Feeds)
- Adversary-Simulationen für Volume/Type/Confirmation/Cluster-Inference (siehe Exposé)
- Performance-Benchmarks
- Vergleich Spectrum-Baseline vs. CHORUS

---

## 16. Mapping zur Spectrum-Referenzimplementierung

### 16.1 Wiederverwendbar 1:1

| Spectrum-Modul | CHORUS-Verwendung |
|---|---|
| `dpf/` (2-Server-DPF mit AES-PRG) | Direkt für Main-Round-Submissions |
| `mac/` (Carter-Wegman) | Direkt für Access Control |
| `audit/` (Spectrum §3.1/§4.2) | Direkt |
| `blame/` (BlameGame) | Direkt |
| `protocols/spectrum.rs` (Server-Pipeline) | Als Basis, mit CHORUS-spezifischen Erweiterungen |
| TLS-Infrastructure | Direkt |

### 16.2 Zu erweitern

| Spectrum | CHORUS-Erweiterung |
|---|---|
| Single setup phase (registriert Broadcaster einmalig) | Pro-Window Bootstrap mit Riposte |
| Submissions enthalten nur DPF + MAC | Klartext-Format unverändert; alle binding-relevanten Werte (fp, P, π) im DPF-Payload |
| Audit-Pipeline (Server-Side) | Spectrum-Audit unverändert; *zusätzlicher* Verifier (Consumer oder Service) macht post-Aggregation-Verifikation |
| Server-Publikation | Spectrum-Server publizieren agg-Shares; Verifier publiziert verifizierte DB inkl. Markierungen und Batch-Coarsening (§10.1) |

### 16.3 Neu zu schreiben

| Komponente |
|---|
| BBS+-Credential-Issuance und -Verifikation |
| Riposte-Bootstrap-Implementierung |
| `structured_digest_v1` Fingerprint-Modul |
| **HashToCurve (RFC 9380) über Ristretto255** |
| **Ring-Membership-ZKP-Modul (Schnorr-OR oder BBS+-bound)** |
| **Verifier-Modul** (Consumer-Side library + optional Dedicated Service) |
| **Pseudonym-Blacklist** mit weekly reset (lebt im Verifier, nicht in Spectrum-Server) |
| Consumer-Threshold-Engine |
| STIX 2.1 Parser-Integration |
| Public HTTP-API für DB-Download und Diff |
| Publish-Pipeline-Modul (Batch-Coarsening §10.1, beim Verifier) |

### 16.4 Verzeichnis-Struktur

```
CHORUS/
├── README.md
├── PROTOCOL_SPECIFICATION.md       (diese Datei)
├── config/
│   └── chorus-config.yaml
├── crates/                          (Rust Workspace)
│   ├── spectrum-base/               (forked from Spectrum)
│   ├── riposte-bootstrap/           (lightweight implementation)
│   ├── chorus-server/              (S_A, S_B Spectrum binaries)
│   ├── chorus-verifier/            (verifier library + standalone service)
│   ├── chorus-client/              (member daemon for submissions)
│   ├── chorus-consumer/            (SIEM integration daemon w/ embedded verifier)
│   ├── fingerprint/                 (STIX parser + structured_digest_v1)
│   ├── pseudonym/                   (Ristretto + HashToCurve + Ring-ZKP)
│   ├── blacklist/                   (HashSet + weekly reset; lives in verifier)
│   ├── publish-pipeline/            (Batch-Coarsening §10.1; lives in verifier)
│   ├── bbs-plus/                    (or use existing crate, e.g. zkp-stuff)
│   └── stix-types/                  (STIX 2.1 minimal types)
├── tests/
│   ├── integration/
│   ├── adversary/
│   └── fixtures/                    (real-world STIX samples for fp testing)
├── eval/
│   ├── workloads/
│   ├── benchmarks/
│   └── analysis/
└── docs/
    ├── api.md
    └── deployment.md
```

---

## 17. Testvektoren und Akzeptanzkriterien

### 17.1 Modul-Tests

- **Fingerprint:** 100 Pairs von STIX-Bundles, je 50 "äquivalent" (gleicher Fingerprint erwartet) und 50 "verschieden" (unterschiedlicher Fingerprint).
- **Spectrum-Audit:** Bekannte gute und schlechte DPF-Keys, Audit-Resultat deterministisch.
- **HashToCurve:** RFC 9380 Test-Vektoren für Ristretto255.
- **Pseudonym-Determinismus:** Für gegebenen $(k_i^{(w)}, \mathsf{fp})$ ergibt $P = H_\mathsf{fp}^{k_i^{(w)}}$ immer denselben Wert.
- **Ring-ZKP:** Bekannte $(k_i, \mathsf{fp}, P, R^{(w)})$, Proof-Generation und -Verifikation funktionieren. Falsche Proofs werden mit überwältigender Wahrscheinlichkeit abgelehnt.
- **BBS+-Proof:** Bekannte Credentials, Proof-Verifikation deterministisch.
- **Pseudonym-Blacklist:** Insert/Contains/Reset semantisch korrekt.

### 17.2 Integrations-Tests

- **End-to-End Bootstrap:** $N = 50$ Klienten, $L = 10$, bootstrap-Konvergenz innerhalb 60 Sekunden.
- **End-to-End Main:** 6 Main-Rounds pro Window in Sequenz, korrekte Publikation der agg-Shares.
- **End-to-End Verifier-Pipeline:** Verifier (Consumer-Side) lädt agg_A + agg_B, aggregiert, prüft Self-Binding + ZKP für jeden Channel, verwaltet Pseudonym-Blacklist.
- **Duplicate-Marking:** Klient versucht denselben Fingerprint zweimal in zwei verschiedenen Rounds derselben Woche — zweite Submission wird vom Verifier als `duplicate` markiert. Threshold-Counter zählt nur ersten Channel.
- **Different-Member-Same-fp:** Zwei verschiedene Klienten (mit verschiedenen $k_i^{(w)}, k_j^{(w)}$) submitten denselben fp — beide Pseudonyme $P_i \ne P_j$ landen in der Blacklist, beide Channels gelten als unabhängige Reports. Threshold $T = 2$ ist erfüllt.
- **Self-Binding-Bypass-Test:** Klient sendet $\mathsf{fp}_\mathsf{claimed}$, das nicht zum stix_bundle passt — Verifier markiert als `self-binding-fail`.
- **Threshold-Consumer:** $T = 3$ konfiguriert; ein Single-Source-False-IOC erscheint nicht im SIEM; ein dreifach korroboriert IOC (drei verschiedene Member) erscheint.

### 17.3 Performance-Akzeptanzkriterien

| Metrik | v0.2-Ziel |
|---|---|
| Klient-Submission-Latenz (Main) | ≤ 100 ms |
| Klient-Bootstrap-Latenz (per Window) | ≤ 30 Sekunden |
| Server-Throughput pro Main-Round | ≥ 200 Submissions/s |
| Audit-Time per Submission | ≤ 5 ms |
| Fingerprint-Compute-Time | ≤ 10 ms per record |
| Publication-Latency (Round-End → DB visible) | ≤ 5 Sekunden |

### 17.4 Adversary-Simulationen

(Angepasst auf die v0.2-Pseudonym-Architektur):
- **Duplicate-Submission-Bypass:** Versucht ein Angreifer mit Zugriff auf einen Channel, denselben Fingerprint zweimal im selben Window zu publizieren? Soll: Pseudonym $P$ ist deterministisch in $(k_i^{(w)}, \mathsf{fp})$, zweite Submission wird vom Verifier als `duplicate` markiert und vom Threshold-Counter ignoriert (§7.2 V3.4).
- **Self-Binding-Bypass:** Versucht ein malicious Broadcaster, $\mathsf{fp}_\mathsf{claimed} \ne \mathsf{Fingerprint.Compute}(\mathsf{stix\_bundle})$ zu deklarieren? Soll: Verifier-Self-Binding-Check schlägt fehl, Channel wird als `self-binding-fail` markiert (§7.2 V3.2).
- **ZKP-Forgery-Bypass:** Versucht ein malicious Broadcaster, ein $P$ ohne gültiges $k_i^{(w)}$ aus dem Roster zu produzieren? Soll: ZKP-Verify schlägt fehl (Schnorr-Soundness mit Wahrscheinlichkeit $1 - \mathsf{negl}(\lambda)$), Channel wird als `zkp-fail` markiert.
- **Member-Sybil:** Ein Angreifer kontrolliert $k$ Member-Identitäten und versucht, $T = 3$ unabhängige Reports desselben fp durchzubringen. Soll: nur bei $k \ge T$ erfolgreich; das ist die deklarierte Threat-Model-Grenze (§14.7).
- **Pseudonym-Linkability:** Kann ein honest-but-curious Verifier zwei Pseudonyme $P_1, P_2$ desselben Members verschiedenen Submissions zuordnen? Soll: nein, weil verschiedene fps → verschiedene unkorrellierbare Pseudonyme (DDH).
- **Cross-Week-Linkability:** Kann ein Beobachter Pseudonyme aus Woche $w$ und Woche $w+1$ als "derselbe Member" erkennen? Soll: nein, weil $k_i^{(w)}$ und $k_i^{(w+1)}$ via HKDF unabhängig sind.

---

## 18. Offene Fragen, Diskussion und Future Work

### 18.1 Geklärte Designentscheidungen (Stand v0.2)

Die folgenden Fragen aus dem Designprozess sind in dieser Version *geklärt*:

**D1 — Partial-Overlap-Fingerprinting.** Akzeptiert als offenes Problem (§8.4). Lösung vertagt, das Problem ist dort konkret beschrieben. Eine semantik-bewahrende Fingerprint-Konstruktion (*Semantic Attack Fingerprinting*), die zwei STIX-Bundles desselben Angriffs auf einen gemeinsamen Fingerprint zwingt, ist als zukünftige Erweiterung anvisiert. Übergangslösung in v0.2: zweistufige Threshold-Logik (§11.3 Fingerprint-Level + Atomic-IOC-Level).

**D2 — Fingerprint-Self-Binding.** Gelöst über die Pseudonym-Konstruktion mit ZKP-Bindung und post-Aggregation-Verifikation (§7.1, §7.2, §7.3, §8.5). Die vorherige Zwei-Hash-Konstruktion hatte einen Soundness-Bug (Server konnte HMAC nicht verifizieren, weil $K_i^{(w)}$ unbekannt) — sie ist verworfen. Die neue Konstruktion bettet $P = H_\mathsf{fp}^{k_i^{(w)}}$ zusammen mit einem Ring-Membership-ZKP im DPF-verschlüsselten Payload ein; ein post-Aggregation-Verifier (Consumer oder dedicated service) prüft Self-Binding und ZKP, ohne Anonymität zu brechen.

**D3 — Synthetic Channels entfernt.** Pflichtteilnahme aller $N$ Mitglieder (Cover oder echt) pro Round ersetzt die Synthetic-Channel-Logik (§10.2). $L'$ ist beobachtbar; akzeptierte Schwäche zugunsten operativer Sauberkeit.

**D4 — Cover-Traffic-Indistinguishability.** In der Pseudonym-Konstruktion entfällt das vorherige "Cover-Hash"-Konstrukt: pre-Aggregation gibt es überhaupt keine Klartext-Metadaten mehr — nur DPF-Shares und MAC-Tags, die für Broadcasts und Cover gleich aussehen (Spectrum-eigene Indistinguishability). Damit ist Cover-Indistinguishability *strukturell* gegeben, ohne separaten Cover-Hash-Mechanismus.

**D5 — Reading Rights (TLP-Klassen).** Future Work (§18.2). v0.2 behandelt alle Records als TLP:WHITE-Equivalent.

**D6 — Window-Length.** 1 Stunde (6 Main-Rounds à 10 min) als v0.2-Default. Optimale Spezifikation ist Forschungsfrage → Future Work (§18.2).

**D7 — Sanktionspolitik bei Self-Binding/ZKP-Fail.** Statt Member-Ban (in der vorherigen Iteration) wird der betroffene Channel nur *markiert* — der Verifier kann den Submitter aus der Ring-Anonymität nicht identifizieren. Konsumenten ignorieren markierte Channels für die Threshold-Zählung. Das ist die einzige sinnvolle Sanktion in einer Architektur mit echter Ring-Anonymität.

**D8 — Verifier-Position.** Default: Consumer-Side (jeder Consumer verifiziert selbst). Optional: Dedicated Verifier Service. Beide sind unter honest-but-curious Annahme sicher (§14.8). Spectrum-Server $S_A, S_B$ machen *keine* Verifikation — sie publizieren nur ihre Aggregations-Shares und tauschen diese nicht untereinander aus.

### 18.2 Future Work (v0.3+)

- **Aggregate-Metadata-Leakage (AML) der publizierten DB.** Ein passiver Beobachter des publizierten Bulletin-Boards kann über Publikations-Timing, Type-Verteilungen und Volumen-Muster über mehrere Windows hinweg Aggregat-Information extrahieren, die einzelne Submitter teilweise re-identifizieren könnte. Diese Klasse von Lecks ist im aktuellen Threat-Modell explizit *außerhalb des Scope* (§14.4) und wird im separaten Exposé `expose_output_privacy.md` als eigenständige Forschungsrichtung mit dem E-DP-ABS-Framework (Event-Level Differential Privacy über Anonymous Broadcast Streams) ausgearbeitet. Eine zukünftige Version kann eine AML-Schicht orthogonal zur Submit-Anonymität von CHORUS-v0.2 aufsetzen.
- **Semantic Attack Fingerprinting für Partial-Overlap (§8.4).** Lösung für das Problem, dass strukturell unterschiedliche STIX-Bundles desselben Angriffs auf einen gemeinsamen Fingerprint gezwungen werden müssen, ohne dass der Threshold-Mechanismus über Cluster-Boundaries operiert. Eine clevere Technik ist anvisiert; konkrete Konstruktion ist Gegenstand zukünftiger Arbeit.
- **CP-ABE Reading Rights** für TLP-AMBER/RED-äquivalente Zugriffsklassen. Ciphertext-Policy Attribute-Based Encryption mit BBS+-attribute-bound credentials. Erlaubt, dass nur Mitglieder mit passenden Attributen (z.B. Sektor "Energy", Jurisdiktion "EU") bestimmte Records lesen können — anonymisierungserhaltend, ohne TTP.
- **Empirische Bestimmung optimaler Window- und Round-Parameter.** v0.2 nutzt 1h/10min als pragmatischen Default. Optimal ist abhängig von ISAC-Größe, typischer Sharing-Frequenz, akzeptabler Latenz und Bootstrap-Overhead-Toleranz. Ein dedizierter empirischer Eval-Lauf an realen MISP-Workloads ist erforderlich.
- **FL-IDS-Gewichts-Sharing (langfristig).** CHORUS könnte als Transport-Layer für föderiertes Lernen genutzt werden: Mitglieder broadcasten anonymisierte IDS-Modell-Updates statt (oder ergänzend zu) STIX-IOCs. Wöchentliche Model-Updates statt rundenbasierter IOC-Submissions. Dies öffnet eine zweite Anwendungsklasse und integriert mit der breiteren FL-CTI-Literatur (SeCTIS, Fischer ETH). Konzeptionell offen: wie kompatibel sind FL-Aggregations-Pipelines mit Spectrum's Channel-Modell?
- **Threshold-Deanonymisierung als Option.** Wiederbelebung des v0.1-Mechanismus für Hochsicherheits-Szenarien (z.B. wenn ISACs Reputations-Sanktionen via Identitäts-Aufdeckung gegen wiederholt poisonierende Mitglieder verhängen wollen). Aktuell nicht nötig, weil clientseitige Threshold-Verifikation den meisten Angriff-Fall abdeckt — aber als Notfall-Option dokumentierbar.
- **Post-Quantum-Migration.** Spectrum nutzt DDH; PQ-Migration würde lattice-basierte DPF und PQ-MAC erfordern.
- **Cross-ISAC-Federation.** Mehrere CHORUS-Instanzen, die untereinander kollaborieren, ohne Anonymität innerhalb eines ISAC zu brechen.
- **Privacy-Preserving Threshold-Tuning.** Consumer können ihr lokales $T$ adaptiv anpassen, basierend auf historisch beobachteter False-Positive-Rate, ohne ihre Wahl zu leaken.

### 18.3 Contributions v0.2

Mit den Änderungen aus dieser Iteration ergeben sich folgende Contributions:

- **Per-Window Broadcaster-Rotation** ist ein eigenständiger, sauber publizierbarer Beitrag — Spectrum geht das Problem so nicht an.
- **STIX-Fingerprint-Modul** ist ein konkreter, prüfbarer Engineering-Beitrag mit semantischem Mehrwert. Das offene Partial-Overlap-Problem (§8.4) wird klar als zu erforschende zukünftige Erweiterung markiert.
- **Content-Bound Linkable Pseudonyms mit Post-Aggregation-Verifikation** (§7.1–§7.3, §8.5) löst das Self-Binding-Problem unter Wahrung der Spectrum-Anonymität. Die Konstruktion ist kryptographisch nicht-trivial (Ring-Membership-ZKP + DDH-basiertes Pseudonym), aber unter etablierten Standardannahmen (Discrete-Log, DDH, BBS+) beweisbar sicher. Das ist eine genuine kryptographische Contribution, nicht nur eine Engineering-Komposition.
- **Client-Threshold-Verifikation** ist die *einfachste und gleichzeitig wirksamste* Anti-Poisoning-Maßnahme. Konzeptionell elegant: statt "wir versuchen kryptographisch zu garantieren, dass alle Submissions wahr sind", sagt sie "wir verlassen uns auf epidemiologische Korroboration in einer ohnehin verteilten Wahrheits-Findung".

Aggregate-Metadata-Leakage (AML) der publizierten DB ist explizit nicht Teil dieser Contributions und wird als orthogonale Folgearbeit positioniert (§18.2, `expose_output_privacy.md`).

Zielklasse: **Mid-to-Top-Tier-Applied-Security/Systems-Paper**. USENIX Security / NDSS Application Track sind im Bereich des Möglichen, sobald die offenen Punkte (Partial-Overlap-Lösung, empirische Window-Tuning, Eval-Pipeline) abgearbeitet sind.


---

*Ende der Protokollspezifikation v0.2 — CHORUS Working Group, April 2026*
