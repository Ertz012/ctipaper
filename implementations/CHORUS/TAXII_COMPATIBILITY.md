# CHORUS ↔ TAXII 2.1 Compatibility Design

**Status:** Design-Skizze v0.1 — Ergänzung zur Protokollspezifikation v0.2.
**Ziel:** CHORUS so erweitern, dass es als drop-in-kompatibles Backend für bestehende STIX/TAXII-Konsumenten (SIEMs, TIPs, IDS-Konnektoren) auftreten kann, ohne die Anonymitätseigenschaften von CHORUS-Submit zu kompromittieren.
**Zielgruppe:** Implementer, Reviewer, Co-Autoren. Vorausgesetzt wird Kenntnis der CHORUS-Protokollspezifikation (PROTOCOL_SPECIFICATION.md) und ein grundlegendes Verständnis von TAXII 2.1 (OASIS Standard, https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html).

---

## 1. Motivation und Kernaussage

### 1.1 Warum überhaupt TAXII-Kompatibilität?

STIX 2.1 ist das de-facto-Standardformat für strukturierte CTI; TAXII 2.1 ist das de-facto-Standardprotokoll für deren Transport. Praktisch alle relevanten Konsumenten — kommerzielle TIPs (ThreatConnect, Anomali, OpenCTI), SIEM-Integrationen (Splunk, QRadar, Sentinel via Connectors), Open-Source-IDS-Anbindungen (MISP-via-TAXII, OpenIOC-Pipelines) — sprechen TAXII. Wenn CHORUS *nicht* TAXII spricht, müssen Operatoren für jedes Konsum-System einen eigenen CHORUS-Native-Connector schreiben. Das ist der dominante Adoptions-Blocker.

Die Forschungsfrage, die wir adressieren wollen, lautet:

> *Kann ein anonymes Broadcast-Protokoll mit STIX-Inhalt eine TAXII-2.1-kompatible Außenschnittstelle exponieren, ohne die kryptographische Anonymität der Submitter zu verlieren?*

Die Antwort, die dieses Dokument skizziert, ist: **ja, asymmetrisch.** TAXII-*Read* lässt sich vollständig erhalten (sogar verbessern: Read-Anonymität wird in Stufe 2 stärker als bei klassischem TAXII). TAXII-*Write* kann *nicht* direkt erhalten bleiben — ein direkter TLS-Push an einen TAXII-Server würde den Submitter offenlegen. Stattdessen verstecken wir den TAXII-Write hinter einem lokalen Client-Adapter, der die TAXII-Semantik aufnimmt und in CHORUS-Submit übersetzt.

### 1.2 Was bleibt erhalten, was wird ersetzt?

**Erhalten (durch Design garantiert):**

- **Sender-Anonymität** bei Submit. Spectrum + Ring-ZKP bleiben unverändert die kryptographische Grundlage. TAXII-Adapter ist nur eine *lokale* Format-Übersetzung.
- **STIX-2.1-Datenmodell.** Bundles, SCOs, SDOs, Relationships, TLP-Marking-Definitions, Granular-Markings — alles unverändert. CHORUS überträgt STIX-Bundles als Payload, das ändert sich nicht.
- **Per-Member-Threshold-Verifikation** über Pseudonyme.
- **Window-basierte Linkability-Kontrolle.**

**Ersetzt durch CHORUS-spezifische Mechanismen:**

- **TAXII-Write-Endpoint** (`POST /collections/{id}/objects/`). In CHORUS gibt es keinen Write-Endpoint im klassischen Sinn — Submissions laufen über Spectrum-Bootstrap + Spectrum-Main. Der Adapter exponiert lokal einen TAXII-Endpoint und übersetzt jeden eingehenden Bundle-Push in einen `CHORUS.Submit`-Aufruf an die nächste Submission-Runde.
- **TAXII-Channels (Push-Subscribe).** TAXII 2.1 hat optionale Push-Endpoints für Server-initiierte Benachrichtigung. Wir unterstützen diese nicht — CHORUS-Consumer pollen die Verifier-DB. Pull-Modell ist im CTI-Kontext ohnehin der dominante Modus.

**Neu durch CHORUS (über TAXII hinaus):**

- **Submit-Anonymität.** TAXII selbst hat keinerlei Sender-Anonymität: TLS-Endpoint ist authentifiziert, Server kennt jeden Submitter. CHORUS bricht hier auf.
- **Granulare Member-Threshold-Logik** auf Collection-Ebene (Stufe 1) bzw. ABE-Attribut-Ebene (Stufe 2).
- **Optionale Read-Anonymität** (Stufe 2 via CP-ABE / PIR-ähnliche Indizes).

---

## 2. Begriffsklärung: TAXII 2.1 Mental Model

TAXII 2.1 ist ein REST/HTTPS-Protokoll über *API-Roots* und *Collections*. Die zentralen Konzepte:

- **API-Root.** Ein logischer Namensraum, der eine Menge Collections gruppiert. URL-Form: `https://taxii.example.org/api1/`.
- **Collection.** Eine Sammlung von STIX-Objekten, identifiziert durch eine UUID. Hat Permissions (`can_read`, `can_write`), Media-Types und optionale Metadaten. URL: `…/collections/{collection_id}/`.
- **Objects-Endpoint.** Pull/Push der STIX-Objekte in einer Collection. URL: `…/collections/{collection_id}/objects/`. Pagination via `next`-Tokens, Filterung via `added_after`, `match[id]`, `match[type]`, `match[version]`.
- **Manifest-Endpoint.** Liefert Metadaten (Hashes, Timestamps, Versionen) der Objekte einer Collection ohne die Bundles selbst. Nützlich für inkrementelles Sync.
- **AuthN/AuthZ.** Bearer-Token oder Basic-Auth, optional per-Collection-RBAC.

Praktische Anbindung in einem typischen ISAC:

- Eine Collection pro **TLP-Stufe** (TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED) und/oder
- Eine Collection pro **Sektor** (z. B. `Finance-IOCs`, `Energy-OT-Anomalies`) und/oder
- Eine Collection pro **CTI-Kategorie** (Phishing, Ransomware, APT-Campaign-Tracking).

Für CHORUS wird Collection-Granularität zur primären Achse der **Access-Control auf Read-Seite** und zur primären Achse der **Channel-Partitionierung auf Submit-Seite**.

---

## 3. Architektur-Übersicht (Stufe 1 + Stufe 2)

```
                                  ┌──────────────────────────────────────┐
                                  │           TAXII-Konsument            │
                                  │   (SIEM, TIP, IDS-Connector, …)      │
                                  └────────────────┬─────────────────────┘
                                                   │   TAXII 2.1 (HTTPS)
                                                   │   GET /collections/{id}/objects/
                                                   ▼
                                  ┌──────────────────────────────────────┐
                                  │     CHORUS Verifier-Service          │
                                  │  ┌────────────────────────────────┐  │
                                  │  │  TAXII-Read-Gateway            │  │
                                  │  │  (REST-Façade über Verifier-DB)│  │
                                  │  └───────────┬────────────────────┘  │
                                  │  ┌───────────▼────────────────────┐  │
                                  │  │  Verifier-DB                   │  │
                                  │  │  (verified bundles, fingerprints,│ │
                                  │  │   pseudonym threshold state,   │  │
                                  │  │   collection_id index)         │  │
                                  │  └───────────▲────────────────────┘  │
                                  │              │ (writes from main-phase) │
                                  └──────────────┼───────────────────────┘
                                                 │
                                                 │  pulls aggregated channel state
                                                 │  (over published DB shares)
                                                 │
                          ┌──────────────────────┴──────────────────────┐
                          │              CHORUS Spectrum Pool           │
                          │      ┌─────────────┐    ┌─────────────┐     │
                          │      │  Server S_A │    │  Server S_B │     │
                          │      └──────┬──────┘    └──────┬──────┘     │
                          └─────────────┼──────────────────┼────────────┘
                                        │                  │
                                        │  Spectrum-Main   │
                                        │  Bootstrap (Riposte)
                                        │                  │
                                        ▼                  ▼
   ┌────────────────────────────────────────────────────────────────────────────┐
   │                          CHORUS-Mitglied (Client)                          │
   │  ┌──────────────────────────────────────────────────────────────────────┐  │
   │  │                  TAXII-Write-Adapter (local)                         │  │
   │  │  Exponiert: POST https://localhost:8443/taxii2/api1/collections/…/   │  │
   │  │  Übersetzt: TAXII-Push  →  Spectrum-Submit                           │  │
   │  └─────────────────────────────────┬────────────────────────────────────┘  │
   │  ┌─────────────────────────────────▼────────────────────────────────────┐  │
   │  │              CHORUS Submit-Engine (unverändert)                      │  │
   │  │  Fingerprint, Pseudonym P, Ring-ZKP, Spectrum-Channel-Write          │  │
   │  └──────────────────────────────────────────────────────────────────────┘  │
   └────────────────────────────────────────────────────────────────────────────┘
                                        ▲
                                        │  TAXII 2.1 (HTTPS, local)
                                        │  POST /collections/{id}/objects/
                                        │
                          ┌─────────────┴──────────────────┐
                          │  Member-internes              │
                          │  CTI-Produktions-Tool         │
                          │  (MISP, OpenCTI, manuelles    │
                          │   TIP, custom script)         │
                          └────────────────────────────────┘
```

**Lesart der Skizze:**

- *Rechte Seite (Read-Path):* TAXII-Konsumenten sehen einen normalen TAXII-2.1-Server. Authentifizieren sich mit Bearer-Tokens oder via BBS+-Attribute-Proof gegen eine Collection. Bekommen verifizierte STIX-Bundles geliefert. Wissen nicht (und müssen nicht wissen), dass die Bundles über ein anonymes Broadcast-Protokoll eingegangen sind.
- *Linke Seite (Write-Path):* Mitglieder betreiben einen lokalen Daemon (CHORUS-Client). Dieser Daemon exponiert *nach innen* eine TAXII-2.1-Server-Schnittstelle (gegen localhost). Member-interne CTI-Tools (MISP, OpenCTI, custom Python-Skripte) pushen ganz normal an `https://localhost:8443/taxii2/…`. Der Adapter nimmt jeden Push entgegen und übersetzt ihn in eine CHORUS-Submission. Das bedeutet: **bestehende Producer-Pipelines bleiben unverändert.**

---

## 4. Stufe 1 — TAXII-Kompatibilität mit Per-Collection-Pseudonymen (v0.2.1)

Stufe 1 ist die *minimalinvasive* Erweiterung der bestehenden CHORUS-v0.2-Spezifikation. Sie ändert nichts an der Spectrum-Schicht selbst und erfordert nur Erweiterungen am Pseudonym-Modul, an der Bootstrap-Strategie und an der Verifier-DB.

### 4.1 Collection-gebundene Pseudonyme

In v0.2 lautet das Pseudonym:

$$P = H_{\mathsf{fp}}^{k_i^{(w)}} = \mathsf{HashToCurve}(\mathsf{fp})^{k_i^{(w)}}$$

In Stufe 1 wird dies erweitert um eine **Collection-Bindung**:

$$P = \mathsf{HashToCurve}(\mathsf{fp} \,\|\, \mathsf{collection\_id})^{k_i^{(w)}}$$

**Eigenschaft.** Derselbe Submitter, der dasselbe Bundle in zwei verschiedene Collections schickt (z. B. einmal in `Finance-IOCs` und einmal in `Ransomware-Tracking`), produziert *zwei verschiedene* Pseudonyme. Das ist beabsichtigt:

- *Begründung.* TAXII-Collections sind oft *thematisch* unabhängig — eine Submission in zwei Themen-Collections ist legitim und kein "Spam". Wir wollen Duplikate *pro Collection* unterdrücken, nicht *über* Collections hinweg.
- *Konsequenz für Threshold-Logik.* Threshold-Counts ($\mathsf{Threshold}_{\mathsf{member}}$ im Verifier) werden ebenfalls pro Collection geführt. "$T-1$ unabhängige Reports" bedeutet: $T-1$ verschiedene Member-Pseudonyme *in derselben Collection* für denselben Fingerprint.

**ZKP-Anpassung.** Der Ring-Membership-ZKP $\pi$ aus §7.1 der Protokollspezifikation muss zusätzlich beweisen, dass `collection_id` korrekt in das Pseudonym eingebracht wurde:

```
π beweist:  ∃ x : (g^x ∈ R^(w))
                AND (P = HashToCurve(fp || collection_id)^x)
                AND (x is the k-attribute of cred_i)
                AND (collection_id ∈ M_collections,i)        ← neu
```

Die letzte Klausel beweist, dass der Submitter berechtigt ist, in die deklarierte Collection zu schreiben (Write-AuthZ). `M_collections,i` ist die Menge der Collections, in die Member $i$ pro BBS+-Credential schreiben darf (Attribut im Credential). Dieser ZKP-Term ist eine *Set-Membership-Proof* über einen Merkle-Tree der erlaubten Collections — kostengünstig, weil typischerweise nur $O(10)$ Collections pro Member.

### 4.2 Multi-Pool Spectrum: ein Channel-Pool pro Collection

Spectrum operiert auf *Channels* innerhalb eines *Pools* (im Original: ein einziger Pool mit $L$ Channels). Für CHORUS-v0.2 ist das ein einzelner Pool für die gesamte ISAC.

In Stufe 1 partitionieren wir den Pool entlang der TAXII-Collections:

```
Pool_TLP_WHITE       (z. B. 32 Channels)
Pool_TLP_GREEN       (z. B. 16 Channels)
Pool_TLP_AMBER       (z. B. 8 Channels)
Pool_Finance         (z. B. 8 Channels)
Pool_Energy          (z. B. 4 Channels)
…
```

Jeder Pool ist eine separate Spectrum-Instanz mit eigenem DPF-Schlüsselraum, eigenem Bootstrap-Riposte-Run und eigenen Carter-Wegman-MACs. Pool-Größen werden basierend auf erwartetem Submission-Volumen pro Collection statisch konfiguriert (mit Möglichkeit zur dynamischen Reallokation zwischen Windows).

**Begründung.** Pool-Partitionierung pro Collection erreicht zwei Ziele:

1. *Cross-Collection-Unlinkability.* Auch ein vollständig korrupter Beobachter, der alle Spectrum-Channel-Outputs sieht, kann nicht erkennen, ob zwei Submissions in verschiedenen Collections vom selben Member kommen — sie laufen über *physisch unterschiedliche* DPF-Aggregationen.
2. *Skalierbarkeit.* Spectrum-Server-Performance skaliert mit $L$ (Channel-Count). Statt einen Mega-Pool mit hunderten Channels zu betreiben, sind kleinere Pools effizienter und können auf separate Server-Hardware verteilt werden.

**Trade-off.** Cover-Traffic verteilt sich über Pools. Eine Collection mit wenigen Submittern hat schwache Anonymity-Set-Größe. Wir kompensieren das, indem wir niedrig-traffic Collections in einen Shared Pool zusammenfassen, der über die Collection-Achse logisch (nicht physisch) partitioniert ist — d. h. ein Channel innerhalb dieses Shared Pools kann Submissions an unterschiedliche Collections tragen, sofern die `collection_id` im Payload mit-übertragen wird.

### 4.3 TAXII-Read-Gateway auf dem Verifier

Der Verifier (siehe §13.2b der Protokollspezifikation) wird um eine **TAXII-2.1-Server-Façade** erweitert. Diese Façade exponiert die folgenden Endpoints (Pull-Subset von TAXII 2.1):

| Endpoint | Funktion |
|---|---|
| `GET /taxii2/` | Server-Discovery (lists API-Roots) |
| `GET /taxii2/{api-root}/` | API-Root-Informationen |
| `GET /taxii2/{api-root}/collections/` | Listet alle für Caller sichtbaren Collections |
| `GET /taxii2/{api-root}/collections/{id}/` | Collection-Metadaten |
| `GET /taxii2/{api-root}/collections/{id}/manifest/` | Manifest aller verifizierten Objekte (Hashes, Timestamps) |
| `GET /taxii2/{api-root}/collections/{id}/objects/` | Verifizierte STIX-Objekte mit Pagination |
| `GET /taxii2/{api-root}/collections/{id}/objects/{stix-id}/` | Einzelnes verifiziertes Objekt |
| `GET /taxii2/{api-root}/status/{status-id}/` | Status-Endpoint (entfällt in unserem Pull-Modell; kann no-op zurückgeben) |
| ⛔ `POST /taxii2/{api-root}/collections/{id}/objects/` | **NICHT exponiert.** Push-Submit läuft über CHORUS-Submit, nicht über TAXII-POST. |

**Mapping Verifier-DB → TAXII-Responses.**

- Die Verifier-DB enthält pro verifiziertem Bundle:
  - `fingerprint` (eindeutig pro Bundle-Inhalt)
  - `collection_id`
  - `verified_at` (Timestamp der Verifikation)
  - `threshold_state` (wie viele Member-Pseudonyme bisher gesehen)
  - `stix_bundle` (raw)
- TAXII-Filter (`added_after`, `match[type]`, `match[id]`, `match[version]`) werden direkt auf die DB übersetzt.
- TAXII-Pagination (`limit` + `next`-Token) wird via opaquen Cursor implementiert (z. B. base64-codierte `(verified_at, fingerprint)`-Tupel).

**Manifest-Hashes.** TAXII 2.1 erwartet pro Object einen SHA-256-Hash im Manifest. Wir liefern hier den CHORUS-Fingerprint (`structured_digest_v1`) als kanonischen Hash, optional auch SHA-256 über das raw Bundle für TAXII-Konformität.

### 4.4 TAXII-Read-AuthN via BBS+-Attribute-Proof

Klassisches TAXII verwendet Bearer-Tokens oder Basic-Auth. Das funktioniert in CHORUS auch — der Verifier kann seinen Konsumenten gewöhnliche API-Keys ausstellen. Für eine **anonyme Read-Auth** (Stufe-1-optional, Stufe-2-default) verwenden wir BBS+-Selektive-Disclosure:

**Protokoll.**

1. Konsument hat ein BBS+-Credential vom Issuer (gleicher Issuer wie Submit-Credentials, oder separater Read-Issuer).
2. Konsument generiert pro Read-Request einen frischen BBS+-Proof, der nur die Attribute *disclosed*, die für die jeweilige Collection autorisierungsrelevant sind (z. B. `tlp_clearance ≥ AMBER`, `sector = Finance`).
3. Verifier verifiziert den Proof, prüft die offengelegten Attribute gegen die Collection-Policy, antwortet mit den passenden Objects.
4. Verifier sieht: einen Proof. Nicht: welcher Konsument. Verschiedene Reads desselben Konsumenten sind *unlinkable* (Standard-BBS+-Eigenschaft).

**Praktischer Trade-off.** Vollanonyme Reads bedeuten kein Bandwidth-Throttling pro Identität — ein DoS-Vektor. Mitigation: rate-limiting per `tlp_clearance × IP`, oder optional ein deterministisches Read-Pseudonym pro Window (analog zur Submit-Seite) für Rate-Limiting-Buckets.

### 4.5 TAXII-Write-Adapter auf dem Client

**Architektur.** Der CHORUS-Client-Daemon (siehe §16.4 Verzeichnis) bekommt eine zusätzliche Komponente: einen lokalen HTTPS-Server, der einen Teil der TAXII-2.1-API exponiert — nämlich die Write-Endpoints. Default-Bind ist `https://localhost:8443/taxii2/api1/`.

**Mapping TAXII-POST → CHORUS-Submit.**

```python
# Sketch
@app.route('/taxii2/api1/collections/<collection_id>/objects/', methods=['POST'])
def taxii_push(collection_id):
    envelope = parse_taxii_envelope(request.body)   # STIX 2.1 Bundle
    for obj in envelope['objects']:
        bundle = wrap_as_bundle([obj])              # einen Bundle pro Object,
                                                    # oder Batch-Modus
        # CHORUS-Submit:
        fp           = fingerprint.compute(bundle)
        H_fp         = hash_to_curve(fp + collection_id)
        P            = H_fp ** k_i_week
        zkp          = ring_proof.prove(bundle, fp, P, collection_id)
        chorus_payload = serialize(bundle, fp, P, zkp, collection_id)
        spectrum_client.submit(pool=pool_for(collection_id),
                               payload=chorus_payload)
    return taxii_status_pending()
```

**Wichtige semantische Punkte:**

- TAXII-POST gibt typischerweise einen `status_id` zurück, mit dem der Producer den Verarbeitungsstatus pollen kann. In CHORUS gibt es kein synchrones Submit-Result (es ist asynchron über mehrere Windows hinweg gerichtet). Der Adapter gibt `status: pending` zurück und exponiert einen *lokalen* Status-Endpoint, der den lokalen Submit-State zeigt (gesendet / in Spectrum-Pool / im nächsten Verify-Run zu erwarten).
- TAXII-Producer erwarten oft, dass ein Push *sofort* read-bar ist. Das ist in CHORUS nicht der Fall — Bundles werden erst nach der nächsten Spectrum-Main-Phase + Verifier-Run sichtbar (Latenz: bis zu 1 Window, in v0.2 = 1 h). Der Adapter dokumentiert dies und kann optional eine *Echo-Cache*-Strategie fahren: der Producer sieht seine eigenen Submissions sofort in der lokalen Adapter-DB, *bevor* sie real verifiziert sind.
- TAXII-Updates / Revocations: TAXII erlaubt das Senden eines Objects mit `modified`-Timestamp als Update. CHORUS hat hier zwei Optionen: (i) jedes Update ist eine neue Submission mit neuem Fingerprint → kein Sonderfall; (ii) `modified`-Marker wird ins Fingerprint-Schema einbezogen, sodass Updates desselben STIX-IDs als "Version-Bump" markiert werden. Wir wählen (i) für Stufe 1 und reservieren (ii) für eine Version-Linkability-Erweiterung in Stufe 3.

**AuthN gegen den lokalen Adapter.** Da der Adapter auf localhost läuft, ist klassische OS-AuthN (Unix-Socket-Permissions, Loopback-Whitelist) ausreichend. Wenn der Adapter remote erreichbar gemacht wird (z. B. zentraler TIP, der mehrere Member-Daemons feedet), muss TLS + Bearer-Token verwendet werden — *aber* das Bearer-Token-Mapping ist Adapter-intern und sieht in keiner Form den externen Spectrum-Pool. Submitter-Anonymität gegenüber Spectrum-Servern bleibt erhalten.

### 4.6 Zusammenfassung Stufe 1

| Eigenschaft | Status |
|---|---|
| TAXII 2.1 Read-API (Pull, alle Standard-Endpoints außer POST) | ✅ vollständig kompatibel |
| TAXII 2.1 Write-API (POST `/objects/`) | ✅ kompatibel via lokalen Adapter, transparent für Producer |
| TAXII 2.1 Channels (Push-Subscribe) | ❌ nicht unterstützt; Konsument nutzt Polling |
| TAXII 2.1 Bearer-AuthN (Read) | ✅ kompatibel |
| BBS+-Attribute-Proof AuthN (Read) | ✅ optional, CHORUS-spezifisch |
| Multi-Collection-Schreibrechte | ✅ via BBS+-Attribut + ZKP-Klausel |
| Threshold pro Collection | ✅ über `(fp, collection_id)`-Pseudonym |
| Submitter-Anonymität bei Read | ⚠️ nur teilweise (Read-Pattern weiterhin beobachtbar; siehe Stufe 2) |
| Cross-Collection-Unlinkability | ✅ via Multi-Pool und distinkte Pseudonyme |

---

## 5. Stufe 2 — Read-Anonymität via CP-ABE und Index-Privacy (v0.3)

Stufe 1 lässt eine Lücke offen: ein Konsument, der eine TAXII-Collection liest, offenbart dem Verifier *welche Collection* er liest und *wann*. Das ist oft ein realer Threat — wenn ein Mitglied seinen TLP:AMBER-Subscription-Status zu APT-29-Trackings offenbart, lässt sich daraus ableiten, dass das Mitglied von APT-29 betroffen ist. Stufe 2 schließt diese Lücke.

### 5.1 CP-ABE für sensitive Collections

Für Collections mit Schutzlevel TLP:AMBER und höher verschlüsseln wir die Payload **bei der Submission** mit einem CP-ABE-Scheme (z. B. Waters-CP-ABE, oder modernerer GGM-basierter Bauplan):

$$\mathsf{Bundle\_enc} = \mathsf{CP\text{-}ABE.Enc}(\mathsf{policy}, \mathsf{bundle})$$

mit `policy` als boolesche Formel über Attribute, z. B. `(sector="Finance") AND (clearance ≥ "AMBER")`.

**Schlüsselausgabe.** Der CP-ABE-Authority (typischerweise: ISAC-Operator, kann auf Threshold-Authorities verteilt werden) gibt jedem Member einen Decryption-Key für die Attribute, die das Member legitim hält. Decryption gelingt nur, wenn die Attribute die Policy erfüllen.

**Konsequenz für TAXII-Read.**

- Der Verifier serviert die *verschlüsselten* Bundles. Er kennt die Policy nicht selbst (sie ist im Ciphertext) und kann nicht entscheiden, wer berechtigt ist.
- Der Konsument decryptiert lokal mit seinem Key. Die Entscheidung "Bundle relevant ja/nein" passiert nicht beim Verifier, sondern beim Konsumenten — analog zu PIR-ähnlichen Privacy-Pattern.

### 5.2 Index-Privacy: Was sieht der Verifier?

Auch bei CP-ABE sieht der Verifier weiterhin *welche Collection-IDs* ein Konsument abfragt. Um auch das zu schließen, gibt es zwei Optionen:

- **Option A: Single Cover-Collection.** Sensitive Bundles aus *allen* AMBER+RED-Collections werden in *eine einzige* TAXII-Collection eingespeist (intern flag-getaggt). Der Konsument zieht *alle* AMBER+RED-Bundles, entschlüsselt lokal, filtert. Bandbreite leidet, Read-Anonymität ist perfekt.
- **Option B: ORAM / PIR-Light.** Verifier exponiert Read-Endpoints, die einen Bandbreiten-Overhead von $O(\sqrt{N})$ tolerieren und im Gegenzug die Index-Privatsphäre über $N$ Bundles verbergen. Praktisch nur für mittlere $N$ (≤ $10^6$ Bundles) sinnvoll, da PIR mit $N$ unangenehm skaliert.

In Stufe 2 wählen wir Option A als Default (operativ einfacher, robuster), Option B als Forschungs-Extension.

### 5.3 Inkompatibilitäten und Adapter-Strategie

CP-ABE-verschlüsselte Bundles sind *nicht direkt* TAXII-konsumierbar — ein generischer TAXII-Client kann nur Klartext-STIX verstehen. Lösung: der TAXII-Konsument betreibt einen **Decryption-Sidecar**:

```
TAXII-Konsument (z. B. SIEM)
   │
   │  TAXII 2.1 Pull
   ▼
[Lokaler Decryption-Sidecar]
   │  CP-ABE.Dec mit Member-Key
   ▼
TAXII-Konsument bekommt Klartext-Bundle
```

Der Sidecar exponiert eine zweite TAXII-Façade gegen den eigentlichen Konsumenten, decryptiert on-the-fly und gibt nur die Bundles weiter, deren Policy mit den Sidecar-Attributen erfüllt wird. Für den eigentlichen SIEM/TIP ist alles transparent.

### 5.4 Zusammenfassung Stufe 2

| Eigenschaft | Status |
|---|---|
| Read-Anonymität gegenüber Verifier | ✅ (Option A vollständig, Option B mit PIR-Overhead) |
| TAXII-Kompatibilität für Konsumenten | ✅ via Sidecar |
| CP-ABE für TLP:AMBER, TLP:RED Bundles | ✅ |
| Threshold-Verifikation bei encrypted Bundles | ⚠️ braucht Anpassung (Fingerprint über Klartext wird beim Submit berechnet und im Encrypted-Header platziert; Verifier verifiziert ZKP gegen diesen ausgesetzten Fingerprint) |
| Key-Issuer als Trusted Third Party | ⚠️ neue Vertrauensentität — kann via Threshold-Authority distribuiert werden |

---

## 6. Was definitiv *nicht* TAXII-kompatibel bleibt

### 6.1 Direkter TAXII-Write über Internet

Ein klassischer TAXII-Producer pusht direkt mit Bearer-Token an einen Remote-TAXII-Server. Das *brechen* wir bewusst:

- Producer kann nicht direkt CHORUS pushen — kein Endpoint exponiert.
- Producer pusht an **lokalen** Adapter → Adapter pusht in Spectrum-Pool.

Diese Asymmetrie ist nicht reparabel, ohne Anonymität zu zerstören. Sie ist die *zentrale Designentscheidung* der CHORUS-TAXII-Integration: wir verkaufen Submit-Anonymität gegen "TAXII-Push über Internet". Für CTI-Sharing ist das ein hervorragender Tausch (klassisches TAXII-Push hatte *nie* Sender-Anonymität; wir machen es jetzt explizit und kompensieren mit dem Adapter).

### 6.2 TAXII-Channels (Push-Subscribe)

TAXII 2.1 erlaubt server-initiierte Notifications via Channels (optional in der Spec). Wir unterstützen das nicht:

- Push-Notifications erfordern, dass der Verifier weiß, *welche* Konsumenten er notifizieren soll — bricht Read-Anonymität.
- Pull-Modell ist im CTI-Kontext dominant.

Workaround für latenzkritische Konsumenten: kurze Poll-Intervalle (z. B. 30 s). Der Verifier kann diese ohne Last-Probleme bedienen, da die Verifier-DB nur ein Read-Only-Index ist.

### 6.3 TAXII-Status-Synchronität

TAXII-Producer erwarten in vielen Fällen ein semi-synchrones Status-Feedback ("dein Bundle wurde akzeptiert / abgelehnt"). In CHORUS ist Status-Feedback per Definition *windowverzögert* (Submit jetzt → Verify in $\le 1$ h). Der Adapter approximiert TAXII-Status durch:

- `status: pending` direkt nach lokalem Submit (vor Spectrum-Round).
- `status: in_progress` nach erfolgreichem Spectrum-Round.
- `status: complete` (oder `failed`) nach Verifier-Result.

Für Producer, die hartes Sync-Feedback brauchen, ist CHORUS architektonisch ungeeignet — was im CTI-Kontext aber kein realer Use-Case ist.

---

## 7. Reihenfolge der Implementierung (Roadmap)

| Stufe | Erweiterung | Aufwand | Abhängigkeiten |
|---|---|---|---|
| **0** | CHORUS v0.2 (PROTOCOL_SPECIFICATION.md) | Baseline | — |
| **1a** | Collection-gebundene Pseudonyme (§4.1) | Klein (Pseudonym-Modul ändern, ZKP erweitern) | Baseline |
| **1b** | Multi-Pool Spectrum (§4.2) | Mittel (Pool-Manager, Bootstrap pro Pool) | 1a |
| **1c** | TAXII-Read-Gateway (§4.3, §4.4) | Mittel (HTTP-Frontend auf Verifier, BBS+-Auth-Modul) | 1a + Verifier-DB-Schema |
| **1d** | TAXII-Write-Adapter (§4.5) | Klein-Mittel (Client-Daemon-Erweiterung) | 1a |
| **2a** | CP-ABE-Encryption für TLP:AMBER/RED-Bundles (§5.1) | Mittel-Groß (CP-ABE-Library, Key-Authority) | 1a–1d |
| **2b** | Single Cover-Collection / PIR-Index (§5.2) | Mittel | 2a |
| **2c** | Decryption-Sidecar (§5.3) | Klein | 2a |
| **3** (forschungsoffen) | TAXII-Channels via anonymous Push, ORAM-PIR-Reads | Groß | 2 |

**Empfehlung.** Stufe 1 (a–d) ist in einer Forschungsarbeit gut beherrschbar und liefert die "Operational-Plausibility"-Story, die ein PETs/SIGCOMM-Reviewer typischerweise sehen will. Stufe 2 wird als *future work* ausführlich diskutiert; eine Prototyp-Implementierung ist optional aber sehr stark.

---

## 8. Offene Fragen und Forschungsthemen

1. **Pool-Sizing-Heuristik.** Wie viele Channels braucht ein Pool für eine Collection mit $\mu$ erwarteten Submissions/Window und $N_c$ aktiven Membern? Hängt von der Cover-Traffic-Strategie ab (§9 der Protokollspezifikation, Mechanismus M1: konstante Submission-Rate).
2. **Collection-Membership-Hopping.** Ein Member ändert seine `M_collections`-Berechtigung (neuer Sektor, neue TLP-Clearance). Wie wirkt sich das auf Pseudonym-Linkability über Windows aus? *Vorläufige Antwort:* Window-Reset (HKDF mit Window-Salt) bricht ohnehin alle Linkabilities pro Window — die Frage betrifft nur das Credential-Update, das atomar zu einem Window-Boundary stattfinden sollte.
3. **TAXII-Conformance-Tests.** TAXII 2.1 hat einen Conformance-Testset (OASIS-Testsuite). Welche Tests bestehen wir, welche nicht? Insbesondere: Erwarten Tests synchrone Status-Returns nach POST? Wenn ja, ist das Adapter-Layer-Issue, das wir dokumentieren müssen.
4. **CP-ABE-Threshold-Authority.** Wer hält die Master-Secret-Keys für CP-ABE? Ein einzelner ISAC-Operator wäre zu starker Trust-Anchor. Threshold-CP-ABE-Schemes (e. g. distributed key generation across ISAC-Boards) sind aktive Forschung — relevant für Stufe 2.
5. **Performance.** Multi-Pool-Spectrum mit $K$ Pools statt einem Pool — wo ist der Crossover-Punkt, bei dem die Aggregat-Server-Kosten höher sind als die Anonymity-Set-Reduction es wert ist? Brauchen wir adaptive Pool-Konsolidation für niedrig-Traffic-Collections?

---

## 9. Anschluss an die Protokollspezifikation

Diese Datei ist als **Ergänzungsdokument** zur PROTOCOL_SPECIFICATION.md v0.2 zu lesen. Konkret:

- **§4.1** dieses Dokuments ersetzt **§7.1 (Algorithm 3, Main.Submit)** der Hauptspezifikation für den Fall, dass TAXII-Collection-Bindung aktiviert ist. Beide Modi sind kompatibel implementierbar (`collection_id` ist optional; wenn nicht gesetzt, fällt das System auf v0.2-Verhalten zurück).
- **§4.3** definiert ein neues Modul `crates/taxii-gateway/` (vorher nicht in der Verzeichnisstruktur §16.4 vorgesehen).
- **§4.5** definiert ein neues Modul `crates/taxii-adapter/` als Erweiterung des `chorus-client`-Daemons.
- **§5.x** ist forschungsoffen, nicht implementierungsleitend in v0.2.1.

Eine konsolidierte v0.3-Hauptspezifikation, die Stufe 1 vollständig integriert, ist als nächster Schritt vorgesehen.

---

*Ende des TAXII-Compatibility-Designs v0.1 — CHORUS Working Group, Mai 2026*
