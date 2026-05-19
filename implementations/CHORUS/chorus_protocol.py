import os
import hashlib
import struct
import random
from typing import NamedTuple
from chorus_core import (
    Point, INF, G, q, p, hash_to_curve, prg, dpf_gen, dpf_eval,
    zkp_prove, zkp_verify, compute_linear_mac, compute_beta_share
)
from fingerprint import STIXFingerprint

class BootstrapSubmission(NamedTuple):
    share: dict # DPF share key
    zkp: tuple # BBS+ mock proof

class MainSubmission(NamedTuple):
    dpf_key: dict
    mac_share: int
    client_id: str # For audit tracking/cover simulation in the prototype

class ChannelPayload(NamedTuple):
    stix_bundle: bytes
    fp: bytes
    P: Point
    c_proof: list[int]
    s_proof: list[int]

# Helper functions for serialization
def serialize_payload(stix_bundle: bytes, fp: bytes, P: Point, c_proof: list[int], s_proof: list[int]) -> bytes:
    N = len(c_proof)
    pi_data = struct.pack(">H", N)
    for ci in c_proof:
        pi_data += ci.to_bytes(32, 'big')
    for si in s_proof:
        pi_data += si.to_bytes(32, 'big')
        
    p_bytes = P.serialize()
    header = struct.pack(">HHHH", 1, 32, 64, len(pi_data))
    payload = header + fp + p_bytes + pi_data + struct.pack(">I", len(stix_bundle)) + stix_bundle
    return payload

def deserialize_payload(payload: bytes) -> ChannelPayload:
    if len(payload) < 12:
        raise ValueError("Payload too short")
    format_version, fp_len, P_len, pi_len = struct.unpack(">HHHH", payload[0:8])
    if format_version != 1:
        raise ValueError("Invalid format version")
        
    offset = 8
    fp = payload[offset : offset + fp_len]
    offset += fp_len
    
    p_bytes = payload[offset : offset + P_len]
    P = Point.deserialize(p_bytes)
    offset += P_len
    
    pi_data = payload[offset : offset + pi_len]
    offset += pi_len
    
    N = struct.unpack(">H", pi_data[0:2])[0]
    c_proof = []
    s_proof = []
    pi_offset = 2
    for _ in range(N):
        c_proof.append(int.from_bytes(pi_data[pi_offset : pi_offset + 32], 'big'))
        pi_offset += 32
    for _ in range(N):
        s_proof.append(int.from_bytes(pi_data[pi_offset : pi_offset + 32], 'big'))
        pi_offset += 32
        
    stix_len = struct.unpack(">I", payload[offset : offset + 4])[0]
    offset += 4
    stix_bundle = payload[offset : offset + stix_len]
    
    return ChannelPayload(stix_bundle, fp, P, c_proof, s_proof)


class ISACAuthority:
    def __init__(self):
        self.roster = {} # member_id -> pk_master (Point)
        self.member_secrets = {} # member_id -> secret_master
        
    def onboard_member(self, member_id: str) -> tuple[int, Point]:
        # Generate master key
        sk = int.from_bytes(os.urandom(32), 'big') % q
        pk = G * sk
        self.roster[member_id] = pk
        self.member_secrets[member_id] = sk
        return sk, pk

    def get_roster(self) -> list[Point]:
        # Return sorted list of public keys for deterministic ZKP mapping
        return [self.roster[mid] for mid in sorted(self.roster.keys())]

    def get_weekly_roster(self, week: int) -> list[Point]:
        # Derive and return the weekly public keys for the roster
        weekly_pks = []
        for mid in sorted(self.roster.keys()):
            sk_master = self.member_secrets[mid]
            # Derive weekly scalar via HKDF-like construction
            salt = f"chorus-week-{week}".encode('utf-8')
            h = hashlib.sha256(sk_master.to_bytes(32, 'big') + salt).digest()
            k_w = int.from_bytes(h, 'big') % q
            weekly_pks.append(G * k_w)
        return weekly_pks


class CHORUSClient:
    def __init__(self, member_id: str, authority: ISACAuthority):
        self.member_id = member_id
        self.authority = authority
        # Onboard with authority
        self.sk_master, self.pk_master = authority.onboard_member(member_id)
        self.k_w = None # Weekly DH secret scalar
        self.pk_w = None # Weekly public key
        
        # Operational states
        self.role = "subscriber" # "broadcaster" or "subscriber"
        self.alpha = None # Broadcast private key for current window
        self.g_alpha = None # Broadcast public key
        self.channel_idx = None # Assigned 1-indexed channel
        
    def rotate_weekly_key(self, week: int):
        salt = f"chorus-week-{week}".encode('utf-8')
        h = hashlib.sha256(self.sk_master.to_bytes(32, 'big') + salt).digest()
        self.k_w = int.from_bytes(h, 'big') % q
        self.pk_w = G * self.k_w

    def choose_role(self, role: str):
        self.role = role
        if role == "broadcaster":
            self.alpha = int.from_bytes(os.urandom(32), 'big') % q
            self.g_alpha = G * self.alpha
        else:
            self.alpha = None
            self.g_alpha = None
            self.channel_idx = None

    def generate_bootstrap_submission(self, claimed_idx: int, L: int) -> tuple[dict, dict]:
        # Create Riposte-like payload: (g_alpha_bytes, claim_idx, nonce)
        nonce = os.urandom(16)
        if self.role == "broadcaster":
            payload = self.g_alpha.serialize() + struct.pack(">H", claimed_idx) + nonce
            target_idx = claimed_idx - 1
        else:
            payload = b'\x00' * 82
            target_idx = 0
            
        key_A, key_B = dpf_gen(target_idx, payload, L)
        return key_A, key_B

    def generate_main_submission(self, stix_bundle: str, L: int, week: int, seed_entropy: bytes, collection_id: str = "") -> tuple[MainSubmission, MainSubmission]:
        # Determine target index and message
        if self.role == "broadcaster" and self.channel_idx is not None:
            # 1. Compute Fingerprint
            fp = STIXFingerprint.compute(stix_bundle)
            
            # 2. Compute Pseudonym with optional Collection ID
            fp_bound = fp
            if collection_id:
                fp_bound = hashlib.sha256(fp + collection_id.encode('utf-8')).digest()
            H_fp = hash_to_curve(fp_bound)
            P = H_fp * self.k_w
            
            # 3. ZKP over Weekly Roster
            weekly_roster = self.authority.get_weekly_roster(week)
            my_roster_idx = sorted(self.authority.roster.keys()).index(self.member_id)
            c_proof, s_proof = zkp_prove(weekly_roster, H_fp, P, self.k_w, my_roster_idx)
            
            # 4. Serialize into payload and pad to 4096 bytes
            stix_bytes = stix_bundle.encode('utf-8')
            payload = serialize_payload(stix_bytes, fp, P, c_proof, s_proof)
            if len(payload) < 4096:
                payload = payload + b'\x00' * (4096 - len(payload))
            elif len(payload) > 4096:
                raise ValueError("Payload size exceeds 4096 bytes")
            
            # 5. Generate DPF keys
            target_idx = self.channel_idx - 1 # 0-indexed
            dpf_A, dpf_B = dpf_gen(target_idx, payload, L)
            
            # 6. Compute Carter-Wegman MAC using the passed seed entropy
            t = compute_linear_mac(self.alpha, payload, seed_entropy)
            
            # Split MAC
            t_A = int.from_bytes(os.urandom(16), 'big') % q
            t_B = (t - t_A) % q
            
            sub_A = MainSubmission(dpf_A, t_A, self.member_id)
            sub_B = MainSubmission(dpf_B, t_B, self.member_id)
            return sub_A, sub_B
        else:
            # Cover submission: DPF of all zeros at index 0, MAC tag = 0
            payload = b'\x00' * 4096
            dpf_A, dpf_B = dpf_gen(0, payload, L)
            
            # Cover tag = 0 split randomly
            t_A = int.from_bytes(os.urandom(16), 'big') % q
            t_B = (0 - t_A) % q
            
            sub_A = MainSubmission(dpf_A, t_A, self.member_id)
            sub_B = MainSubmission(dpf_B, t_B, self.member_id)
            return sub_A, sub_B


class CHORUSServer:
    def __init__(self, server_id: str, L: int):
        self.server_id = server_id
        self.L = L
        self.active_channels = [] # List of Point (g_alpha) for L' active channels
        
    def process_bootstrap(self, submissions_share: list[dict]) -> list[bytes]:
        # Riposte XOR aggregation
        db_shares = []
        for share in submissions_share:
            eval_db = dpf_eval(share)
            db_shares.append(eval_db)
            
        # XOR combine all evaluated shares
        aggregated_db = []
        for x in range(self.L):
            combined = b'\x00' * len(db_shares[0][0])
            for share in db_shares:
                combined = bytes(a ^ b for a, b in zip(combined, share[x]))
            aggregated_db.append(combined)
            
        return aggregated_db

    def decode_bootstrap_db(self, aggregated_db: list[bytes]) -> list[dict]:
        # Decode the aggregated Riposte database of size L
        claims = []
        for idx, data in enumerate(aggregated_db):
            if all(b == 0 for b in data):
                continue
            try:
                g_alpha_bytes = data[0:64]
                g_alpha = Point.deserialize(g_alpha_bytes)
                if g_alpha.is_infinity():
                    continue
                claim_idx = struct.unpack(">H", data[64:66])[0]
                nonce = data[66:82]
                claims.append({
                    'g_alpha': g_alpha,
                    'claim_idx': claim_idx,
                    'nonce': nonce,
                    'reconstructed_at': idx + 1
                })
            except Exception:
                # Malformed due to DPF XOR collision
                continue
        return claims

    def resolve_collisions(self, claims: list[dict]) -> list[tuple[Point, int]]:
        # Deterministic tie-breaking via H(g_alpha || nonce)
        def claim_hash(c):
            h_data = c['g_alpha'].serialize() + c['nonce']
            return hashlib.sha256(h_data).digest()
            
        sorted_claims = sorted(claims, key=claim_hash)
        final_assignments = []
        free_slots = list(range(1, self.L + 1))
        
        # First pass: assign to claimed slot if free
        for c in sorted_claims:
            idx = c['claim_idx']
            if idx in free_slots:
                final_assignments.append((c['g_alpha'], idx))
                free_slots.remove(idx)
                c['assigned'] = True
            else:
                c['assigned'] = False
                
        # Second pass: assign collided clients to remaining free slots
        for c in sorted_claims:
            if not c['assigned']:
                if free_slots:
                    idx = free_slots.pop(0)
                    final_assignments.append((c['g_alpha'], idx))
                    c['assigned'] = True
                else:
                    # Drop if no slots left
                    pass
        return final_assignments

    def process_main(self, submissions: list[MainSubmission], seed_entropy: bytes, peer_submissions: list[MainSubmission] = None) -> tuple[list[bytes], list[Point]]:
        # Evaluate DPFs
        evaluated_shares = []
        for idx, sub in enumerate(submissions):
            eval_share = dpf_eval(sub.dpf_key)
            
            # Reconstruct the message vector for audit
            if peer_submissions and idx < len(peer_submissions):
                peer_eval = dpf_eval(peer_submissions[idx].dpf_key)
                m_vec = []
                for sa, sb in zip(eval_share, peer_eval):
                    m_vec.append(bytes(a ^ b for a, b in zip(sa, sb)))
            else:
                m_vec = eval_share # Fallback
                
            evaluated_shares.append((eval_share, sub.mac_share, m_vec))
            
        # Run MAC audit per submission
        passed_shares = []
        betas = []
        for eval_share, t_share, m_vec in evaluated_shares:
            beta = compute_beta_share(self.active_channels, m_vec, t_share, seed_entropy)
            betas.append(beta)
            passed_shares.append(eval_share)
            
        # Aggregate all passed shares
        # Note: in Spectrum, the server only adds shares that pass audit.
        # Here we return passed shares and the computed betas for audit check.
        aggregated_db = []
        msg_len = len(passed_shares[0][0])
        for x in range(len(self.active_channels)):
            combined = b'\x00' * msg_len
            for share in passed_shares:
                combined = bytes(a ^ b for a, b in zip(combined, share[x]))
            aggregated_db.append(combined)
            
        return aggregated_db, betas


class CHORUSVerifier:
    def __init__(self, authority: ISACAuthority):
        self.authority = authority
        self.blacklist = set() # Set of serialized pseudonym Points (bytes)
        self.evidence_window = {} # fp -> list of pseudonyms P
        self.duplicate_log = [] # Logs of duplicates found
        
    def reset_weekly_blacklist(self):
        self.blacklist.clear()
        
    def coarsen_batches(self, rounds_data: list[list[dict]], B: int, seed: bytes) -> list[list[dict]]:
        coarsened = []
        for i in range(0, len(rounds_data), B):
            batch = rounds_data[i:i+B]
            flat_items = []
            for round_items in batch:
                for item in round_items:
                    flat_items.append(item)
            # Permute deterministically
            batch_seed = hashlib.sha256(seed + i.to_bytes(4, 'big')).digest()
            rng = random.Random(batch_seed)
            rng.shuffle(flat_items)
            coarsened.append(flat_items)
        return coarsened
        
    def verify_round(self, agg_A: list[bytes], agg_B: list[bytes], week: int, collection_id: str = "") -> list[dict]:
        # Reconstruct final channels
        L_prime = len(agg_A)
        channels = []
        
        weekly_roster = self.authority.get_weekly_roster(week)
        
        for idx in range(L_prime):
            combined_payload = bytes(a ^ b for a, b in zip(agg_A[idx], agg_B[idx]))
            
            # If payload is empty (all zeros), skip
            if all(b == 0 for b in combined_payload):
                continue
                
            try:
                stix_bundle, fp_claimed, P, c_proof, s_proof = deserialize_payload(combined_payload)
                stix_str = stix_bundle.decode('utf-8')
                
                status = "ok"
                
                # 1. Self-Binding Check
                fp_recomputed = STIXFingerprint.compute(stix_str)
                if fp_recomputed != fp_claimed:
                    status = "self-binding-fail"
                    
                # 2. ZKP Verification
                if status == "ok":
                    fp_bound = fp_claimed
                    if collection_id:
                        fp_bound = hashlib.sha256(fp_claimed + collection_id.encode('utf-8')).digest()
                    H_fp = hash_to_curve(fp_bound)
                    
                    if not zkp_verify(weekly_roster, H_fp, P, c_proof, s_proof):
                        status = "zkp-fail"
                        
                # 3. Blacklist (Duplicate Check)
                if status == "ok":
                    p_bytes = P.serialize()
                    if p_bytes in self.blacklist:
                        status = "duplicate"
                        self.duplicate_log.append((fp_claimed, P))
                    else:
                        self.blacklist.add(p_bytes)
                        
                channels.append({
                    'channel_index': idx + 1,
                    'stix_bundle': stix_str,
                    'fp': fp_claimed.hex(),
                    'P': P.serialize().hex(),
                    'status': status
                })
            except Exception as e:
                # Log parsing failure
                channels.append({
                    'channel_index': idx + 1,
                    'error': f"Failed to parse payload: {str(e)}",
                    'status': "malformed"
                })
                
        return channels


class CHORUSConsumer:
    def __init__(self, T: int):
        self.T = T
        self.distinct_pseudonyms_per_fp = {} # fp (hex) -> set of P (hex)
        self.already_emitted = set() # set of fp (hex)
        self.siem_alerts = [] # Alerts emitted
        
    def consume_channels(self, verified_channels: list[dict]):
        for chan in verified_channels:
            if chan['status'] != "ok":
                continue
                
            fp = chan['fp']
            P = chan['P']
            
            if fp not in self.distinct_pseudonyms_per_fp:
                self.distinct_pseudonyms_per_fp[fp] = set()
                
            self.distinct_pseudonyms_per_fp[fp].add(P)
            
            count = len(self.distinct_pseudonyms_per_fp[fp])
            if count >= self.T and fp not in self.already_emitted:
                self.siem_alerts.append({
                    'fp': fp,
                    'stix_bundle': chan['stix_bundle'],
                    'evidence_count': count
                })
                self.already_emitted.add(fp)
