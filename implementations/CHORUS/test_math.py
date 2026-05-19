import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 1. Elliptic Curve Math (secp256k1)
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
a = 0
b = 7

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if self.is_infinity() or other.is_infinity():
            return self.is_infinity() and other.is_infinity()
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.is_infinity(): return other
        if other.is_infinity(): return self
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return INF
            else:
                return self.double()
        # Add distinct points
        lam = ((other.y - self.y) * pow(other.x - self.x, p - 2, p)) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Point(x3, y3)

    def double(self):
        if self.is_infinity() or self.y == 0:
            return INF
        lam = ((3 * self.x * self.x + a) * pow(2 * self.y, p - 2, p)) % p
        x3 = (lam * lam - 2 * self.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Point(x3, y3)

    def __mul__(self, scalar):
        scalar = scalar % q
        res = INF
        base = self
        while scalar > 0:
            if scalar & 1:
                res = res + base
            base = base.double()
            scalar >>= 1
        return res

    def __str__(self):
        if self.is_infinity():
            return "INF"
        return f"Point({self.x}, {self.y})"

INF = Point(None, None)
G = Point(
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)

# 2. HashToCurve (hash-and-pray for secp256k1)
def hash_to_curve(data: bytes) -> Point:
    salt = 0
    while True:
        h = hashlib.sha256(data + salt.to_bytes(4, 'big')).digest()
        x = int.from_bytes(h, 'big') % p
        y2 = (x**3 + 7) % p
        if pow(y2, (p - 1) // 2, p) == 1:
            y = pow(y2, (p + 1) // 4, p)
            return Point(x, y)
        salt += 1

# 3. DPF & PRG
def prg(seed: bytes, length: int) -> bytes:
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(seed), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b'\x00' * length) + encryptor.finalize()

def dpf_gen(j: int, m: bytes, L: int) -> tuple[dict, dict]:
    d = (L - 1).bit_length()
    s_A = os.urandom(16)
    s_B = os.urandom(16)
    t_A = 0
    t_B = 1
    
    CW = []
    curr_s_A, curr_s_B = s_A, s_B
    curr_t_A, curr_t_B = t_A, t_B
    
    for i in range(d):
        keep = (j >> (d - 1 - i)) & 1
        out_A = prg(curr_s_A, 34)
        out_B = prg(curr_s_B, 34)
        
        s_L_A, t_L_A = out_A[0:16], out_A[16] & 1
        s_R_A, t_R_A = out_A[17:33], out_A[33] & 1
        
        s_L_B, t_L_B = out_B[0:16], out_B[16] & 1
        s_R_B, t_R_B = out_B[17:33], out_B[33] & 1
        
        if keep == 0:
            s_lose_A, s_lose_B = s_R_A, s_R_B
            t_keep_CW = t_L_A ^ t_L_B ^ 1
            t_lose_CW = t_R_A ^ t_R_B ^ 0
        else:
            s_lose_A, s_lose_B = s_L_A, s_L_B
            t_keep_CW = t_R_A ^ t_R_B ^ 1
            t_lose_CW = t_L_A ^ t_L_B ^ 0
            
        s_CW = bytes(x ^ y for x, y in zip(s_lose_A, s_lose_B))
        t_L_CW = t_keep_CW if keep == 0 else t_lose_CW
        t_R_CW = t_lose_CW if keep == 0 else t_keep_CW
            
        CW.append({'s_CW': s_CW, 't_L_CW': t_L_CW, 't_R_CW': t_R_CW})
        
        if curr_t_A == 1:
            curr_s_A = s_L_A if keep == 0 else s_R_A
            curr_t_A = t_L_A if keep == 0 else t_R_A
            curr_s_A = bytes(x ^ y for x, y in zip(curr_s_A, s_CW))
            curr_t_A ^= t_L_CW if keep == 0 else t_R_CW
        else:
            curr_s_A = s_L_A if keep == 0 else s_R_A
            curr_t_A = t_L_A if keep == 0 else t_R_A
            
        if curr_t_B == 1:
            curr_s_B = s_L_B if keep == 0 else s_R_B
            curr_t_B = t_L_B if keep == 0 else t_R_B
            curr_s_B = bytes(x ^ y for x, y in zip(curr_s_B, s_CW))
            curr_t_B ^= t_L_CW if keep == 0 else t_R_CW
        else:
            curr_s_B = s_L_B if keep == 0 else s_R_B
            curr_t_B = t_L_B if keep == 0 else t_R_B
            
    out_A_final = prg(curr_s_A, len(m))
    out_B_final = prg(curr_s_B, len(m))
    CW_final = bytes(x ^ y ^ z for x, y, z in zip(out_A_final, out_B_final, m))
    
    key_A = {'s_0': s_A, 't_0': t_A, 'CW': CW, 'CW_final': CW_final, 'L': L, 'msg_len': len(m)}
    key_B = {'s_0': s_B, 't_0': t_B, 'CW': CW, 'CW_final': CW_final, 'L': L, 'msg_len': len(m)}
    return key_A, key_B

def dpf_eval(key: dict) -> list[bytes]:
    s_0, t_0, CW, CW_final, L, msg_len = key['s_0'], key['t_0'], key['CW'], key['CW_final'], key['L'], key['msg_len']
    d = (L - 1).bit_length()
    nodes = [(s_0, t_0)]
    for i in range(d):
        next_nodes = []
        s_CW = CW[i]['s_CW']
        t_L_CW = CW[i]['t_L_CW']
        t_R_CW = CW[i]['t_R_CW']
        for s, t in nodes:
            out = prg(s, 34)
            s_L, t_L = out[0:16], out[16] & 1
            s_R, t_R = out[17:33], out[33] & 1
            if t == 1:
                s_L = bytes(x ^ y for x, y in zip(s_L, s_CW))
                t_L ^= t_L_CW
                s_R = bytes(x ^ y for x, y in zip(s_R, s_CW))
                t_R ^= t_R_CW
            next_nodes.append((s_L, t_L))
            next_nodes.append((s_R, t_R))
        nodes = next_nodes
    outputs = []
    for x in range(L):
        s, t = nodes[x]
        out_final = prg(s, msg_len)
        if t == 1:
            val = bytes(a ^ b for a, b in zip(out_final, CW_final))
        else:
            val = out_final
        outputs.append(val)
    return outputs[:L]

# 4. Ring Membership ZKP (Cramer-Damgård-Schoenmakers OR-proof for Chaum-Pedersen relation)
def zkp_prove(Y: list[Point], H: Point, P: Point, x: int, i: int) -> tuple[list[int], list[int]]:
    N = len(Y)
    c = [0] * N
    s = [0] * N
    a = [INF] * N
    b = [INF] * N
    
    # 1. For real index i:
    u = int.from_bytes(os.urandom(32), 'big') % q
    a[i] = G * u
    b[i] = H * u
    
    # 2. For fake indices j != i:
    for j in range(N):
        if j == i:
            continue
        s[j] = int.from_bytes(os.urandom(32), 'big') % q
        c[j] = int.from_bytes(os.urandom(32), 'big') % q
        a[j] = G * s[j] + Y[j] * (-c[j])
        b[j] = H * s[j] + P * (-c[j])
        
    # 3. Compute challenge hash
    h_data = b""
    for pk in Y:
        h_data += pk.x.to_bytes(32, 'big') + pk.y.to_bytes(32, 'big')
    h_data += H.x.to_bytes(32, 'big') + H.y.to_bytes(32, 'big')
    h_data += P.x.to_bytes(32, 'big') + P.y.to_bytes(32, 'big')
    for idx in range(N):
        ax = a[idx].x if a[idx].x is not None else 0
        ay = a[idx].y if a[idx].y is not None else 0
        bx = b[idx].x if b[idx].x is not None else 0
        by = b[idx].y if b[idx].y is not None else 0
        h_data += ax.to_bytes(32, 'big') + ay.to_bytes(32, 'big') + bx.to_bytes(32, 'big') + by.to_bytes(32, 'big')
        
    C = int.from_bytes(hashlib.sha256(h_data).digest(), 'big') % q
    
    # 4. Set real challenge c[i]
    sum_c_fake = sum(c[j] for j in range(N) if j != i) % q
    c[i] = (C - sum_c_fake) % q
    
    # 5. Compute real response s[i]
    s[i] = (u + c[i] * x) % q
    
    return c, s

def zkp_verify(Y: list[Point], H: Point, P: Point, c: list[int], s: list[int]) -> bool:
    N = len(Y)
    if len(c) != N or len(s) != N:
        return False
        
    a = [INF] * N
    b = [INF] * N
    
    # Recompute commitments
    for j in range(N):
        a[j] = G * s[j] + Y[j] * (-c[j])
        b[j] = H * s[j] + P * (-c[j])
        
    # Compute challenge hash
    h_data = b""
    for pk in Y:
        h_data += pk.x.to_bytes(32, 'big') + pk.y.to_bytes(32, 'big')
    h_data += H.x.to_bytes(32, 'big') + H.y.to_bytes(32, 'big')
    h_data += P.x.to_bytes(32, 'big') + P.y.to_bytes(32, 'big')
    for idx in range(N):
        ax = a[idx].x if a[idx].x is not None else 0
        ay = a[idx].y if a[idx].y is not None else 0
        bx = b[idx].x if b[idx].x is not None else 0
        by = b[idx].y if b[idx].y is not None else 0
        h_data += ax.to_bytes(32, 'big') + ay.to_bytes(32, 'big') + bx.to_bytes(32, 'big') + by.to_bytes(32, 'big')
        
    C = int.from_bytes(hashlib.sha256(h_data).digest(), 'big') % q
    
    return sum(c) % q == C

# Test everything
if __name__ == '__main__':
    print("Testing EC Math...")
    P1 = G * 10
    P2 = G * 20
    assert P1 + P2 == G * 30
    print("EC Math: SUCCESS")

    print("Testing HashToCurve...")
    pt = hash_to_curve(b"test_fingerprint")
    assert not pt.is_infinity()
    assert (pt.y**2 - pt.x**3 - 7) % p == 0
    print("HashToCurve: SUCCESS")

    print("Testing DPF...")
    L = 20
    m = b"A" * 32
    target_idx = 5
    key_A, key_B = dpf_gen(target_idx, m, L)
    out_A = dpf_eval(key_A)
    out_B = dpf_eval(key_B)
    
    for idx in range(L):
        recon = bytes(x ^ y for x, y in zip(out_A[idx], out_B[idx]))
        if idx == target_idx:
            assert recon == m
        else:
            assert recon == b"\x00" * 32
    print("DPF: SUCCESS")

    print("Testing Ring ZKP...")
    # Generate a ring of public keys
    secrets = [int.from_bytes(os.urandom(32), 'big') % q for _ in range(5)]
    pks = [G * s for s in secrets]
    
    # Real index
    real_idx = 2
    my_secret = secrets[real_idx]
    
    # Compute pseudonym
    fp = b"some_ioc_fingerprint"
    H_fp = hash_to_curve(fp)
    P_ps = H_fp * my_secret
    
    # Prove
    c_proof, s_proof = zkp_prove(pks, H_fp, P_ps, my_secret, real_idx)
    
    # Verify
    is_valid = zkp_verify(pks, H_fp, P_ps, c_proof, s_proof)
    print("Valid ZKP verification:", is_valid)
    assert is_valid == True, "Verification failed for valid proof"
    
    # Verify with invalid pseudonym
    invalid_P = H_fp * secrets[0] # Pseudonym for a different secret
    is_valid_fake = zkp_verify(pks, H_fp, invalid_P, c_proof, s_proof)
    print("Fake ZKP verification:", is_valid_fake)
    assert is_valid_fake == False, "Verification succeeded for fake proof"
    
    print("ZKP: SUCCESS")
