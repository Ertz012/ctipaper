import json
import hashlib
from chorus_core import Point, G, q, INF
from chorus_protocol import (
    ISACAuthority, CHORUSClient, CHORUSServer, CHORUSVerifier, CHORUSConsumer
)

# Text styles for beautiful terminal output
class Style:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(title: str):
    print(f"\n{Style.BOLD}{Style.CYAN}{'='*60}\n{title.center(60)}\n{'='*60}{Style.END}")

def print_step(step: str, desc: str = ""):
    print(f"\n{Style.BOLD}>>> {step}{Style.END} {Style.YELLOW}{desc}{Style.END}")

def print_success(msg: str):
    print(f"  {Style.GREEN}[OK] {msg}{Style.END}")

def print_info(msg: str):
    print(f"  [INFO] {msg}")

def print_warning(msg: str):
    print(f"  {Style.YELLOW}[WARN] {msg}{Style.END}")

def print_error(msg: str):
    print(f"  {Style.RED}[ERR] {msg}{Style.END}")


def run_cli_demo():
    print_header("CHORUS PROTOCOL CLI DEMONSTRATION")
    
    # Configuration
    L = 6 # Total channel slots
    T = 2 # Threshold of unique pseudonyms
    week = 1
    
    print_info(f"System Configuration: Channels (L) = {L}, Threshold (T) = {T}, Week = {week}")
    
    # 1. Authority & Onboarding
    print_step("Step 1: Onboarding and Weekly Key Rotation", "Setting up ISAC and generating member keys")
    auth = ISACAuthority()
    
    member_ids = ["Alice", "Bob", "Charlie", "Dave", "Eve"]
    clients = {}
    
    for mid in member_ids:
        client = CHORUSClient(mid, auth)
        clients[mid] = client
        client.rotate_weekly_key(week)
        print_success(f"Onboarded member '{mid}'")
        print_info(f"   Master PK: {client.pk_master.serialize().hex()[:24]}...")
        print_info(f"   Weekly PK: {client.pk_w.serialize().hex()[:24]}...")
        
    # 2. Bootstrap (Riposte)
    print_step("Step 2: Bootstrap Phase (Channel Claiming)", "Clients claim write channels via anonymous DPF slots")
    
    # Alice claims 2, Bob claims 4, Charlie claims 1
    claims = {
        "Alice": 2,
        "Bob": 4,
        "Charlie": 1,
        "Dave": 0,    # Subscriber (cover)
        "Eve": 0     # Subscriber (cover)
    }
    
    submissions_A = []
    submissions_B = []
    
    for mid, client in clients.items():
        claimed_idx = claims[mid]
        if claimed_idx > 0:
            client.choose_role("broadcaster")
            print_info(f"'{mid}' claims channel slot {claimed_idx} (g^alpha public key generated)")
        else:
            client.choose_role("subscriber")
            
        share_A, share_B = client.generate_bootstrap_submission(claimed_idx, L)
        submissions_A.append(share_A)
        submissions_B.append(share_B)
        
    # Servers aggregate
    server_A = CHORUSServer("Server_A", L)
    server_B = CHORUSServer("Server_B", L)
    
    agg_A = server_A.process_bootstrap(submissions_A)
    agg_B = server_B.process_bootstrap(submissions_B)
    
    # Reconstruct bulletin board
    reconstructed_db = []
    for x in range(L):
        reconstructed_db.append(bytes(a ^ b for a, b in zip(agg_A[x], agg_B[x])))
        
    claims_decoded = server_A.decode_bootstrap_db(reconstructed_db)
    print_info(f"Reconstructed database claims decoded: {len(claims_decoded)} claims found.")
    
    # Resolve Collisions
    print_info("Resolving channel collisions via deterministic tie-breaking...")
    assignments = server_A.resolve_collisions(claims_decoded)
    
    active_pks = [None] * L
    active_map = {}
    for g_alpha, final_idx in assignments:
        # Match back to client
        matched_client = None
        for client in clients.values():
            if client.g_alpha and client.g_alpha == g_alpha:
                matched_client = client
                break
        if matched_client:
            matched_client.channel_idx = final_idx
            active_map[final_idx] = matched_client.member_id
            active_pks[final_idx - 1] = g_alpha
            print_success(f"Channel slot {final_idx} successfully assigned to '{matched_client.member_id}'")
            
    # Servers configure their channel verification keys
    server_A.active_channels = active_pks
    server_B.active_channels = active_pks
    
    # 3. Main Phase (Spectrum)
    print_step("Step 3: Main Phase (Spectrum Anonymous Submissions)", "Broadcasters submit STIX IOCs while others send cover traffic")
    
    verifier = CHORUSVerifier(auth)
    consumer = CHORUSConsumer(T)
    
    # STIX bundle Alice wants to submit
    stix_alice = json.dumps({
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "pattern_type": "stix"
            }
        ]
    })
    
    seed_entropy = b"demo-round-mac-entropy"
    
    # Alice submits
    sub_A, sub_B = clients["Alice"].generate_main_submission(stix_alice, L, week, seed_entropy)
    
    # Other clients generate cover traffic
    main_subs_A = [sub_A]
    main_subs_B = [sub_B]
    
    for name, client in clients.items():
        if name == "Alice":
            continue
        cov_A, cov_B = client.generate_main_submission("", L, week, seed_entropy)
        main_subs_A.append(cov_A)
        main_subs_B.append(cov_B)
        
    print_info("Alice generated Spectrum DPF shares, pseudonym, Ring ZKP, and Carter-Wegman MAC shares")
    print_info(f"Simulating cover traffic submissions from {len(clients)-1} subscribers")
    
    # Server processing & Carter-Wegman MAC Audit
    agg_main_A, betas_A = server_A.process_main(main_subs_A, seed_entropy, peer_submissions=main_subs_B)
    agg_main_B, betas_B = server_B.process_main(main_subs_B, seed_entropy, peer_submissions=main_subs_A)
    
    # Perform MAC audits on servers
    print_info("Share servers running Carter-Wegman MAC Audits...")
    all_passed = True
    for idx in range(len(main_subs_A)):
        beta_sum = betas_A[idx] + betas_B[idx]
        is_valid = beta_sum == INF # equals INF
        if not is_valid:
            all_passed = False
            print_error(f"MAC Audit failed for client {main_subs_A[idx].client_id}")
            
    if all_passed:
        print_success("All submissions (including cover traffic) successfully passed Carter-Wegman MAC audits!")
        
    # Verifier aggregates and verifies
    print_info("Verifier reconstructing bulletin board channels...")
    verified_channels = verifier.verify_round(agg_main_A, agg_main_B, week)
    
    for ch in verified_channels:
        status = ch['status']
        status_style = Style.GREEN if status == "ok" else Style.RED
        print_success(f"Channel {ch['channel_index']}: Status = {status_style}{status}{Style.END}")
        if status == "ok":
            print_info(f"   Fingerprint: {ch['fp']}")
            print_info(f"   Pseudonym: {ch['P']}")
            
    # Consumer processes verified channels
    consumer.consume_channels(verified_channels)
    print_info(f"SIEM Alert count: {len(consumer.siem_alerts)}")
    
    # 4. Double Submission Detection
    print_step("Step 4: Double Submission (Replay Protection)", "Alice attempts to submit the same IOC in the same week")
    
    sub_A2, sub_B2 = clients["Alice"].generate_main_submission(stix_alice, L, week, seed_entropy)
    main_subs_A2 = [sub_A2]
    main_subs_B2 = [sub_B2]
    for name, client in clients.items():
        if name == "Alice":
            continue
        cov_A, cov_B = client.generate_main_submission("", L, week, seed_entropy)
        main_subs_A2.append(cov_A)
        main_subs_B2.append(cov_B)
        
    agg_main_A2, _ = server_A.process_main(main_subs_A2, seed_entropy, peer_submissions=main_subs_B2)
    agg_main_B2, _ = server_B.process_main(main_subs_B2, seed_entropy, peer_submissions=main_subs_A2)
    
    verified_channels2 = verifier.verify_round(agg_main_A2, agg_main_B2, week)
    for ch in verified_channels2:
        if ch['status'] != 'malformed':
            status = ch['status']
            status_style = Style.YELLOW if status == "duplicate" else Style.GREEN
            print_warning(f"Channel {ch['channel_index']}: Status = {status_style}{status}{Style.END} (Blacklist check executed)")
            
    # 5. Threshold Verification & SIEM Alerting
    print_step("Step 5: Threshold Verification & Alerting", "Bob submits the same indicator to reach the threshold (T=2)")
    
    # Bob submits same STIX bundle
    # Note: Bob has a different weekly key, so his pseudonym will be DIFFERENT than Alice's
    stix_bob = stix_alice
    sub_Bob_A, sub_Bob_B = clients["Bob"].generate_main_submission(stix_bob, L, week, seed_entropy)
    
    main_subs_A3 = [sub_Bob_A]
    main_subs_B3 = [sub_Bob_B]
    for name, client in clients.items():
        if name == "Bob":
            continue
        cov_A, cov_B = client.generate_main_submission("", L, week, seed_entropy)
        main_subs_A3.append(cov_A)
        main_subs_B3.append(cov_B)
        
    agg_main_A3, _ = server_A.process_main(main_subs_A3, seed_entropy, peer_submissions=main_subs_B3)
    agg_main_B3, _ = server_B.process_main(main_subs_B3, seed_entropy, peer_submissions=main_subs_A3)
    
    verified_channels3 = verifier.verify_round(agg_main_A3, agg_main_B3, week)
    for ch in verified_channels3:
        if ch['status'] != 'malformed':
            print_success(f"Channel {ch['channel_index']}: Status = {Style.GREEN}{ch['status']}{Style.END}")
            print_info(f"   Fingerprint: {ch['fp']}")
            print_info(f"   Bob's Pseudonym: {ch['P']}")
            
    consumer.consume_channels(verified_channels3)
    
    print_info(f"SIEM Alert count: {len(consumer.siem_alerts)}")
    if len(consumer.siem_alerts) > 0:
        alert = consumer.siem_alerts[0]
        print(f"\n{Style.BOLD}{Style.RED}[CRITICAL SIEM ALERT EMITTED]{Style.END}")
        print(f"  - Fingerprint: {alert['fp']}")
        print(f"  - Confirmed by {alert['evidence_count']} unique pseudonyms (Threshold T={T} met)")
        print(f"  - STIX Bundle Content:")
        print(f"    {alert['stix_bundle']}")
        
    print_header("DEMO COMPLETE")

if __name__ == '__main__':
    run_cli_demo()
