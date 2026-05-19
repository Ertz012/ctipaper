import unittest
import json
import hashlib
from chorus_core import Point, G, q, INF, hash_to_curve
from chorus_protocol import (
    ISACAuthority, CHORUSClient, CHORUSServer, CHORUSVerifier, CHORUSConsumer,
    serialize_payload, deserialize_payload, MainSubmission
)
from fingerprint import STIXFingerprint

class TestCHORUSProtocol(unittest.TestCase):
    def setUp(self):
        self.auth = ISACAuthority()
        self.L = 6
        self.week = 1
        self.seed_entropy = b"test-seed-entropy-value"
        
        # Onboard 3 members
        self.alice = CHORUSClient("Alice", self.auth)
        self.bob = CHORUSClient("Bob", self.auth)
        self.charlie = CHORUSClient("Charlie", self.auth)
        
        for c in [self.alice, self.bob, self.charlie]:
            c.rotate_weekly_key(self.week)

    def test_fingerprint_normalization(self):
        # Test IPv4
        bundle_ipv4 = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.42']"}]
        })
        fp_ipv4 = STIXFingerprint.compute(bundle_ipv4)
        
        # Test lowercase domains and IDN decoding
        bundle_domain = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[domain-name:value = 'MüNchEn.de']"}]
        })
        fp_domain = STIXFingerprint.compute(bundle_domain)
        self.assertNotEqual(fp_ipv4, fp_domain)
        self.assertEqual(len(fp_ipv4), 32)
        
    def test_bootstrap_claiming_and_collision_resolution(self):
        server_A = CHORUSServer("Server_A", self.L)
        
        # Select roles
        self.alice.choose_role("broadcaster")
        self.bob.choose_role("broadcaster")
        self.charlie.choose_role("broadcaster")
        
        # Mock decoded claims with channel slot collision:
        # Alice claims slot 2 (from database index 1)
        # Bob claims slot 2 (from database index 2)
        # Charlie claims slot 4 (from database index 3)
        claims = [
            {'g_alpha': self.alice.g_alpha, 'claim_idx': 2, 'nonce': b'alice-nonce-1234', 'reconstructed_at': 2},
            {'g_alpha': self.bob.g_alpha, 'claim_idx': 2, 'nonce': b'bob-nonce-567890', 'reconstructed_at': 3},
            {'g_alpha': self.charlie.g_alpha, 'claim_idx': 4, 'nonce': b'charlie-nonce-abc', 'reconstructed_at': 4}
        ]
        
        # Resolve collisions
        assignments = server_A.resolve_collisions(claims)
        self.assertEqual(len(assignments), 3)
        
        # All assigned to unique slots
        slots = [idx for _, idx in assignments]
        self.assertEqual(len(set(slots)), 3)
        self.assertTrue(2 in slots)
        self.assertTrue(4 in slots)

    def test_main_round_successful_flow(self):
        # Alice claims slot 2
        self.alice.choose_role("broadcaster")
        self.alice.channel_idx = 2
        
        # Bob and Charlie send cover traffic
        self.bob.choose_role("subscriber")
        self.charlie.choose_role("subscriber")
        
        # Active channel keys on servers
        active_pks = [None] * self.L
        active_pks[1] = self.alice.g_alpha
        
        server_A = CHORUSServer("Server_A", self.L)
        server_B = CHORUSServer("Server_B", self.L)
        server_A.active_channels = active_pks
        server_B.active_channels = active_pks
        
        # Submissions
        stix_alice = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.42']"}]
        })
        
        sub_A_A, sub_A_B = self.alice.generate_main_submission(stix_alice, self.L, self.week, self.seed_entropy)
        sub_B_A, sub_B_B = self.bob.generate_main_submission("", self.L, self.week, self.seed_entropy)
        sub_C_A, sub_C_B = self.charlie.generate_main_submission("", self.L, self.week, self.seed_entropy)
        
        # Aggregate
        agg_A, betas_A = server_A.process_main([sub_A_A, sub_B_A, sub_C_A], self.seed_entropy, peer_submissions=[sub_A_B, sub_B_B, sub_C_B])
        agg_B, betas_B = server_B.process_main([sub_A_B, sub_B_B, sub_C_B], self.seed_entropy, peer_submissions=[sub_A_A, sub_B_A, sub_C_A])
        
        # MAC audit checks out
        for idx in range(len(betas_A)):
            beta_sum = betas_A[idx] + betas_B[idx]
            self.assertTrue(beta_sum.is_infinity(), f"Audit failed for index {idx}")
            
        # Reconstruct
        verifier = CHORUSVerifier(self.auth)
        verified_channels = verifier.verify_round(agg_A, agg_B, self.week)
        
        # Find Alice's channel in the non-empty list
        alice_channel = next(ch for ch in verified_channels if ch['channel_index'] == 2)
        self.assertEqual(alice_channel['status'], 'ok')
        self.assertEqual(json.loads(alice_channel['stix_bundle'])['type'], 'bundle')

    def test_main_round_mac_failure(self):
        # Alice claims slot 2
        self.alice.choose_role("broadcaster")
        self.alice.channel_idx = 2
        
        active_pks = [None] * self.L
        active_pks[1] = self.alice.g_alpha
        
        server_A = CHORUSServer("Server_A", self.L)
        server_B = CHORUSServer("Server_B", self.L)
        server_A.active_channels = active_pks
        server_B.active_channels = active_pks
        
        stix_alice = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.42']"}]
        })
        
        sub_A_A, sub_A_B = self.alice.generate_main_submission(stix_alice, self.L, self.week, self.seed_entropy)
        
        # Tamper with MAC share
        bad_sub_A_A = MainSubmission(sub_A_A.dpf_key, (sub_A_A.mac_share + 1) % q, sub_A_A.client_id)
        
        # Aggregate
        agg_A, betas_A = server_A.process_main([bad_sub_A_A], self.seed_entropy, peer_submissions=[sub_A_B])
        agg_B, betas_B = server_B.process_main([sub_A_B], self.seed_entropy, peer_submissions=[bad_sub_A_A])
        
        # MAC audit must fail
        beta_sum = betas_A[0] + betas_B[0]
        self.assertFalse(beta_sum.is_infinity(), "Audit should have failed due to tampered MAC share")

    def test_main_round_self_binding_failure(self):
        # Create a payload where the claimed fingerprint does not match the actual STIX bundle hash
        stix_bytes = b"fake-stix-data"
        fp_wrong = b"\x00" * 32
        
        # Generate valid proofs but for fp_wrong
        H_fp = hash_to_curve(fp_wrong)
        P = H_fp * self.alice.k_w
        
        weekly_roster = self.auth.get_weekly_roster(self.week)
        my_idx = sorted(self.auth.roster.keys()).index(self.alice.member_id)
        
        from chorus_core import zkp_prove
        c_proof, s_proof = zkp_prove(weekly_roster, H_fp, P, self.alice.k_w, my_idx)
        
        payload_bad = serialize_payload(stix_bytes, fp_wrong, P, c_proof, s_proof)
        # Pad
        payload_bad = payload_bad + b'\x00' * (4096 - len(payload_bad))
        
        # Verify directly through deserialize
        ch_payload = deserialize_payload(payload_bad)
        self.assertEqual(ch_payload.fp, fp_wrong)
        
        # Verifier checks
        verifier = CHORUSVerifier(self.auth)
        # Simulate local verification on extracted payload
        fp_recomputed = STIXFingerprint.compute(ch_payload.stix_bundle.decode('utf-8', errors='ignore'))
        self.assertNotEqual(fp_recomputed, ch_payload.fp)

    def test_double_submission_blacklist(self):
        # Alice claims channel index 2
        self.alice.choose_role("broadcaster")
        self.alice.channel_idx = 2
        
        active_pks = [None] * self.L
        active_pks[1] = self.alice.g_alpha
        
        server_A = CHORUSServer("Server_A", self.L)
        server_B = CHORUSServer("Server_B", self.L)
        server_A.active_channels = active_pks
        server_B.active_channels = active_pks
        
        stix_alice = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.42']"}]
        })
        
        # Submit first time
        sub_A_A, sub_A_B = self.alice.generate_main_submission(stix_alice, self.L, self.week, self.seed_entropy)
        agg_A, betas_A = server_A.process_main([sub_A_A], self.seed_entropy, peer_submissions=[sub_A_B])
        agg_B, betas_B = server_B.process_main([sub_A_B], self.seed_entropy, peer_submissions=[sub_A_A])
        
        verifier = CHORUSVerifier(self.auth)
        verified_channels1 = verifier.verify_round(agg_A, agg_B, self.week)
        alice_channel1 = next(ch for ch in verified_channels1 if ch['channel_index'] == 2)
        self.assertEqual(alice_channel1['status'], 'ok')
        
        # Submit second time (same week, same client, same IOC)
        sub_A_A2, sub_A_B2 = self.alice.generate_main_submission(stix_alice, self.L, self.week, self.seed_entropy)
        agg_A2, _ = server_A.process_main([sub_A_A2], self.seed_entropy, peer_submissions=[sub_A_B2])
        agg_B2, _ = server_B.process_main([sub_A_B2], self.seed_entropy, peer_submissions=[sub_A_A2])
        
        verified_channels2 = verifier.verify_round(agg_A2, agg_B2, self.week)
        alice_channel2 = next(ch for ch in verified_channels2 if ch['channel_index'] == 2)
        self.assertEqual(alice_channel2['status'], 'duplicate')

    def test_threshold_alerting(self):
        # Alice claims slot 2, Bob claims slot 4
        self.alice.choose_role("broadcaster")
        self.alice.channel_idx = 2
        self.bob.choose_role("broadcaster")
        self.bob.channel_idx = 4
        
        active_pks = [None] * self.L
        active_pks[1] = self.alice.g_alpha
        active_pks[3] = self.bob.g_alpha
        
        server_A = CHORUSServer("Server_A", self.L)
        server_B = CHORUSServer("Server_B", self.L)
        server_A.active_channels = active_pks
        server_B.active_channels = active_pks
        
        stix_payload = json.dumps({
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.42']"}]
        })
        
        # Alice submits IOC
        sub_Alice_A, sub_Alice_B = self.alice.generate_main_submission(stix_payload, self.L, self.week, self.seed_entropy)
        
        # Bob submits same IOC
        sub_Bob_A, sub_Bob_B = self.bob.generate_main_submission(stix_payload, self.L, self.week, self.seed_entropy)
        
        # Step 1: Alice's submission processed
        agg_A1, _ = server_A.process_main([sub_Alice_A], self.seed_entropy, peer_submissions=[sub_Alice_B])
        agg_B1, _ = server_B.process_main([sub_Alice_B], self.seed_entropy, peer_submissions=[sub_Alice_A])
        
        verifier = CHORUSVerifier(self.auth)
        consumer = CHORUSConsumer(T=2)
        
        v_ch1 = verifier.verify_round(agg_A1, agg_B1, self.week)
        consumer.consume_channels(v_ch1)
        self.assertEqual(len(consumer.siem_alerts), 0) # T=2, only 1 unique report so far
        
        # Step 2: Bob's submission processed
        agg_A2, _ = server_A.process_main([sub_Bob_A], self.seed_entropy, peer_submissions=[sub_Bob_B])
        agg_B2, _ = server_B.process_main([sub_Bob_B], self.seed_entropy, peer_submissions=[sub_Bob_A])
        
        v_ch2 = verifier.verify_round(agg_A2, agg_B2, self.week)
        consumer.consume_channels(v_ch2)
        
        # Threshold met! 2 unique members (Alice, Bob) reported same fingerprint
        self.assertEqual(len(consumer.siem_alerts), 1)
        alert = consumer.siem_alerts[0]
        self.assertEqual(alert['fp'], STIXFingerprint.compute(stix_payload).hex())
        self.assertEqual(alert['evidence_count'], 2)


if __name__ == '__main__':
    unittest.main()
