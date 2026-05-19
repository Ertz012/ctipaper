import os
import json
import struct
import hashlib
import random
import traceback
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Dict, List, Optional

# Import CHORUS modules
from chorus_core import Point, G, q, hash_to_curve, INF
from chorus_protocol import (
    ISACAuthority, CHORUSClient, CHORUSServer, CHORUSVerifier, CHORUSConsumer,
    serialize_payload, deserialize_payload
)
import taxii

app = FastAPI(title="CHORUS Protocol Simulator")

# Add the TAXII routes
app.include_router(taxii.taxii_router)

# Simulation Global State
class SimulationState:
    def __init__(self):
        self.authority = ISACAuthority()
        self.clients: Dict[str, CHORUSClient] = {}
        self.server_A: Optional[CHORUSServer] = None
        self.server_B: Optional[CHORUSServer] = None
        self.verifier: Optional[CHORUSVerifier] = None
        self.consumer: Optional[CHORUSConsumer] = None
        
        self.L = 6 # Default number of channels
        self.week = 1
        self.threshold = 2
        self.is_initialized = False
        
        # Logs and history for UI visualization
        self.logs: List[Dict] = []
        self.round_history: List[Dict] = []
        
    def add_log(self, stage: str, message: str, detail: Optional[str] = None, log_type: str = "info"):
        self.logs.append({
            "stage": stage,
            "message": message,
            "detail": detail,
            "type": log_type
        })

sim_state = SimulationState()

class InitParams(BaseModel):
    client_ids: List[str]
    L: int
    threshold: int

class BootstrapParams(BaseModel):
    claims: Dict[str, int] # member_id -> claimed_idx

class SubmitIocParams(BaseModel):
    client_id: str
    stix_bundle: str

@app.post("/api/initialize")
async def initialize_sim(params: InitParams):
    try:
        sim_state.__init__() # Reset state
        sim_state.L = params.L
        sim_state.threshold = params.threshold
        
        # Initialize clients
        for c_id in params.client_ids:
            client = CHORUSClient(c_id, sim_state.authority)
            sim_state.clients[c_id] = client
            sim_state.add_log("Onboarding", f"Onboarded member '{c_id}'", f"Master Public Key: {client.pk_master}", "success")
            
        # Initialize Servers
        sim_state.server_A = CHORUSServer("Server_A", params.L)
        sim_state.server_B = CHORUSServer("Server_B", params.L)
        
        # Initialize Verifier & Consumer
        sim_state.verifier = CHORUSVerifier(sim_state.authority)
        sim_state.consumer = CHORUSConsumer(params.threshold)
        
        # Rotate keys for week 1 initially
        for client in sim_state.clients.values():
            client.rotate_weekly_key(sim_state.week)
            
        sim_state.is_initialized = True
        
        # Configure the global TAXII system instance
        taxii.taxii_system = taxii.TAXIISystem(
            list(sim_state.clients.values()),
            sim_state.verifier,
            [sim_state.server_A, sim_state.server_B],
            sim_state.L,
            sim_state.week
        )
        
        sim_state.add_log("Initialization", "Simulation successfully initialized", f"Total Clients: {len(params.client_ids)}, Channels (L): {params.L}", "success")
        return {"status": "success", "message": "Simulation initialized"}
    except Exception as e:
        sim_state.add_log("Initialization", "Failed to initialize simulation", str(e), "error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rotate-keys")
async def rotate_keys():
    if not sim_state.is_initialized:
        raise HTTPException(status_code=400, detail="Simulation not initialized")
    try:
        sim_state.week += 1
        weekly_roster = []
        for c_id, client in sim_state.clients.items():
            client.rotate_weekly_key(sim_state.week)
            weekly_roster.append({
                "client_id": c_id,
                "weekly_pk": client.pk_w.serialize().hex()
            })
            
        # Reset weekly blacklist in verifier
        sim_state.verifier.reset_weekly_blacklist()
        
        # Update TAXII system week
        if taxii.taxii_system:
            taxii.taxii_system.week = sim_state.week
            
        sim_state.add_log(
            "Key Rotation", 
            f"Rotated weekly keys to week {sim_state.week}", 
            f"Roster updated. Blacklist cleared.", 
            "info"
        )
        return {"status": "success", "week": sim_state.week, "roster": weekly_roster}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/bootstrap")
async def run_bootstrap(params: BootstrapParams):
    if not sim_state.is_initialized:
        raise HTTPException(status_code=400, detail="Simulation not initialized")
    try:
        sim_state.add_log("Bootstrap", "Starting Bootstrap Phase (Channel Claiming)...")
        
        # Set roles and generate Riposte submissions
        claims_list = []
        submissions_A = []
        submissions_B = []
        
        for c_id, client in sim_state.clients.items():
            claimed_idx = params.claims.get(c_id, 0)
            if claimed_idx > 0:
                client.choose_role("broadcaster")
                claims_list.append({
                    "client_id": c_id,
                    "claimed_idx": claimed_idx,
                    "g_alpha": client.g_alpha.serialize().hex()
                })
                sim_state.add_log("Bootstrap", f"Member '{c_id}' claims channel slot {claimed_idx}", f"g^alpha: {client.g_alpha}", "info")
            else:
                client.choose_role("subscriber")
                
            # Generate shares
            share_A, share_B = client.generate_bootstrap_submission(claimed_idx, sim_state.L)
            submissions_A.append(share_A)
            submissions_B.append(share_B)
            
        # Servers process bootstrap shares
        agg_A = sim_state.server_A.process_bootstrap(submissions_A)
        agg_B = sim_state.server_B.process_bootstrap(submissions_B)
        
        # Reconstruct Riposte DB
        # Final aggregated db on the blackboard
        final_db_bytes = []
        for x in range(sim_state.L):
            final_db_bytes.append(bytes(a ^ b for a, b in zip(agg_A[x], agg_B[x])))
            
        # Decode claims
        reconstructed_claims = sim_state.server_A.decode_bootstrap_db(final_db_bytes)
        sim_state.add_log("Bootstrap", f"Reconstructed {len(reconstructed_claims)} raw channel claims from blackboard", None, "info")
        
        # Resolve Collisions and perform Tie-Breaking
        final_assignments = sim_state.server_A.resolve_collisions(reconstructed_claims)
        
        # Assign indices back to clients
        active_channels_map = {}
        for g_alpha, final_idx in final_assignments:
            # Match g_alpha back to client
            matched_client = None
            for client in sim_state.clients.values():
                if client.g_alpha and client.g_alpha == g_alpha:
                    matched_client = client
                    break
            if matched_client:
                matched_client.channel_idx = final_idx
                active_channels_map[final_idx] = matched_client.member_id
                
        # Servers record the active channel public keys in correct order
        # L' = number of active channels
        L_prime = len(final_assignments)
        sorted_assignments = sorted(final_assignments, key=lambda x: x[1]) # Sort by channel index
        
        active_pks = [None] * sim_state.L
        for g_alpha, final_idx in final_assignments:
            active_pks[final_idx - 1] = g_alpha
        sim_state.server_A.active_channels = active_pks
        sim_state.server_B.active_channels = active_pks
        
        # Formulate signed Channel List CL_w
        cl_w = []
        for g_alpha, idx in sorted_assignments:
            cl_w.append({
                "channel_index": idx,
                "g_alpha": g_alpha.serialize().hex(),
                "assigned_member": active_channels_map[idx]
            })
            
        sim_state.add_log("Bootstrap", f"Bootstrap Phase complete. L' = {L_prime} active channels allocated.", json.dumps(cl_w), "success")
        return {
            "status": "success",
            "L_prime": L_prime,
            "channel_list": cl_w
        }
    except Exception as e:
        traceback.print_exc()
        sim_state.add_log("Bootstrap", "Failed to complete bootstrap phase", str(e), "error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/submit-ioc")
async def submit_ioc(params: SubmitIocParams):
    if not sim_state.is_initialized:
        raise HTTPException(status_code=400, detail="Simulation not initialized")
    try:
        client = sim_state.clients.get(params.client_id)
        if not client:
            raise HTTPException(status_code=400, detail="Client not found")
        if client.role != "broadcaster" or client.channel_idx is None:
            raise HTTPException(status_code=400, detail="Client is not an active broadcaster")
            
        # Parse STIX to ensure valid JSON
        try:
            stix_data = json.loads(params.stix_bundle)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid STIX bundle JSON")
            
        sim_state.add_log(
            "Main Round", 
            f"Client '{params.client_id}' is generating a Main Round submission for channel slot {client.channel_idx}"
        )
        
        # 1. Generate client submission
        sub_A, sub_B = client.generate_main_submission(params.stix_bundle, sim_state.L, sim_state.week)
        
        # Prepare list of submissions (1 real broadcaster, rest are cover traffic)
        submissions_A = [sub_A]
        submissions_B = [sub_B]
        
        cover_clients = []
        for other_id, other_client in sim_state.clients.items():
            if other_id == params.client_id:
                continue
            cov_A, cov_B = other_client.generate_main_submission("", sim_state.L, sim_state.week)
            submissions_A.append(cov_A)
            submissions_B.append(cov_B)
            cover_clients.append(other_id)
            
        sim_state.add_log(
            "Main Round", 
            f"Simulating cover traffic. {len(cover_clients)} subscribers submitted zero-payload DPF keys.",
            f"Cover Clients: {', '.join(cover_clients)}"
        )
        
        # 2. Server Processing & Carter-Wegman MAC Audit
        seed_entropy = b"round-mac-entropy"
        agg_A, betas_A = sim_state.server_A.process_main(submissions_A, seed_entropy, peer_submissions=submissions_B)
        agg_B, betas_B = sim_state.server_B.process_main(submissions_B, seed_entropy, peer_submissions=submissions_A)
        
        # Run audits
        audit_results = []
        passed_count = 0
        for i in range(len(submissions_A)):
            sub_id = submissions_A[i].client_id
            # Beta sum
            beta_sum = betas_A[i] + betas_B[i]
            is_valid = beta_sum == INF # equals INF
            
            audit_results.append({
                "client_id": sub_id,
                "passed": is_valid,
                "beta_sum": beta_sum.serialize().hex()
            })
            if is_valid:
                passed_count += 1
                
        sim_state.add_log(
            "Main Round - Server Audit",
            f"Carter-Wegman MAC Audits performed. {passed_count}/{len(submissions_A)} submissions passed.",
            json.dumps(audit_results),
            "success" if passed_count == len(submissions_A) else "warning"
        )
        
        # 3. Verifier Post-Aggregation Checks
        verified_channels = sim_state.verifier.verify_round(agg_A, agg_B, sim_state.week)
        
        # Extract trace details of the submission for UI inspection
        trace = {
            "fingerprint": hashlib.sha256(params.stix_bundle.encode('utf-8')).digest().hex()[:32], # placeholder for trace
            "pseudonym": "",
            "status": "",
            "checks": []
        }
        
        for ch in verified_channels:
            if ch.get('channel_index') == client.channel_idx:
                trace["fingerprint"] = ch.get('fp')
                trace["pseudonym"] = ch.get('P')
                trace["status"] = ch.get('status')
                
        # 4. Consumer updates
        sim_state.consumer.consume_channels(verified_channels)
        
        sim_state.add_log(
            "Verifier & Consumer",
            f"Verifier decoded bulletin board. Consumer processed verified IOCs.",
            json.dumps(verified_channels),
            "success"
        )
        
        sim_state.round_history.append({
            "week": sim_state.week,
            "broadcaster": params.client_id,
            "channel_idx": client.channel_idx,
            "trace": trace,
            "results": verified_channels
        })
        
        return {
            "status": "success",
            "audit": audit_results,
            "verified_channels": verified_channels,
            "alerts": sim_state.consumer.siem_alerts
        }
        
    except Exception as e:
        traceback.print_exc()
        sim_state.add_log("Main Round", "Submission failed", str(e), "error")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/state")
async def get_state():
    if not sim_state.is_initialized:
        return {"is_initialized": False}
        
    roster_list = []
    for c_id, client in sim_state.clients.items():
        roster_list.append({
            "client_id": c_id,
            "pk_master": client.pk_master.serialize().hex(),
            "role": client.role,
            "channel_idx": client.channel_idx,
            "weekly_pk": client.pk_w.serialize().hex() if client.pk_w else None
        })
        
    blacklist_list = [bytes.fromhex(p_hex).hex() for p_hex in [p_bytes.hex() for p_bytes in sim_state.verifier.blacklist]]
    
    distinct_counts = {}
    for fp, p_set in sim_state.consumer.distinct_pseudonyms_per_fp.items():
        distinct_counts[fp] = list(p_set)
        
    return {
        "is_initialized": True,
        "week": sim_state.week,
        "L": sim_state.L,
        "threshold": sim_state.threshold,
        "roster": roster_list,
        "blacklist": blacklist_list,
        "evidence_store": distinct_counts,
        "alerts": sim_state.consumer.siem_alerts,
        "logs": sim_state.logs,
        "history": sim_state.round_history
    }

# ----------------- UI / Front-end -----------------
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHORUS Anonymous CTI Bulletin Board Protocol Simulator</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-surface: #131b2e;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --accent-green: #10b981;
            --accent-cyan: #06b6d4;
            --accent-purple: #a855f7;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --border: #334155;
            --font-main: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-main);
            background-color: var(--bg-base);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
            min-height: 100vh;
        }

        header {
            margin-bottom: 2rem;
            text-align: center;
        }

        header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--primary), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.1rem;
        }

        .dashboard {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 2rem;
            max-width: 1600px;
            margin: 0 auto;
        }

        .sidebar {
            background-color: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            height: fit-content;
        }

        .main-content {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .card {
            background-color: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.75rem;
        }

        .card-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* Buttons */
        .btn {
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 8px;
            font-family: var(--font-main);
            font-weight: 500;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .btn:hover {
            background-color: var(--primary-hover);
            transform: translateY(-1px);
        }

        .btn-secondary {
            background-color: transparent;
            border: 1px solid var(--border);
            color: var(--text-main);
        }

        .btn-secondary:hover {
            background-color: var(--border);
        }

        .btn-danger {
            background-color: var(--accent-red);
        }

        .btn-danger:hover {
            background-color: #dc2626;
        }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }

        .tab {
            padding: 0.75rem 1.25rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            color: var(--text-muted);
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .tab.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }

        /* Form Controls */
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        label {
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        input, select, textarea {
            background-color: var(--bg-base);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.6rem 0.8rem;
            border-radius: 8px;
            font-family: var(--font-main);
            font-size: 0.95rem;
            outline: none;
            width: 100%;
        }

        input:focus, select:focus, textarea:focus {
            border-color: var(--primary);
        }

        /* Roster / Tables */
        .grid-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 1rem;
        }

        .member-badge {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            position: relative;
        }

        .badge-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .badge-role {
            font-size: 0.75rem;
            padding: 0.15rem 0.5rem;
            border-radius: 9999px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-role.broadcaster {
            background-color: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
        }

        .badge-role.subscriber {
            background-color: rgba(148, 163, 184, 0.15);
            color: var(--text-muted);
        }

        .badge-name {
            font-weight: 600;
            font-size: 1.05rem;
        }

        .badge-detail {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: var(--text-muted);
            word-break: break-all;
        }

        /* Logs & Code console */
        .console {
            background-color: #05070f;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            max-height: 250px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .log-item {
            display: flex;
            gap: 0.5rem;
        }

        .log-tag {
            color: var(--accent-cyan);
            font-weight: bold;
            flex-shrink: 0;
        }

        .log-item.success .log-tag { color: var(--accent-green); }
        .log-item.error .log-tag { color: var(--accent-red); }
        .log-item.warning .log-tag { color: var(--accent-amber); }

        .log-detail {
            color: var(--text-muted);
            margin-left: 1.5rem;
            font-size: 0.8rem;
            white-space: pre-wrap;
            word-break: break-all;
            background-color: #0e1220;
            padding: 0.4rem;
            border-radius: 4px;
        }

        /* Flow Visualizer */
        .network-viz {
            height: 240px;
            background-color: #070a13;
            border: 1px solid var(--border);
            border-radius: 12px;
            display: flex;
            justify-content: space-around;
            align-items: center;
            position: relative;
            padding: 1rem;
            overflow: hidden;
        }

        .viz-node {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.5rem;
            z-index: 2;
        }

        .viz-circle {
            width: 54px;
            height: 54px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 0.9rem;
            border: 2px solid var(--border);
            background-color: var(--bg-card);
            box-shadow: 0 0 15px rgba(0,0,0,0.5);
            transition: all 0.3s ease;
        }

        .viz-node.active .viz-circle {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
            transform: scale(1.08);
        }

        .viz-label {
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        .viz-connection {
            position: absolute;
            height: 2px;
            background: linear-gradient(90deg, var(--border), var(--border));
            z-index: 1;
            top: 50%;
            transform: translateY(-50%);
            width: 80%;
        }

        .viz-connection.active {
            background: linear-gradient(90deg, var(--accent-cyan), var(--primary), var(--accent-purple));
            animation: pulse-line 2s infinite;
        }

        @keyframes pulse-line {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }

        /* Channel Slots */
        .channel-slots {
            display: flex;
            gap: 0.75rem;
            overflow-x: auto;
            padding-bottom: 0.5rem;
        }

        .slot-card {
            min-width: 140px;
            flex: 1;
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 0.75rem;
            text-align: center;
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
        }

        .slot-card.active {
            border-color: var(--accent-cyan);
            background: linear-gradient(180deg, var(--bg-card) 0%, rgba(6, 182, 212, 0.05) 100%);
        }

        .slot-index {
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--text-muted);
        }

        .slot-card.active .slot-index {
            color: var(--accent-cyan);
        }

        .slot-owner {
            font-size: 0.95rem;
            font-weight: 600;
        }

        .slot-pk {
            font-family: var(--font-mono);
            font-size: 0.65rem;
            color: var(--text-muted);
            word-break: break-all;
        }

        /* SIEM alerts */
        .alert-item {
            background-color: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 0.75rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--accent-red);
            font-weight: bold;
        }

        .alert-body {
            font-family: var(--font-mono);
            font-size: 0.8rem;
            background-color: #0a0c14;
            padding: 0.5rem;
            border-radius: 6px;
            overflow-x: auto;
            white-space: pre-wrap;
        }

        .alert-meta {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .flex-row {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .grid-2col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
    </style>
</head>
<body>

    <header>
        <h1>CHORUS: Anonymous Collaborative CTI Exchange</h1>
        <p>Spectrum & Riposte-based Cryptographic Bulletin Board Prototype</p>
    </header>

    <div class="dashboard">
        <!-- Sidebar controls -->
        <div class="sidebar">
            <div class="card-title" style="border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;">
                ⚙️ Simulation Config
            </div>
            
            <div class="form-group">
                <label>Number of Channels (L)</label>
                <input type="number" id="param-L" value="6" min="3" max="20">
            </div>

            <div class="form-group">
                <label>SIEM Threshold (T)</label>
                <input type="number" id="param-threshold" value="2" min="1" max="5">
            </div>

            <button class="btn" onclick="initializeSim()">Initialize Network</button>
            <button class="btn btn-secondary" onclick="rotateKeys()">Rotate Weekly Keys</button>
            
            <div style="margin-top: 1rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <h3 style="font-size: 0.95rem; margin-bottom: 0.5rem; color: var(--text-muted);">Current Phase</h3>
                <div id="status-phase" style="font-weight: bold; font-size: 1.1rem; color: var(--accent-cyan);">Not Initialized</div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;">
                    Week: <span id="status-week" style="color: var(--text-main); font-weight: bold;">-</span>
                </div>
            </div>
        </div>

        <!-- Main content area -->
        <div class="main-content">
            <!-- Roster & Active Members -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">👥 ISAC Public Key Roster & Client Nodes</div>
                    <div class="flex-row">
                        <span id="roster-count" class="badge-role subscriber" style="background-color: var(--border);">0 Clients</span>
                    </div>
                </div>
                <div class="grid-list" id="member-roster">
                    <div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 2rem;">
                        Initialize the network to view the public roster.
                    </div>
                </div>
            </div>

            <!-- Visual Flow Network -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🔗 Protocol Transmission Pipeline</div>
                </div>
                <div class="network-viz">
                    <div class="viz-connection active" id="net-conn"></div>
                    <div class="viz-node" id="node-clients">
                        <div class="viz-circle">Clients</div>
                        <div class="viz-label">Broadcasters</div>
                    </div>
                    <div class="viz-node" id="node-serverA">
                        <div class="viz-circle" style="border-color: var(--accent-purple);">S_A</div>
                        <div class="viz-label">Share Server A</div>
                    </div>
                    <div class="viz-node" id="node-serverB">
                        <div class="viz-circle" style="border-color: var(--accent-purple);">S_B</div>
                        <div class="viz-label">Share Server B</div>
                    </div>
                    <div class="viz-node" id="node-verifier">
                        <div class="viz-circle" style="border-color: var(--accent-green);">Verify</div>
                        <div class="viz-label">Decrypter/Verifier</div>
                    </div>
                    <div class="viz-node" id="node-siem">
                        <div class="viz-circle" style="border-color: var(--accent-red);">SIEM</div>
                        <div class="viz-label">Consumer</div>
                    </div>
                </div>
            </div>

            <!-- Tabbed Interface for Actions -->
            <div class="card">
                <div class="tabs">
                    <div class="tab active" id="tab-bootstrap" onclick="switchTab('bootstrap')">Phase 1: Bootstrap (Riposte)</div>
                    <div class="tab" id="tab-main" onclick="switchTab('main')">Phase 2: Main Round (Spectrum)</div>
                    <div class="tab" id="tab-blacklist" onclick="switchTab('blacklist')">Weekly Blacklist & Evidence</div>
                </div>

                <!-- Bootstrap Tab Content -->
                <div id="content-bootstrap" class="tab-content">
                    <p style="color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.95rem;">
                        Broadcasters claim write channels via Riposte. Collisions are resolved deterministically using hashes of their claims.
                    </p>
                    <div class="grid-2col">
                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Select Channel Claims</h3>
                            <div id="bootstrap-claims-form">
                                <!-- Populated dynamically -->
                            </div>
                            <button class="btn" style="margin-top: 1rem;" onclick="runBootstrap()">Run Riposte Channel Claims</button>
                        </div>
                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Active Channel List (CL_w)</h3>
                            <div class="channel-slots" id="channel-slots-view">
                                <div style="color: var(--text-muted); padding: 1rem;">No channels allocated. Run bootstrap first.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main Round Tab Content -->
                <div id="content-main" class="tab-content" style="display: none;">
                    <p style="color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.95rem;">
                        Broadcasters submit normalized STIX IOCs with DPF shares, content-bound weekly pseudonyms, and ring ZKPs.
                    </p>
                    <div class="grid-2col">
                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Submit Indicator Anonymously</h3>
                            
                            <div class="form-group">
                                <label>Broadcaster Node</label>
                                <select id="main-submitter">
                                    <!-- Populated dynamically -->
                                </select>
                            </div>

                            <div class="form-group">
                                <label>STIX 2.1 Bundle (JSON)</label>
                                <textarea id="main-stix-bundle" rows="8" style="font-family: var(--font-mono); font-size: 0.85rem;">
{
  "type": "bundle",
  "id": "bundle--2c6a-4d2c-88e2",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--8b3f-1d4e",
      "pattern": "[ipv4-addr:value = '198.51.100.42']",
      "pattern_type": "stix",
      "valid_from": "2026-05-19T00:00:00Z"
    }
  ]
}</textarea>
                            </div>

                            <button class="btn" onclick="submitIoc()">Submit STIX Bundle Anonymously</button>
                            <button class="btn btn-secondary" onclick="loadTemplate('ipv4')">Template: IP</button>
                            <button class="btn btn-secondary" onclick="loadTemplate('hash')">Template: Hash</button>
                        </div>

                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem;">Main Round Cryptographic Trace</h3>
                            <div style="background-color: #070a13; border: 1px solid var(--border); border-radius: 12px; padding: 1rem; font-family: var(--font-mono); font-size: 0.85rem; height: 350px; overflow-y: auto;" id="main-trace-view">
                                <div style="color: var(--text-muted);">Submit an IOC to trace DPF keys, MAC tag audits, and ZKPs.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Blacklist Tab Content -->
                <div id="content-blacklist" class="tab-content" style="display: none;">
                    <div class="grid-2col">
                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem; color: var(--accent-red);">Weekly-Rotating Blacklist</h3>
                            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
                                Keeps weekly pseudonyms to detect duplicate uploads by the same member in a week without revealing identity. Cleared during key rotation.
                            </p>
                            <div class="console" id="blacklist-view" style="max-height: 350px;">
                                <div>No pseudonyms blacklisted.</div>
                            </div>
                        </div>
                        <div>
                            <h3 style="margin-bottom: 1rem; font-size: 1.1rem; color: var(--accent-cyan);">Evidence Store</h3>
                            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
                                Accumulates unique pseudonyms per fingerprint. Serves as client-side threshold check database.
                            </p>
                            <div class="console" id="evidence-view" style="max-height: 350px;">
                                <div>No evidence collected yet.</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SIEM / TAXII Outlets -->
            <div class="grid-2col">
                <!-- SIEM Alerts -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title" style="color: var(--accent-red);">🚨 SIEM Consumer Alerts</div>
                    </div>
                    <div id="siem-alerts-list" style="max-height: 300px; overflow-y: auto;">
                        <div style="color: var(--text-muted); text-align: center; padding: 2rem;">No alerts emitted. Indicators require T unique reports.</div>
                    </div>
                </div>

                <!-- TAXII 2.1 Interface -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title" style="color: var(--accent-cyan);">🔌 TAXII 2.1 API Endpoint Simulation</div>
                    </div>
                    <div style="font-size: 0.9rem; display: flex; flex-direction: column; gap: 0.75rem;">
                        <p style="color: var(--text-muted);">
                            Local CTI tools (e.g. MISP) write to local adapters, and SIEMs pull via TAXII GET.
                        </p>
                        <div class="console" style="height: 160px; font-size: 0.8rem;" id="taxii-console">
                            [GET] /taxii2/ - Discovery Endpoint available
                            [GET] /taxii2/api1/collections/ - Shared Collection listed
                        </div>
                        <div class="flex-row">
                            <button class="btn btn-secondary" onclick="testTaxiiGet()">Test GET Collection</button>
                            <button class="btn btn-secondary" onclick="testTaxiiPost()">Test POST Local Adapter</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Simulation Protocol Console Logs -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🖥️ Protocol Execution Ledger</div>
                </div>
                <div class="console" id="protocol-console" style="max-height: 300px;">
                    <div>System ready. Please initialize the network.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentTab = 'bootstrap';

        function switchTab(tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
            
            document.getElementById(`tab-${tabId}`).classList.add('active');
            document.getElementById(`content-${tabId}`).style.display = 'block';
            currentTab = tabId;
        }

        async function updateState() {
            try {
                const res = await fetch('/api/state');
                const state = await res.json();
                
                if (!state.is_initialized) return;

                // Update Phase Status
                document.getElementById('status-phase').innerText = state.blacklist.length > 0 ? "Main Phase Running" : "Bootstrap Complete / Main Active";
                document.getElementById('status-week').innerText = state.week;

                // Update Roster
                const rosterCount = document.getElementById('roster-count');
                rosterCount.innerText = `${state.roster.length} Clients`;
                
                const rosterDiv = document.getElementById('member-roster');
                rosterDiv.innerHTML = state.roster.map(m => {
                    const ch_idx = m.channel_idx ? `Slot ${m.channel_idx}` : 'Subscriber';
                    const active_class = m.role === 'broadcaster' ? 'broadcaster' : 'subscriber';
                    return `
                        <div class="member-badge">
                            <div class="badge-header">
                                <span class="badge-name">${m.client_id}</span>
                                <span class="badge-role ${active_class}">${ch_idx}</span>
                            </div>
                            <div class="badge-detail">Master PK: ${m.pk_master.substring(0, 16)}...</div>
                            <div class="badge-detail" style="color: var(--accent-purple);">Weekly PK: ${m.weekly_pk ? m.weekly_pk.substring(0, 16) : '-'}...</div>
                        </div>
                    `;
                }).join('');

                // Update Bootstrap form & Submitter drop-down
                const claimsForm = document.getElementById('bootstrap-claims-form');
                const submitterSelect = document.getElementById('main-submitter');
                
                // Keep selected values
                const prevSubmitter = submitterSelect.value;
                
                let claimsHtml = '';
                let selectHtml = '';
                
                state.roster.forEach(m => {
                    claimsHtml += `
                        <div class="form-group" style="flex-direction: row; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                            <label style="font-weight: bold; width: 120px;">${m.client_id}</label>
                            <select id="claim-${m.client_id}" style="width: 140px;">
                                <option value="0">Subscriber</option>
                                ${Array.from({length: state.L}, (_, i) => `<option value="${i+1}" ${i+1 === m.channel_idx ? 'selected' : ''}>Channel ${i+1}</option>`).join('')}
                            </select>
                        </div>
                    `;
                    if (m.role === 'broadcaster') {
                        selectHtml += `<option value="${m.client_id}" ${m.client_id === prevSubmitter ? 'selected' : ''}>${m.client_id} (Slot ${m.channel_idx})</option>`;
                    }
                });
                claimsForm.innerHTML = claimsHtml;
                submitterSelect.innerHTML = selectHtml || '<option value="">No active broadcasters</option>';

                // Update channel slots
                const slotsView = document.getElementById('channel-slots-view');
                const channelMap = {};
                state.roster.forEach(m => {
                    if (m.channel_idx) channelMap[m.channel_idx] = m;
                });
                
                let slotsHtml = '';
                for (let i = 1; i <= state.L; i++) {
                    const m = channelMap[i];
                    if (m) {
                        slotsHtml += `
                            <div class="slot-card active">
                                <div class="slot-index">Channel ${i}</div>
                                <div class="slot-owner">${m.client_id}</div>
                                <div class="slot-pk">g^α: ${m.weekly_pk.substring(0, 10)}...</div>
                            </div>
                        `;
                    } else {
                        slotsHtml += `
                            <div class="slot-card">
                                <div class="slot-index">Channel ${i}</div>
                                <div class="slot-owner" style="color: var(--text-muted); font-weight: normal;">Unclaimed</div>
                            </div>
                        `;
                    }
                }
                slotsView.innerHTML = slotsHtml;

                // Update Blacklist
                const blacklistView = document.getElementById('blacklist-view');
                if (state.blacklist.length === 0) {
                    blacklistView.innerHTML = '<div>No pseudonyms blacklisted for this week.</div>';
                } else {
                    blacklistView.innerHTML = state.blacklist.map(p_hex => `<div>🚫 Blacklisted: ${p_hex.substring(0, 32)}...</div>`).join('');
                }

                // Update Evidence Store
                const evidenceView = document.getElementById('evidence-view');
                const keys = Object.keys(state.evidence_store);
                if (keys.length === 0) {
                    evidenceView.innerHTML = '<div>No evidence collected yet.</div>';
                } else {
                    evidenceView.innerHTML = keys.map(fp => {
                        const count = state.evidence_store[fp].length;
                        return `
                            <div style="margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem;">
                                <div style="color: var(--accent-cyan); font-weight: bold;">Fingerprint: ${fp.substring(0, 20)}...</div>
                                <div style="font-size: 0.8rem; color: var(--accent-amber);">Reports (count: ${count}):</div>
                                ${state.evidence_store[fp].map(p => `<div style="font-size: 0.75rem; margin-left: 1rem; color: var(--text-muted);">${p.substring(0, 24)}...</div>`).join('')}
                            </div>
                        `;
                    }).join('');
                }

                // Update SIEM Alerts
                const alertsList = document.getElementById('siem-alerts-list');
                if (state.alerts.length === 0) {
                    alertsList.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 2rem;">No alerts emitted. Indicators require T unique reports.</div>';
                } else {
                    alertsList.innerHTML = state.alerts.map(alert => `
                        <div class="alert-item">
                            <div class="alert-header">
                                <span>🚨 SIEM THRESHOLD ALERT: INCIDENT CONFIRMED</span>
                                <span style="background-color: var(--accent-red); color: white; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.75rem;">CRITICAL</span>
                            </div>
                            <div class="alert-meta">
                                <b>Fingerprint:</b> ${alert.fp}<br>
                                <b>Evidence Source Count:</b> ${alert.evidence_count} / ${state.threshold} distinct pseudonyms
                            </div>
                            <div class="alert-body">${JSON.stringify(JSON.parse(alert.stix_bundle), null, 2)}</div>
                        </div>
                    `).join('');
                }

                // Update Protocol Console Ledger
                const protocolConsole = document.getElementById('protocol-console');
                protocolConsole.innerHTML = state.logs.map(log => `
                    <div class="log-item ${log.type}">
                        <span class="log-tag">[${log.stage}]</span>
                        <span>${log.message}</span>
                    </div>
                    ${log.detail ? `<div class="log-detail">${log.detail}</div>` : ''}
                `).join('');
                
                // Scroll console to bottom
                protocolConsole.scrollTop = protocolConsole.scrollHeight;

            } catch (err) {
                console.error("State update error:", err);
            }
        }

        async function initializeSim() {
            const L = parseInt(document.getElementById('param-L').value);
            const threshold = parseInt(document.getElementById('param-threshold').value);
            
            const payload = {
                client_ids: ["Alice", "Bob", "Charlie", "Dave", "Eve"],
                L: L,
                threshold: threshold
            };
            
            const res = await fetch('/api/initialize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            
            // Highlight nodes
            document.getElementById('node-clients').classList.add('active');
            document.getElementById('status-phase').innerText = "Initialized. Run Bootstrap Next.";
            
            updateState();
        }

        async function rotateKeys() {
            const res = await fetch('/api/rotate-keys', { method: 'POST' });
            updateState();
        }

        async function runBootstrap() {
            const claims = {};
            ["Alice", "Bob", "Charlie", "Dave", "Eve"].forEach(name => {
                const selectEl = document.getElementById(`claim-${name}`);
                if (selectEl) {
                    claims[name] = parseInt(selectEl.value);
                }
            });

            const res = await fetch('/api/bootstrap', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ claims: claims })
            });
            
            // Animate pipelines
            document.getElementById('node-serverA').classList.add('active');
            document.getElementById('node-serverB').classList.add('active');
            setTimeout(() => {
                document.getElementById('node-verifier').classList.add('active');
            }, 1000);
            
            updateState();
            
            // Switch to main round tab automatically on success
            setTimeout(() => {
                switchTab('main');
            }, 1500);
        }

        async function submitIoc() {
            const client_id = document.getElementById('main-submitter').value;
            const stix_bundle = document.getElementById('main-stix-bundle').value;

            if (!client_id) {
                alert("Please select a broadcaster client.");
                return;
            }

            const res = await fetch('/api/submit-ioc', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ client_id, stix_bundle })
            });
            const data = await res.json();
            
            // Animate
            const netConn = document.getElementById('net-conn');
            netConn.style.background = 'linear-gradient(90deg, var(--accent-cyan), var(--accent-purple))';
            
            setTimeout(() => {
                document.getElementById('node-siem').classList.add('active');
            }, 1500);

            // Display trace
            const traceView = document.getElementById('main-trace-view');
            
            if (data.status === 'success') {
                const verifiedObj = data.verified_channels.find(c => c.status === 'ok');
                const dupObj = data.verified_channels.find(c => c.status === 'duplicate');
                const failedObj = data.verified_channels.find(c => c.status !== 'ok' && c.status !== 'duplicate');
                
                let traceHtml = `<div style="color: var(--accent-green); font-weight: bold; margin-bottom: 0.5rem;">✅ Submission Processing Complete!</div>`;
                
                // Show audit details
                traceHtml += `<div style="margin-bottom: 0.8rem;"><b>1. Carter-Wegman MAC Audit:</b><br>`;
                data.audit.forEach(a => {
                    const color = a.passed ? 'var(--accent-green)' : 'var(--accent-red)';
                    traceHtml += ` - Client [${a.client_id}]: <span style="color: ${color};">${a.passed ? 'PASSED' : 'FAILED'}</span> (Beta: ${a.beta_sum.substring(0, 16)}...)<br>`;
                });
                traceHtml += `</div>`;
                
                // Show decryptions
                traceHtml += `<div style="margin-bottom: 0.8rem;"><b>2. Verifier Channel Decryptions:</b><br>`;
                data.verified_channels.forEach(ch => {
                    let color = 'var(--text-muted)';
                    if (ch.status === 'ok') color = 'var(--accent-green)';
                    if (ch.status === 'duplicate') color = 'var(--accent-amber)';
                    if (ch.status.includes('fail')) color = 'var(--accent-red)';
                    
                    traceHtml += ` - Channel ${ch.channel_index}: Status = <span style="color: ${color}; font-weight: bold;">${ch.status.toUpperCase()}</span><br>`;
                    if (ch.fp) {
                        traceHtml += `   - Claimed Fingerprint: ${ch.fp.substring(0, 20)}...<br>`;
                        traceHtml += `   - Weekly Pseudonym: ${ch.P.substring(0, 20)}...<br>`;
                    }
                });
                traceHtml += `</div>`;
                
                traceView.innerHTML = traceHtml;
            } else {
                traceView.innerHTML = `<div style="color: var(--accent-red);">Submission failed: ${data.detail}</div>`;
            }

            updateState();
        }

        function loadTemplate(type) {
            const bundleText = document.getElementById('main-stix-bundle');
            if (type === 'ipv4') {
                const randomIp = `198.51.100.${Math.floor(Math.random() * 254) + 1}`;
                bundleText.value = JSON.stringify({
                    "type": "bundle",
                    "id": `bundle--${Math.random().toString(16).slice(2, 6)}-4d2c`,
                    "objects": [
                        {
                            "type": "indicator",
                            "id": `indicator--${Math.random().toString(16).slice(2, 6)}-1d4e`,
                            "pattern": `[ipv4-addr:value = '${randomIp}']`,
                            "pattern_type": "stix",
                            "valid_from": "2026-05-19T00:00:00Z"
                        }
                    ]
                }, null, 2);
            } else if (type === 'hash') {
                const hexChars = '0123456789abcdef';
                let randomHash = '';
                for (let i = 0; i < 64; i++) randomHash += hexChars[Math.floor(Math.random() * 16)];
                bundleText.value = JSON.stringify({
                    "type": "bundle",
                    "id": `bundle--${Math.random().toString(16).slice(2, 6)}-9e8a`,
                    "objects": [
                        {
                            "type": "indicator",
                            "id": `indicator--${Math.random().toString(16).slice(2, 6)}-3f4b`,
                            "pattern": `[file:hashes.'SHA-256' = '${randomHash}']`,
                            "pattern_type": "stix",
                            "valid_from": "2026-05-19T00:00:00Z"
                        }
                    ]
                }, null, 2);
            }
        }

        // TAXII Simulator API testers
        async function testTaxiiGet() {
            const consoleEl = document.getElementById('taxii-console');
            consoleEl.innerHTML += `\n[REQUEST] GET /taxii2/api1/collections/c1a2-3b4c-5d6e/objects/...`;
            
            const res = await fetch('/taxii2/api1/collections/c1a2-3b4c-5d6e/objects/');
            const data = await res.json();
            
            consoleEl.innerHTML += `\n[RESPONSE] Status: 200 OK. Envelope contains ${data.objects.length} STIX items.`;
            consoleEl.innerHTML += `\n${JSON.stringify(data, null, 2)}`;
            consoleEl.scrollTop = consoleEl.scrollHeight;
        }

        async function testTaxiiPost() {
            const consoleEl = document.getElementById('taxii-console');
            const broadcaster = document.getElementById('main-submitter').value;
            
            if (!broadcaster) {
                alert("Please initialize network & run bootstrap first to have active broadcaster.");
                return;
            }
            
            consoleEl.innerHTML += `\n[REQUEST] POST /taxii2/api1/collections/c1a2-3b4c-5d6e/objects/ via client '${broadcaster}'...`;
            
            // Random IP
            const randomIp = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;
            const dummyBundle = {
                "type": "bundle",
                "id": "bundle--taxii-client-post",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--taxii-post-id",
                        "pattern": `[ipv4-addr:value = '${randomIp}']`,
                        "pattern_type": "stix",
                        "valid_from": "2026-05-19T00:00:00Z"
                    }
                ]
            };
            
            const res = await fetch(`/taxii2/api1/collections/c1a2-3b4c-5d6e/objects/?client_id=${broadcaster}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(dummyBundle)
            });
            const data = await res.json();
            
            consoleEl.innerHTML += `\n[RESPONSE] Status: ${res.status}. Data: ${JSON.stringify(data)}`;
            consoleEl.scrollTop = consoleEl.scrollHeight;
            updateState();
        }

        // Initialize state
        updateState();
        setInterval(updateState, 5000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return HTMLResponse(content=HTML_CONTENT)
