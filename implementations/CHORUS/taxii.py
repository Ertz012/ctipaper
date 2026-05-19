import json
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
from chorus_protocol import CHORUSClient, CHORUSVerifier
from chorus_core import INF

# FastAPI router for TAXII 2.1 compatibility
taxii_router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1"])

class TaxiiDiscovery(BaseModel):
    title: str
    description: str
    contact: str
    default: str
    api_roots: List[str]

class ApiRoot(BaseModel):
    title: str
    description: str
    versions: List[str]
    max_content_length: int

class Collection(BaseModel):
    id: str
    title: str
    description: Optional[str]
    can_read: bool
    can_write: bool
    media_types: List[str]

class CollectionsResponse(BaseModel):
    collections: List[Collection]

# In-memory storage or pointer to simulation nodes
class TAXIISystem:
    def __init__(self, clients: List[CHORUSClient], verifier: CHORUSVerifier, servers: list, L: int, week: int):
        self.clients = {c.member_id: c for c in clients}
        self.verifier = verifier
        self.servers = servers
        self.L = L
        self.week = week
        
        # Collection config
        self.collections = [
            Collection(
                id="c1a2-3b4c-5d6e",
                title="ISAC Shared Malware Indicators",
                description="Community shared malware indicators via CHORUS anonymous channel",
                can_read=True,
                can_write=True,
                media_types=["application/stix+json;version=2.1"]
            )
        ]

# Global reference populated by simulation startup
taxii_system: Optional[TAXIISystem] = None

@taxii_router.get("/", response_model=TaxiiDiscovery)
async def discovery():
    return TaxiiDiscovery(
        title="CHORUS TAXII 2.1 Server",
        description="Anonymous CTI Exchange Bulletin Board compliant with TAXII 2.1",
        contact="isac-admin@chorus.org",
        default="http://localhost:8000/taxii2/api1/",
        api_roots=["http://localhost:8000/taxii2/api1/"]
    )

@taxii_router.get("/api1/", response_model=ApiRoot)
async def api_root():
    return ApiRoot(
        title="CHORUS Anonymous API Root",
        description="Core API root for the CHORUS network",
        versions=["taxii-2.1"],
        max_content_length=10485760
    )

@taxii_router.get("/api1/collections", response_model=CollectionsResponse)
async def list_collections():
    if not taxii_system:
        raise HTTPException(status_code=500, detail="TAXII system not initialized")
    return CollectionsResponse(collections=taxii_system.collections)

@taxii_router.get("/api1/collections/{collection_id}/")
async def get_collection(collection_id: str):
    if not taxii_system:
        raise HTTPException(status_code=500, detail="TAXII system not initialized")
    for col in taxii_system.collections:
        if col.id == collection_id:
            return col
    raise HTTPException(status_code=404, detail="Collection not found")

@taxii_router.post("/api1/collections/{collection_id}/objects/")
async def add_objects(collection_id: str, request: Request, client_id: str = "alice"):
    """
    Client-side TAXII POST Write Adapter.
    Intercepts local TAXII POSTs, runs the CHORUS Main Round submission protocol,
    and returns a success response.
    """
    if not taxii_system:
        raise HTTPException(status_code=500, detail="TAXII system not initialized")
        
    client = taxii_system.clients.get(client_id)
    if not client:
        raise HTTPException(status_code=400, detail=f"Client '{client_id}' not found in local system")
        
    if client.role != "broadcaster" or client.channel_idx is None:
        raise HTTPException(
            status_code=400, 
            detail=f"Client '{client_id}' is not registered as an active broadcaster. Please run bootstrap first."
        )
        
    try:
        body = await request.json()
        stix_bundle_str = json.dumps(body)
        
        # Submit to servers S_A and S_B
        server_A, server_B = taxii_system.servers
        seed_entropy = b"taxii-round-entropy"
        
        # Trigger CHORUS protocol submission
        sub_A, sub_B = client.generate_main_submission(
            stix_bundle_str, 
            taxii_system.L, 
            taxii_system.week, 
            seed_entropy,
            collection_id=collection_id
        )
        
        # In a real environment, these go over HTTP. Here we process them synchronously in the mock server.
        # Store submissions for the current round
        if not hasattr(server_A, 'pending_submissions'):
            server_A.pending_submissions = []
        if not hasattr(server_B, 'pending_submissions'):
            server_B.pending_submissions = []
            
        server_A.pending_submissions.append(sub_A)
        server_B.pending_submissions.append(sub_B)
        
        # We also trigger cover traffic from other subscribers to keep it anonymous
        for c_id, other_client in taxii_system.clients.items():
            if c_id == client_id:
                continue
            cov_A, cov_B = other_client.generate_main_submission(
                "", 
                taxii_system.L, 
                taxii_system.week, 
                seed_entropy,
                collection_id=collection_id
            )
            server_A.pending_submissions.append(cov_A)
            server_B.pending_submissions.append(cov_B)
            
        # Process the round immediately in the TAXII simulator
        agg_A, betas_A = server_A.process_main(server_A.pending_submissions, seed_entropy)
        agg_B, betas_B = server_B.process_main(server_B.pending_submissions, seed_entropy)
        
        # Check betas for audit verification
        # beta_A + beta_B should equal INF (identity)
        audit_failed = False
        for idx in range(len(betas_A)):
            if betas_A[idx] + betas_B[idx] != INF:
                audit_failed = True
                break
        
        # Clear pending
        server_A.pending_submissions = []
        server_B.pending_submissions = []
        
        if audit_failed:
            raise HTTPException(status_code=400, detail="Carter-Wegman MAC audit failed for submission.")
            
        # Run Verifier
        verified = taxii_system.verifier.verify_round(agg_A, agg_B, taxii_system.week, collection_id)
        
        # Save verified objects to a local cache in the gateway
        if not hasattr(taxii_system, 'verified_objects'):
            taxii_system.verified_objects = []
            
        for item in verified:
            if item['status'] == "ok":
                # Decode and insert into TAXII collection
                stix_obj = json.loads(item['stix_bundle'])
                taxii_system.verified_objects.append(stix_obj)
                
        return {
            "status": "success",
            "message": "STIX objects accepted anonymously through CHORUS channel",
            "fingerprint": verified[0]['fp'] if verified else None
        }
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@taxii_router.get("/api1/collections/{collection_id}/objects/")
async def get_objects(collection_id: str):
    """
    Server-side TAXII Read Gateway.
    Fetches the verified STIX objects from the aggregated database.
    """
    if not taxii_system:
        raise HTTPException(status_code=500, detail="TAXII system not initialized")
        
    # Check collection existence
    found = False
    for col in taxii_system.collections:
        if col.id == collection_id:
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail="Collection not found")
        
    objects = getattr(taxii_system, 'verified_objects', [])
    
    return {
        "more": False,
        "objects": objects
    }
