from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import json
import base64
from random import randint
import os

# Initialize FastAPI app
app = FastAPI(title="BGN Vote Encryption API", version="1.0.0")

# Pydantic models for request/response
class VoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

class EncryptedVoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

# BGN Encryption Functions
def encrypt_value(m, n):
    """BGN-style additive encryption"""
    return m + randint(1, 9999999) * n

def load_public_key(filename):
    """Load BGN public key from file"""
    try:
        with open(filename, 'rb') as f:
            key_data = json.loads(base64.b64decode(f.read()).decode('utf-8'))
            return key_data['n']
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Public key file not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading public key: {str(e)}")

def encrypt_string(message: str, public_key_n: int) -> str:
    """Encrypt a string using BGN encryption"""
    # Convert string to character codes
    char_encoded = [ord(c) for c in message]
    
    encrypted_chars = []
    
    # Encrypt each character
    for char_code in char_encoded:
        # Encrypt the character code
        encrypted_value = encrypt_value(char_code, public_key_n)
        
        # Convert to bytes and encode in base64
        encrypted_bytes = encrypted_value.to_bytes(
            (encrypted_value.bit_length() + 7) // 8, 
            byteorder='big'
        )
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
        encrypted_chars.append(encrypted_b64)
    
    # Join all encrypted characters with a delimiter
    return "|".join(encrypted_chars)

def encrypt_vote_data(vote_data: VoteData, public_key_n: int) -> EncryptedVoteData:
    """Encrypt all fields in the vote data"""
    return EncryptedVoteData(
        candidateId=encrypt_string(vote_data.candidateId, public_key_n),
        timestamp=encrypt_string(vote_data.timestamp, public_key_n),
        walletAddress=encrypt_string(vote_data.walletAddress, public_key_n),
        voteHash=encrypt_string(vote_data.voteHash, public_key_n),
        blockNumber=encrypt_string(vote_data.blockNumber, public_key_n),
        transactionHash=encrypt_string(vote_data.transactionHash, public_key_n)
    )

# Load public key on startup
PUBLIC_KEY_PATH = "bgn_keys/bgn_public.pem"
public_key_n = None

@app.on_event("startup")
async def startup_event():
    global public_key_n
    try:
        public_key_n = load_public_key(PUBLIC_KEY_PATH)
        print(f"Public key loaded successfully")
    except Exception as e:
        print(f"Warning: Could not load public key on startup: {e}")

# API Endpoints
@app.get("/")
async def root():
    return {"message": "BGN Vote Encryption API", "status": "running"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "public_key_loaded": public_key_n is not None
    }

@app.post("/encrypt-vote", response_model=EncryptedVoteData)
async def encrypt_vote(vote_data: VoteData):
    """
    Encrypt vote data using BGN encryption
    """
    global public_key_n
    
    # Check if public key is loaded
    if public_key_n is None:
        try:
            public_key_n = load_public_key(PUBLIC_KEY_PATH)
        except Exception as e:
            raise HTTPException(
                status_code=500, 
                detail="Public key not available. Please ensure the key file exists."
            )
    
    try:
        # Encrypt the vote data
        encrypted_data = encrypt_vote_data(vote_data, public_key_n)
        return encrypted_data
    
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Encryption failed: {str(e)}"
        )

@app.post("/encrypt-vote-raw")
async def encrypt_vote_raw(vote_data: VoteData):
    """
    Encrypt vote data and return as raw JSON (for debugging)
    """
    encrypted_data = await encrypt_vote(vote_data)
    return encrypted_data.dict()

# Example usage endpoint
@app.get("/example")
async def get_example():
    """
    Returns an example of the expected input format
    """
    return {
        "example_input": {
            "candidateId": "blazing-titan",
            "timestamp": "2025-07-08T16:13:24.000Z",
            "walletAddress": "0x7D11c7F2594525Af3Bc2ba611A804a1A235c2FF0",
            "voteHash": "0xf20aa3ffa7b47518dbeddcb1f0f0b4c3b9950049ebcafc37d36eccb7573b4405",
            "blockNumber": "0",
            "transactionHash": "0x3a9aa3fb330361635e9106a4b1f83682a7d9e37b9ef5d79e63235fa81ac5be24"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)