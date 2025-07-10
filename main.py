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
    publicKey: int  # Public key passed with each request

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

def encrypt_vote_data(vote_data: VoteData) -> EncryptedVoteData:
    """Encrypt all fields in the vote data"""
    return EncryptedVoteData(
        candidateId=encrypt_string(vote_data.candidateId, vote_data.publicKey),
        timestamp=encrypt_string(vote_data.timestamp, vote_data.publicKey),
        walletAddress=encrypt_string(vote_data.walletAddress, vote_data.publicKey),
        voteHash=encrypt_string(vote_data.voteHash, vote_data.publicKey),
        blockNumber=encrypt_string(vote_data.blockNumber, vote_data.publicKey),
        transactionHash=encrypt_string(vote_data.transactionHash, vote_data.publicKey)
    )

# API Endpoints
@app.get("/")
async def root():
    return {"message": "BGN Vote Encryption API", "status": "running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/encrypt-vote", response_model=EncryptedVoteData)
async def encrypt_vote(vote_data: VoteData):
    """
    Encrypt vote data using BGN encryption
    """
    try:
        # Encrypt the vote data using the provided public key
        encrypted_data = encrypt_vote_data(vote_data)
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
            "transactionHash": "0x3a9aa3fb330361635e9106a4b1f83682a7d9e37b9ef5d79e63235fa81ac5be24",
            "publicKey": 123456789  # Example public key value
        }
    }

# For local development
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)