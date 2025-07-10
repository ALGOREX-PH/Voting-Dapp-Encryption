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
    publicKey: str  # Base64 encoded JSON public key

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

def decode_public_key(encoded_key: str) -> int:
    """Decode base64 encoded JSON public key"""
    try:
        # Decode base64
        decoded_bytes = base64.b64decode(encoded_key)
        # Parse JSON
        key_data = json.loads(decoded_bytes.decode('utf-8'))
        # Extract 'n' value and convert to int
        return int(key_data['n'])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key format: {str(e)}")

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
    # Decode the public key
    public_key_n = decode_public_key(vote_data.publicKey)
    
    return EncryptedVoteData(
        candidateId=encrypt_string(vote_data.candidateId, public_key_n),
        timestamp=encrypt_string(vote_data.timestamp, public_key_n),
        walletAddress=encrypt_string(vote_data.walletAddress, public_key_n),
        voteHash=encrypt_string(vote_data.voteHash, public_key_n),
        blockNumber=encrypt_string(vote_data.blockNumber, public_key_n),
        transactionHash=encrypt_string(vote_data.transactionHash, public_key_n)
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
            "publicKey": "eyJuIjogIjMxMjEzNTQxMjczNTQ2MjIyOTU2ODgwNDMyNjk0NzYwNDkxMzkyNzgyNjgxODg1MzMwNjM2ODAxNjA2MTA0MzUzMzY5MTEyNTc3MDU1Mjc0Mjg5NDY1NDQ4NDc0ODYxMzU2NzYwNjE4NjYyMTE2OTMzNTc1NDc4NDc1MTE3NTIyNzA3NjQ1NTM3NDU3NjAzNzEwNTcwMTgwNzAxIn0"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)