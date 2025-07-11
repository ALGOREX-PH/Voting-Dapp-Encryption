from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import json
import base64
import hashlib
from random import randint
import os
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI(title="BGN Vote Encryption API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

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
def string_to_int(s: str) -> int:
    """Convert string to integer using hash function for consistent mapping"""
    # Use SHA-256 to convert string to a large integer
    hash_object = hashlib.sha256(s.encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    return int(hex_dig, 16)

def int_to_base64(num: int) -> str:
    """Convert integer to base64 string"""
    if num == 0:
        return base64.b64encode(b'\x00').decode('utf-8')
    
    # Calculate number of bytes needed
    byte_length = (num.bit_length() + 7) // 8
    num_bytes = num.to_bytes(byte_length, byteorder='big')
    return base64.b64encode(num_bytes).decode('utf-8')

def bgn_encrypt(message_int: int, n: int) -> int:
    """
    Simplified BGN-style encryption
    E(m) = g^m * r^n mod n^2
    For simplicity, we'll use a basic implementation
    """
    # Generate random value r
    r = randint(2, n - 1)
    
    # Compute n^2
    n_squared = n * n
    
    # Simplified BGN encryption: (1 + m*n) * r^n mod n^2
    # This is a simplified version - full BGN requires bilinear groups
    encrypted = ((1 + message_int * n) * pow(r, n, n_squared)) % n_squared
    
    return encrypted

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
    try:
        # Convert string to integer
        message_int = string_to_int(message)
        
        # Reduce message size to prevent overflow
        # Take modulo of a smaller number to ensure it fits in our encryption scheme
        max_message_size = public_key_n // 1000  # Arbitrary safety factor
        message_int = message_int % max_message_size
        
        # Encrypt the integer
        encrypted_int = bgn_encrypt(message_int, public_key_n)
        
        # Convert to base64 string
        return int_to_base64(encrypted_int)
    
    except Exception as e:
        raise Exception(f"String encryption failed: {str(e)}")

def encrypt_vote_data(vote_data: VoteData) -> EncryptedVoteData:
    """Encrypt all fields in the vote data"""
    try:
        # Decode the public key
        public_key_n = decode_public_key(vote_data.publicKey)
        
        # Validate public key
        if public_key_n <= 0:
            raise ValueError("Invalid public key: n must be positive")
        
        return EncryptedVoteData(
            candidateId=encrypt_string(vote_data.candidateId, public_key_n),
            timestamp=encrypt_string(vote_data.timestamp, public_key_n),
            walletAddress=encrypt_string(vote_data.walletAddress, public_key_n),
            voteHash=encrypt_string(vote_data.voteHash, public_key_n),
            blockNumber=encrypt_string(vote_data.blockNumber, public_key_n),
            transactionHash=encrypt_string(vote_data.transactionHash, public_key_n)
        )
    
    except Exception as e:
        raise Exception(f"Vote data encryption failed: {str(e)}")

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
        # Debug: log the public key for troubleshooting
        print(f"Received public key: {vote_data.publicKey[:50]}...")
        
        # Decrypt and validate the public key first
        try:
            public_key_n = decode_public_key(vote_data.publicKey)
            print(f"Decoded public key n: {str(public_key_n)[:50]}...")
        except Exception as key_error:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid public key: {str(key_error)}"
            )
        
        # Encrypt the vote data using the provided public key
        encrypted_data = encrypt_vote_data(vote_data)
        return encrypted_data
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Encryption error: {str(e)}")  # Server-side logging
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

@app.post("/test-key")
async def test_key_decoding(request: dict):
    """
    Test endpoint to debug public key decoding
    """
    try:
        public_key = request.get("publicKey")
        if not public_key:
            raise HTTPException(status_code=400, detail="publicKey field required")
        
        # Decode the public key
        public_key_n = decode_public_key(public_key)
        
        return {
            "status": "success",
            "decoded_key": str(public_key_n),
            "key_length": len(str(public_key_n)),
            "key_bit_length": public_key_n.bit_length(),
            "original_key": public_key[:50] + "..." if len(public_key) > 50 else public_key
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.post("/test-encryption")
async def test_encryption(request: dict):
    """
    Test endpoint to debug encryption process
    """
    try:
        public_key = request.get("publicKey")
        test_message = request.get("message", "test")
        
        if not public_key:
            raise HTTPException(status_code=400, detail="publicKey field required")
        
        # Decode the public key
        public_key_n = decode_public_key(public_key)
        
        # Test encryption
        encrypted = encrypt_string(test_message, public_key_n)
        
        return {
            "status": "success",
            "original_message": test_message,
            "encrypted_message": encrypted,
            "public_key_n": str(public_key_n)[:100] + "..." if len(str(public_key_n)) > 100 else str(public_key_n)
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)