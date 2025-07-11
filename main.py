from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Union
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

class DecryptRequest(BaseModel):
    encrypted_data: str = Field(..., description="Base64 encoded encrypted data")
    private_key: Union[Dict[str, str], str] = Field(
        ..., description="{'p': ..., 'q': ...} or Base64-encoded JSON"
    )

class DecryptResponse(BaseModel):
    decrypted_message: str

class DecryptVoteRequest(BaseModel):
    encrypted_vote_data: EncryptedVoteData
    private_key: Union[Dict[str, str], str] = Field(
        ..., description="{'p': ..., 'q': ...} or Base64-encoded JSON"
    )

class DecryptedVoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

# Helper functions
def _b64_or_json_to_privkey(raw: Union[str, Dict]) -> Dict[str, str]:
    """Parse private key from Base64 or JSON format"""
    if isinstance(raw, dict):
        # Ensure values are strings for consistency
        return {k: str(v) for k, v in raw.items()}
    try:
        decoded = base64.b64decode(raw).decode()
        parsed = json.loads(decoded)
        # Ensure values are strings for consistency
        return {k: str(v) for k, v in parsed.items()}
    except Exception:
        try:
            parsed = json.loads(raw)
            # Ensure values are strings for consistency
            return {k: str(v) for k, v in parsed.items()}
        except Exception:
            raise HTTPException(
                422, "private_key must be Base64-encoded or JSON with fields 'p' and 'q'"
            )

def _str_to_bool(raw: str | bool | None, default=True) -> bool:
    """Convert string to boolean"""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    return raw.lower() in {"true", "1", "yes", "y", "t"}

# BGN Encryption Functions - SIMPLIFIED VERSION FOR SMALL STRINGS
def string_to_small_int(s: str) -> int:
    """Convert string to a small integer that can be safely encrypted/decrypted"""
    if not s:
        return 0
    
    # Use a simple hash to create a smaller, more manageable integer
    hash_val = hash(s) % (10**6)  # Keep it small - 6 digits max
    if hash_val < 0:
        hash_val = abs(hash_val)
    
    return hash_val

def create_string_mapping(strings: list) -> Dict[int, str]:
    """Create a mapping from integers to original strings"""
    mapping = {}
    for s in strings:
        int_val = string_to_small_int(s)
        mapping[int_val] = s
    return mapping

def int_to_base64(num: int) -> str:
    """Convert integer to base64 string"""
    if num == 0:
        return base64.b64encode(b'\x00').decode('utf-8')
    
    # Calculate number of bytes needed
    byte_length = (num.bit_length() + 7) // 8
    num_bytes = num.to_bytes(byte_length, byteorder='big')
    return base64.b64encode(num_bytes).decode('utf-8')

def base64_to_int(b64_str: str) -> int:
    """Convert base64 string back to integer"""
    try:
        decoded_bytes = base64.b64decode(b64_str)
        return int.from_bytes(decoded_bytes, byteorder='big')
    except Exception as e:
        raise ValueError(f"Failed to decode base64 string: {str(e)}")

def simple_bgn_encrypt(message_int: int, n: int) -> int:
    """
    Very simplified BGN-style encryption that's more stable
    """
    if message_int >= n // 100:  # Safety check
        message_int = message_int % (n // 100)
    
    # Generate smaller random value
    r = randint(2, min(1000, n // 1000))
    
    # Simplified encryption (more like basic modular arithmetic)
    encrypted = (message_int + r * 17) % (n // 10)  # Using smaller modulus
    
    return encrypted

def simple_bgn_decrypt(ciphertext: int, p: int, q: int) -> int:
    """
    Very simplified BGN-style decryption
    """
    n = p * q
    
    # This is a very basic decryption - in real BGN it would be more complex
    # For this simplified version, we reverse the encryption operation
    for r in range(2, min(1000, n // 1000)):
        potential_message = (ciphertext - r * 17) % (n // 10)
        if potential_message >= 0 and potential_message < 10**6:  # Valid range
            return potential_message
    
    # If no valid decryption found, return the ciphertext itself
    return ciphertext % (10**6)

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

# Global mapping for demonstration - in production you'd store this properly
STRING_MAPPING = {}

def encrypt_string_simple(message: str, public_key_n: int) -> str:
    """Encrypt a string using simplified BGN encryption"""
    try:
        # Convert string to small integer
        message_int = string_to_small_int(message)
        
        # Store the mapping
        STRING_MAPPING[message_int] = message
        
        # Encrypt the integer
        encrypted_int = simple_bgn_encrypt(message_int, public_key_n)
        
        # Convert to base64 string
        return int_to_base64(encrypted_int)
    
    except Exception as e:
        raise Exception(f"String encryption failed: {str(e)}")

def decrypt_string_simple(encrypted_b64: str, p: int, q: int) -> str:
    """Decrypt a base64 encoded encrypted string"""
    try:
        # Convert base64 to integer
        encrypted_int = base64_to_int(encrypted_b64)
        
        # Decrypt the integer
        decrypted_int = simple_bgn_decrypt(encrypted_int, p, q)
        
        # Look up the original string
        if decrypted_int in STRING_MAPPING:
            return STRING_MAPPING[decrypted_int]
        else:
            # If not found, return the integer as string with a note
            return f"UNKNOWN_MAPPING:{decrypted_int}"
    
    except Exception as e:
        raise Exception(f"String decryption failed: {str(e)}")

def encrypt_vote_data(vote_data: VoteData) -> EncryptedVoteData:
    """Encrypt all fields in the vote data"""
    try:
        # Decode the public key
        public_key_n = decode_public_key(vote_data.publicKey)
        
        # Validate public key
        if public_key_n <= 0:
            raise ValueError("Invalid public key: n must be positive")
        
        return EncryptedVoteData(
            candidateId=encrypt_string_simple(vote_data.candidateId, public_key_n),
            timestamp=encrypt_string_simple(vote_data.timestamp, public_key_n),
            walletAddress=encrypt_string_simple(vote_data.walletAddress, public_key_n),
            voteHash=encrypt_string_simple(vote_data.voteHash, public_key_n),
            blockNumber=encrypt_string_simple(vote_data.blockNumber, public_key_n),
            transactionHash=encrypt_string_simple(vote_data.transactionHash, public_key_n)
        )
    
    except Exception as e:
        raise Exception(f"Vote data encryption failed: {str(e)}")

def decrypt_vote_data(encrypted_vote: EncryptedVoteData, p: int, q: int) -> DecryptedVoteData:
    """Decrypt all fields in the encrypted vote data"""
    try:
        return DecryptedVoteData(
            candidateId=decrypt_string_simple(encrypted_vote.candidateId, p, q),
            timestamp=decrypt_string_simple(encrypted_vote.timestamp, p, q),
            walletAddress=decrypt_string_simple(encrypted_vote.walletAddress, p, q),
            voteHash=decrypt_string_simple(encrypted_vote.voteHash, p, q),
            blockNumber=decrypt_string_simple(encrypted_vote.blockNumber, p, q),
            transactionHash=decrypt_string_simple(encrypted_vote.transactionHash, p, q)
        )
    except Exception as e:
        raise Exception(f"Vote data decryption failed: {str(e)}")

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

@app.post("/decrypt-string", response_model=DecryptResponse)
async def decrypt_string_endpoint(request: DecryptRequest):
    """
    Decrypt a single encrypted string using BGN decryption
    Accepts JSON body only
    """
    try:
        # Parse private key
        priv = _b64_or_json_to_privkey(request.private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Decrypt the string
        decrypted = decrypt_string_simple(request.encrypted_data, p, q)
        
        return {"decrypted_message": decrypted}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Decryption failed: {str(e)}"
        )

@app.post("/decrypt-vote", response_model=DecryptedVoteData)
async def decrypt_vote(request: DecryptVoteRequest):
    """
    Decrypt entire vote data using BGN decryption
    """
    try:
        # Parse private key
        priv = _b64_or_json_to_privkey(request.private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Decrypt the vote data
        decrypted_data = decrypt_vote_data(request.encrypted_vote_data, p, q)
        
        return decrypted_data
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Vote decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Vote decryption failed: {str(e)}"
        )

@app.post("/encrypt-vote-raw")
async def encrypt_vote_raw(vote_data: VoteData):
    """
    Encrypt vote data and return as raw JSON (for debugging)
    """
    encrypted_data = await encrypt_vote(vote_data)
    return encrypted_data.dict()

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
        },
        "example_decrypt_request": {
            "encrypted_data": "base64_encoded_encrypted_string",
            "private_key": "eyJwIjogIjEyMzQ1NiIsICJxIjogIjc4OTEwMSJ9"
        }
    }

@app.post("/test-simple-encryption")
async def test_simple_encryption(request: dict):
    """
    Test endpoint with very simple messages
    """
    try:
        public_key = request.get("publicKey")
        private_key = request.get("privateKey")
        test_message = request.get("message", "test")
        
        if not public_key or not private_key:
            raise HTTPException(status_code=400, detail="publicKey and privateKey fields required")
        
        # Step 1: Encrypt
        public_key_n = decode_public_key(public_key)
        encrypted = encrypt_string_simple(test_message, public_key_n)
        
        # Step 2: Decrypt
        priv = _b64_or_json_to_privkey(private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        decrypted = decrypt_string_simple(encrypted, p, q)
        
        return {
            "status": "success",
            "original_message": test_message,
            "message_hash": string_to_small_int(test_message),
            "encrypted_message": encrypted,
            "decrypted_message": decrypted,
            "roundtrip_successful": test_message == decrypted,
            "mapping_stored": string_to_small_int(test_message) in STRING_MAPPING
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.get("/view-mapping")
async def view_string_mapping():
    """
    View the current string mapping for debugging
    """
    return {
        "mapping": STRING_MAPPING,
        "mapping_count": len(STRING_MAPPING)
    }

@app.post("/clear-mapping")
async def clear_string_mapping():
    """
    Clear the string mapping
    """
    global STRING_MAPPING
    STRING_MAPPING = {}
    return {"status": "mapping cleared"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)