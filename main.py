
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

# Your actual encryption/decryption functions (matching your system)
def decrypt_value(encrypted_int: int, p: int, q: int) -> int:
    """
    This should match your actual decrypt_value function
    Since I don't have your exact implementation, I'll create a compatible one
    """
    n = p * q
    
    # This is a placeholder - you should replace this with your actual decryption logic
    # For now, using a simple modular arithmetic approach
    try:
        # Basic decryption approach (you may need to adjust this)
        decrypted = encrypted_int % n
        return decrypted
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_value(value_int: int, public_key_n: int) -> int:
    """
    This should match your actual encrypt_value function
    Placeholder implementation - replace with your actual encryption logic
    """
    try:
        # Basic encryption approach (you may need to adjust this)
        # Generate random component
        r = randint(1, 1000)
        encrypted = (value_int + r) % public_key_n
        return encrypted
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def string_to_int_hash(s: str) -> int:
    """Convert string to integer using hash (for consistent mapping)"""
    # Use a hash function to convert string to integer
    hash_val = hash(s)
    # Ensure positive value
    if hash_val < 0:
        hash_val = abs(hash_val)
    return hash_val

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

def encrypt_string_compatible(message: str, public_key_n: int) -> str:
    """Encrypt a string in a way compatible with your system"""
    try:
        # Convert string to integer
        message_int = string_to_int_hash(message)
        
        # Reduce to safe size
        safe_int = message_int % (public_key_n // 1000)
        
        # Encrypt the integer
        encrypted_int = encrypt_value(safe_int, public_key_n)
        
        # Convert to base64 string (matching your format)
        encrypted_bytes = str(encrypted_int).encode('utf-8')
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    except Exception as e:
        raise Exception(f"String encryption failed: {str(e)}")

def decrypt_string_compatible(encrypted_b64: str, p: int, q: int) -> str:
    """Decrypt a string in a way compatible with your system"""
    try:
        # Decode base64 to get the integer (matching your process)
        encrypted_int = int(base64.b64decode(encrypted_b64).decode())
        
        # Decrypt using your decrypt_value function
        decrypted_int = decrypt_value(encrypted_int, p, q)
        
        # Return the integer as string (since reversing hash is not feasible)
        return str(decrypted_int)
    
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
            candidateId=encrypt_string_compatible(vote_data.candidateId, public_key_n),
            timestamp=encrypt_string_compatible(vote_data.timestamp, public_key_n),
            walletAddress=encrypt_string_compatible(vote_data.walletAddress, public_key_n),
            voteHash=encrypt_string_compatible(vote_data.voteHash, public_key_n),
            blockNumber=encrypt_string_compatible(vote_data.blockNumber, public_key_n),
            transactionHash=encrypt_string_compatible(vote_data.transactionHash, public_key_n)
        )
    
    except Exception as e:
        raise Exception(f"Vote data encryption failed: {str(e)}")

def decrypt_vote_data(encrypted_vote: EncryptedVoteData, p: int, q: int) -> DecryptedVoteData:
    """Decrypt all fields in the encrypted vote data"""
    try:
        return DecryptedVoteData(
            candidateId=decrypt_string_compatible(encrypted_vote.candidateId, p, q),
            timestamp=decrypt_string_compatible(encrypted_vote.timestamp, p, q),
            walletAddress=decrypt_string_compatible(encrypted_vote.walletAddress, p, q),
            voteHash=decrypt_string_compatible(encrypted_vote.voteHash, p, q),
            blockNumber=decrypt_string_compatible(encrypted_vote.blockNumber, p, q),
            transactionHash=decrypt_string_compatible(encrypted_vote.transactionHash, p, q)
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
    Encrypt vote data using compatible encryption
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
    Decrypt a single encrypted string using compatible decryption
    Matches your process: encrypted_salary = int(base64.b64decode(value).decode())
    """
    try:
        # Parse private key
        priv = _b64_or_json_to_privkey(request.private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Decrypt the string using compatible method
        decrypted = decrypt_string_compatible(request.encrypted_data, p, q)
        
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
    Decrypt entire vote data using compatible decryption
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

@app.post("/test-decrypt-raw")
async def test_decrypt_raw(request: dict):
    """
    Test endpoint that matches your exact decryption process
    """
    try:
        encrypted_data = request.get("encrypted_data")
        private_key = request.get("private_key")
        
        if not encrypted_data or not private_key:
            raise HTTPException(status_code=400, detail="encrypted_data and private_key required")
        
        # Parse private key
        priv = _b64_or_json_to_privkey(private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Follow your exact process:
        # encrypted_salary = int(base64.b64decode(ws[f'G{row}'].value).decode())
        encrypted_int = int(base64.b64decode(encrypted_data).decode())
        
        # decrypted_salary_cents = decrypt_value(encrypted_salary, p, q)
        decrypted_int = decrypt_value(encrypted_int, p, q)
        
        return {
            "status": "success",
            "encrypted_data": encrypted_data,
            "encrypted_int": encrypted_int,
            "decrypted_int": decrypted_int,
            "decrypted_message": str(decrypted_int)
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.post("/test-simple-decrypt")
async def test_simple_decrypt(request: dict):
    """
    Very basic test to see if we can decrypt your data
    """
    try:
        encrypted_data = request.get("encrypted_data")
        private_key = request.get("private_key")
        
        # Parse private key
        priv = _b64_or_json_to_privkey(private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Try to decode the base64 first
        try:
            decoded = base64.b64decode(encrypted_data).decode()
            print(f"Decoded string: {decoded}")
            
            # Try to convert to int
            encrypted_int = int(decoded)
            print(f"Encrypted int: {encrypted_int}")
            
            # Try simple decryption
            result = encrypted_int % (p * q)
            
            return {
                "status": "success",
                "decoded_string": decoded,
                "encrypted_int": encrypted_int,
                "simple_result": result,
                "p": str(p)[:20] + "...",
                "q": str(q)[:20] + "..."
            }
        except Exception as decode_error:
            return {
                "status": "decode_error",
                "error": str(decode_error),
                "encrypted_data_length": len(encrypted_data)
            }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)