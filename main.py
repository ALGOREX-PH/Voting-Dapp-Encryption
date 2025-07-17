from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Dict, List, Any
import json
import base64
import os
from random import randint
from sympy import randprime
import uvicorn
from datetime import datetime

app = FastAPI(title="BGN Encryption API", version="1.0.0")

# Data models
class VoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

class EncryptedVoteData(BaseModel):
    candidateId: List[str]
    timestamp: List[str]
    walletAddress: List[str]
    voteHash: List[str]
    blockNumber: List[str]
    transactionHash: str  # Keep transaction hash unencrypted as identifier

class KeyGenerationRequest(BaseModel):
    bit_length: int = 256

class EncryptionResponse(BaseModel):
    success: bool
    encrypted_data: EncryptedVoteData
    message: str

# BGN Key Generation Functions
def generate_bgn_keys(bit_length=256):
    """Generate BGN public and private keys"""
    # Generate two large distinct primes
    p = randprime(2**bit_length, 2**(bit_length+1))
    q = randprime(2**bit_length, 2**(bit_length+1))
    while q == p:  # Ensure distinct primes
        q = randprime(2**bit_length, 2**(bit_length+1))
    
    n = p * q  # Modulus for encryption
    return ({"n": n}, {"p": p, "q": q})

def serialize_key(key):
    """Serialize key to base64 encoded JSON"""
    return base64.b64encode(json.dumps(key).encode('utf-8'))

def load_public_key(filename):
    """Load public key from file"""
    try:
        with open(filename, 'rb') as f:
            key_data = json.loads(base64.b64decode(f.read()).decode('utf-8'))
            return key_data['n']
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Public key file {filename} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading public key: {str(e)}")

def load_private_key(filename):
    """Load private key from file"""
    try:
        with open(filename, 'rb') as f:
            key_data = json.loads(base64.b64decode(f.read()).decode('utf-8'))
            return key_data['p'], key_data['q']
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Private key file {filename} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading private key: {str(e)}")

def encrypt_value(m, n):
    """BGN-style additive encryption"""
    return m + randint(1, 9999999) * n

def encrypt_string(message, public_key_n):
    """Encrypt a string using BGN encryption"""
    # Convert string to character codes
    char_encoded = [ord(c) for c in message]
    
    encrypted_message = []
    for char_code in char_encoded:
        # Encrypt each character
        letter_encrypted_value = encrypt_value(char_code, public_key_n)
        
        # Convert to bytes and encode as base64
        letter_bytes = letter_encrypted_value.to_bytes(
            (letter_encrypted_value.bit_length() + 7) // 8, 
            byteorder='big'
        )
        letter_encoded = base64.b64encode(letter_bytes)
        letter_encoded_str = letter_encoded.decode('utf-8')
        encrypted_message.append(letter_encoded_str)
    
    return encrypted_message

# API Endpoints
@app.post("/generate-keys")
async def generate_keys(request: KeyGenerationRequest):
    """Generate BGN public and private keys"""
    try:
        # Create keys directory if it doesn't exist
        os.makedirs('bgn_keys', exist_ok=True)
        
        # Generate keys
        public_key, private_key = generate_bgn_keys(request.bit_length)
        
        # Save keys to files
        with open('bgn_keys/bgn_public.pem', 'wb') as f:
            f.write(serialize_key(public_key))
        
        with open('bgn_keys/bgn_private.pem', 'wb') as f:
            f.write(serialize_key(private_key))
        
        # Verify keys
        loaded_public = json.loads(base64.b64decode(serialize_key(public_key)).decode('utf-8'))
        loaded_private = json.loads(base64.b64decode(serialize_key(private_key)).decode('utf-8'))
        assert loaded_public['n'] == loaded_private['p'] * loaded_private['q']
        
        return {
            "success": True,
            "message": "BGN keys generated successfully!",
            "public_key_file": "bgn_keys/bgn_public.pem",
            "private_key_file": "bgn_keys/bgn_private.pem",
            "public_key_n": public_key['n']
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating keys: {str(e)}")

@app.post("/encrypt-vote", response_model=EncryptionResponse)
async def encrypt_vote_data(vote_data: VoteData):
    """Encrypt vote data using BGN encryption"""
    try:
        # Load public key
        public_key_n = load_public_key('bgn_keys/bgn_public.pem')
        
        # Encrypt each field except transactionHash (keep as identifier)
        encrypted_data = EncryptedVoteData(
            candidateId=encrypt_string(vote_data.candidateId, public_key_n),
            timestamp=encrypt_string(vote_data.timestamp, public_key_n),
            walletAddress=encrypt_string(vote_data.walletAddress, public_key_n),
            voteHash=encrypt_string(vote_data.voteHash, public_key_n),
            blockNumber=encrypt_string(vote_data.blockNumber, public_key_n),
            transactionHash=vote_data.transactionHash  # Keep unencrypted
        )
        
        return EncryptionResponse(
            success=True,
            encrypted_data=encrypted_data,
            message="Vote data encrypted successfully!"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error encrypting vote data: {str(e)}")

@app.post("/encrypt-string")
async def encrypt_string_endpoint(data: dict):
    """Encrypt a single string using BGN encryption"""
    try:
        if "message" not in data:
            raise HTTPException(status_code=400, detail="Missing 'message' field")
        
        message = data["message"]
        public_key_n = load_public_key('bgn_keys/bgn_public.pem')
        
        encrypted_message = encrypt_string(message, public_key_n)
        
        return {
            "success": True,
            "original_message": message,
            "encrypted_message": encrypted_message,
            "message_length": len(encrypted_message)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error encrypting string: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "BGN Encryption API",
        "version": "1.0.0",
        "endpoints": {
            "generate_keys": "/generate-keys",
            "encrypt_vote": "/encrypt-vote",
            "encrypt_string": "/encrypt-string"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/key-info")
async def get_key_info():
    """Get information about current keys"""
    try:
        public_key_n = load_public_key('bgn_keys/bgn_public.pem')
        return {
            "public_key_exists": True,
            "public_key_n": public_key_n,
            "key_bit_length": public_key_n.bit_length()
        }
    except Exception as e:
        return {
            "public_key_exists": False,
            "error": str(e)
        }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)