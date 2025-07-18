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
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="BGN Encryption API", version="1.0.0")

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

# Data models
class VoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

class VoteDataWithKey(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str
    public_key: str  # BGN public key (base64-encoded JSON)

class EncryptedVoteData(BaseModel):
    candidateId: List[str]
    timestamp: List[str]
    walletAddress: List[str]
    voteHash: List[str]
    blockNumber: List[str]
    transactionHash: str  # Keep transaction hash unencrypted as identifier

class DecryptedVoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str  # This remains unchanged

class DecryptVoteRequest(BaseModel):
    encrypted_data: EncryptedVoteData
    private_key: str  # Base64-encoded JSON private key (contains p and q)

class DecryptVoteResponse(BaseModel):
    success: bool
    decrypted_data: DecryptedVoteData
    message: str

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

def decode_private_key(private_key_base64):
    """Decode base64-encoded JSON private key to get p and q values"""
    try:
        # Decode base64 to get JSON string
        json_string = base64.b64decode(private_key_base64).decode('utf-8')
        # Parse JSON to get the key data
        key_data = json.loads(json_string)
        # Return the p and q values
        return int(key_data['p']), int(key_data['q'])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid private key format: {str(e)}")

def decrypt_encrypted_list(encrypted_list, p, q):
    """
    Decrypt a list of base64-encoded encrypted values
    Each encrypted value is a base64-encoded big-endian integer
    """
    n = p * q
    decrypted_chars = []
    
    for encrypted_b64 in encrypted_list:
        try:
            # Decode base64 to get bytes
            encrypted_bytes = base64.b64decode(encrypted_b64)
            # Convert bytes to integer
            encrypted_int = int.from_bytes(encrypted_bytes, byteorder='big')
            # Decrypt by taking modulo n to get original character code
            decrypted_char_code = encrypted_int % n
            # Convert character code to character
            decrypted_chars.append(chr(decrypted_char_code))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error decrypting value: {str(e)}")
    
    return ''.join(decrypted_chars)

def decode_public_key(public_key_base64):
    """Decode base64-encoded JSON public key to get n value"""
    try:
        # Decode base64 to get JSON string
        json_string = base64.b64decode(public_key_base64).decode('utf-8')
        # Parse JSON to get the key data
        key_data = json.loads(json_string)
        # Return the n value
        return key_data['n']
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key format: {str(e)}")

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

@app.post("/decrypt-vote", response_model=DecryptVoteResponse)
async def decrypt_vote_data(request: DecryptVoteRequest):
    """Decrypt encrypted vote data using BGN decryption with provided private key"""
    try:
        # Decode the base64-encoded private key to get p and q values
        p, q = decode_private_key(request.private_key)
        
        # Decrypt each field
        decrypted_data = DecryptedVoteData(
            candidateId=decrypt_encrypted_list(request.encrypted_data.candidateId, p, q),
            timestamp=decrypt_encrypted_list(request.encrypted_data.timestamp, p, q),
            walletAddress=decrypt_encrypted_list(request.encrypted_data.walletAddress, p, q),
            voteHash=decrypt_encrypted_list(request.encrypted_data.voteHash, p, q),
            blockNumber=decrypt_encrypted_list(request.encrypted_data.blockNumber, p, q),
            transactionHash=request.encrypted_data.transactionHash  # Keep unchanged
        )
        
        return DecryptVoteResponse(
            success=True,
            decrypted_data=decrypted_data,
            message="Vote data decrypted successfully!"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error decrypting vote data: {str(e)}")

@app.post("/decrypt-string-simple")
async def decrypt_string_simple(data: dict):
    """Decrypt a single encrypted string list using BGN decryption with provided private key"""
    try:
        if "encrypted_message" not in data:
            raise HTTPException(status_code=400, detail="Missing 'encrypted_message' field")
        if "private_key" not in data:
            raise HTTPException(status_code=400, detail="Missing 'private_key' field")
        
        encrypted_list = data["encrypted_message"]
        p, q = decode_private_key(data["private_key"])
        
        decrypted_message = decrypt_encrypted_list(encrypted_list, p, q)
        
        return {
            "success": True,
            "decrypted_message": decrypted_message,
            "original_length": len(encrypted_list)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error decrypting string: {str(e)}")

@app.post("/encrypt-vote", response_model=EncryptionResponse)
async def encrypt_vote_data(vote_data: VoteDataWithKey):
    """Encrypt vote data using BGN encryption with provided public key"""
    try:
        # Decode the base64-encoded public key to get n value
        public_key_n = decode_public_key(vote_data.public_key)
        
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

@app.post("/encrypt-vote-from-file", response_model=EncryptionResponse)
async def encrypt_vote_data_from_file(vote_data: VoteData):
    """Encrypt vote data using BGN encryption with key loaded from file"""
    try:
        # Load public key from file
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
    """Encrypt a single string using BGN encryption with provided public key"""
    try:
        if "message" not in data:
            raise HTTPException(status_code=400, detail="Missing 'message' field")
        if "public_key" not in data:
            raise HTTPException(status_code=400, detail="Missing 'public_key' field")
        
        message = data["message"]
        public_key_n = decode_public_key(data["public_key"])
        
        encrypted_message = encrypt_string(message, public_key_n)
        
        return {
            "success": True,
            "original_message": message,
            "encrypted_message": encrypted_message,
            "message_length": len(encrypted_message)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error encrypting string: {str(e)}")

@app.post("/encrypt-string-from-file")
async def encrypt_string_from_file_endpoint(data: dict):
    """Encrypt a single string using BGN encryption with key loaded from file"""
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
            "encrypt_vote": "/encrypt-vote (with public key in request)",
            "decrypt_vote": "/decrypt-vote (with private key in request)",
            "encrypt_vote_from_file": "/encrypt-vote-from-file (loads key from file)",
            "encrypt_string": "/encrypt-string (with public key in request)",
            "decrypt_string_simple": "/decrypt-string-simple (with private key in request)",
            "encrypt_string_from_file": "/encrypt-string-from-file (loads key from file)"
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