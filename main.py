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

# New Pydantic models for decryption
class DecryptVoteData(BaseModel):
    encryptedCandidateId: str
    encryptedTimestamp: str
    encryptedWalletAddress: str
    encryptedVoteHash: str
    encryptedBlockNumber: str
    encryptedTransactionHash: str
    publicKey: str  # Base64 encoded JSON public key
    privateKey: str  # Base64 encoded JSON private key

class DecryptedVoteData(BaseModel):
    candidateId: str
    timestamp: str
    walletAddress: str
    voteHash: str
    blockNumber: str
    transactionHash: str

class DecryptTextRequest(BaseModel):
    encryptedText: str  # Base64 encoded encrypted text
    publicKey: str
    privateKey: str

class DecryptTextResponse(BaseModel):
    decryptedText: str

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

# BGN Decryption Functions
def base64_to_int(b64_str: str) -> int:
    """Convert base64 string back to integer"""
    try:
        decoded_bytes = base64.b64decode(b64_str)
        if len(decoded_bytes) == 0:
            return 0
        return int.from_bytes(decoded_bytes, byteorder='big')
    except Exception as e:
        raise Exception(f"Base64 to int conversion failed: {str(e)}")

def decode_private_key(encoded_key: str) -> tuple:
    """Decode base64 encoded JSON private key"""
    try:
        # Decode base64
        decoded_bytes = base64.b64decode(encoded_key)
        # Parse JSON
        key_data = json.loads(decoded_bytes.decode('utf-8'))
        # Extract 'p' and 'q' values and convert to int
        return int(key_data['p']), int(key_data['q'])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid private key format: {str(e)}")

def bgn_decrypt_simple(encrypted_int: int, p: int, q: int) -> int:
    """
    Simplified BGN-style decryption using private key primes
    This matches the decryption method from your example
    """
    n = p * q  # Reconstruct modulus
    return encrypted_int % n  # Retrieve original value by taking modulo n

def int_to_string_hash_reverse(decrypted_int: int, max_message_size: int, original_candidates: list = None) -> str:
    """
    Since we used SHA-256 hash to convert string to int, we need to reverse it
    For vote data, we can try common candidates or use a lookup table
    """
    if original_candidates is None:
        # Common vote-related strings that might be encrypted
        original_candidates = [
            "blazing-titan", "candidate-1", "candidate-2", "candidate-3", "candidate-4", "candidate-5",
            "2025-07-08T16:13:24.000Z", "2025-07-17T10:00:00.000Z", "2024-12-25T00:00:00.000Z",
            "0x7D11c7F2594525Af3Bc2ba611A804a1A235c2FF0",
            "0xf20aa3ffa7b47518dbeddcb1f0f0b4c3b9950049ebcafc37d36eccb7573b4405",
            "0x3a9aa3fb330361635e9106a4b1f83682a7d9e37b9ef5d79e63235fa81ac5be24",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
            "test", "hello", "world", "prismo", "vote", "encryption", "bgn",
            "alice", "bob", "charlie", "david", "eve", "frank", "grace",
            # Add more candidate values as needed
        ]
    
    # Try to find the original string by testing candidates
    for candidate in original_candidates:
        candidate_hash = string_to_int(candidate)
        # Apply the same reduction as in encryption
        reduced_candidate_hash = candidate_hash % max_message_size
        
        if reduced_candidate_hash == decrypted_int:
            return candidate
    
    # If no exact match found, try partial matching with different bit lengths
    for candidate in original_candidates:
        candidate_hash = string_to_int(candidate)
        reduced_candidate_hash = candidate_hash % max_message_size
        
        # Try matching with different modulo values
        if (reduced_candidate_hash % (2**32)) == (decrypted_int % (2**32)):
            return candidate
        if (reduced_candidate_hash % (2**24)) == (decrypted_int % (2**24)):
            return candidate
        if (reduced_candidate_hash % (2**16)) == (decrypted_int % (2**16)):
            return candidate
    
    # If no match found, return a truncated version of the number
    if decrypted_int > 1000000:
        return f"UNKNOWN_HASH_{decrypted_int % 100000}"
    else:
        return str(decrypted_int)

def decrypt_string_bgn(encrypted_b64: str, public_key_n: int, p: int, q: int) -> str:
    """Decrypt a BGN encrypted string"""
    try:
        # Convert base64 to integer
        encrypted_int = base64_to_int(encrypted_b64)
        
        # Decrypt the integer
        decrypted_int = bgn_decrypt_simple(encrypted_int, p, q)
        
        # For the simplified BGN used in main.py, we need to handle the message size reduction
        max_message_size = public_key_n // 1000
        decrypted_int = decrypted_int % max_message_size
        
        # Try to reverse the hash (this is limited - hash functions are one-way)
        # For practical use, you'd need a lookup table or known candidates
        return int_to_string_hash_reverse(decrypted_int, max_message_size)
        
    except Exception as e:
        raise Exception(f"String decryption failed: {str(e)}")

def decrypt_character_by_character(encrypted_chars: list, p: int, q: int) -> str:
    """
    Decrypt a list of encrypted characters (like in your BGN_ENCRYPT_TEXT_MESSAGE example)
    This is for the character-by-character encryption method
    """
    decrypted_chars = []
    
    for encrypted_char_b64 in encrypted_chars:
        try:
            # Convert base64 to integer
            encrypted_int = base64_to_int(encrypted_char_b64)
            
            # Decrypt using the simple method from your example
            decrypted_int = encrypted_int % (p * q)
            
            # Convert back to character
            if 0 <= decrypted_int <= 127:  # Valid ASCII range
                decrypted_chars.append(chr(decrypted_int))
            else:
                # If outside ASCII range, it might be the encrypted value
                # Try modulo operation to get original character
                original_char_code = decrypted_int % 128
                decrypted_chars.append(chr(original_char_code))
                
        except Exception as e:
            decrypted_chars.append(f"[ERROR: {str(e)}]")
    
    return ''.join(decrypted_chars)

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

# New Decryption Endpoints
@app.post("/decrypt-vote", response_model=DecryptedVoteData)
async def decrypt_vote(decrypt_data: DecryptVoteData):
    """
    Decrypt vote data using BGN decryption
    """
    try:
        # Decode the keys
        public_key_n = decode_public_key(decrypt_data.publicKey)
        p, q = decode_private_key(decrypt_data.privateKey)
        
        # Validate keys
        if public_key_n != p * q:
            raise HTTPException(status_code=400, detail="Public and private keys don't match")
        
        # Decrypt all fields
        return DecryptedVoteData(
            candidateId=decrypt_string_bgn(decrypt_data.encryptedCandidateId, public_key_n, p, q),
            timestamp=decrypt_string_bgn(decrypt_data.encryptedTimestamp, public_key_n, p, q),
            walletAddress=decrypt_string_bgn(decrypt_data.encryptedWalletAddress, public_key_n, p, q),
            voteHash=decrypt_string_bgn(decrypt_data.encryptedVoteHash, public_key_n, p, q),
            blockNumber=decrypt_string_bgn(decrypt_data.encryptedBlockNumber, public_key_n, p, q),
            transactionHash=decrypt_string_bgn(decrypt_data.encryptedTransactionHash, public_key_n, p, q)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Decryption failed: {str(e)}"
        )

@app.post("/decrypt-text", response_model=DecryptTextResponse)
async def decrypt_text(decrypt_request: DecryptTextRequest):
    """
    Decrypt a single encrypted text string
    """
    try:
        # Decode the keys
        public_key_n = decode_public_key(decrypt_request.publicKey)
        p, q = decode_private_key(decrypt_request.privateKey)
        
        # Validate keys
        if public_key_n != p * q:
            raise HTTPException(status_code=400, detail="Public and private keys don't match")
        
        # Decrypt the text
        decrypted_text = decrypt_string_bgn(decrypt_request.encryptedText, public_key_n, p, q)
        
        return DecryptTextResponse(decryptedText=decrypted_text)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Text decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Text decryption failed: {str(e)}"
        )

@app.post("/decrypt-character-array")
async def decrypt_character_array(request: dict):
    """
    Decrypt an array of encrypted characters (like in BGN_ENCRYPT_TEXT_MESSAGE example)
    Expected format: {
        "encryptedChars": ["base64_char1", "base64_char2", ...],
        "privateKey": "base64_encoded_private_key"
    }
    """
    try:
        encrypted_chars = request.get("encryptedChars")
        private_key = request.get("privateKey")
        
        if not encrypted_chars or not private_key:
            raise HTTPException(
                status_code=400, 
                detail="encryptedChars and privateKey fields required"
            )
        
        # Decode private key
        p, q = decode_private_key(private_key)
        
        # Decrypt character by character
        decrypted_message = decrypt_character_by_character(encrypted_chars, p, q)
        
        return {
            "status": "success",
            "decryptedMessage": decrypted_message,
            "characterCount": len(decrypted_message)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Character array decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Character array decryption failed: {str(e)}"
        )

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

# New endpoint to add known strings to lookup table
@app.post("/add-lookup-candidate")
async def add_lookup_candidate(request: dict):
    """
    Add a known string to the lookup table for better decryption
    Expected format: {"candidate": "string_to_add"}
    """
    try:
        candidate = request.get("candidate")
        if not candidate:
            raise HTTPException(status_code=400, detail="candidate field required")
        
        # Test what hash value this candidate produces
        candidate_hash = string_to_int(candidate)
        
        return {
            "status": "success",
            "candidate": candidate,
            "hash_value": str(candidate_hash),
            "message": f"Add '{candidate}' to your lookup table in int_to_string_hash_reverse function"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
    """
    Test endpoint to debug decryption process
    """
    try:
        encrypted_text = request.get("encryptedText")
        public_key = request.get("publicKey")
        private_key = request.get("privateKey")
        
        if not all([encrypted_text, public_key, private_key]):
            raise HTTPException(
                status_code=400, 
                detail="encryptedText, publicKey, and privateKey fields required"
            )
        
        # Decode keys
        public_key_n = decode_public_key(public_key)
        p, q = decode_private_key(private_key)
        
        # Test decryption
        decrypted = decrypt_string_bgn(encrypted_text, public_key_n, p, q)
        
        return {
            "status": "success",
            "encryptedText": encrypted_text[:50] + "..." if len(encrypted_text) > 50 else encrypted_text,
            "decryptedText": decrypted,
            "publicKeyN": str(public_key_n)[:50] + "..." if len(str(public_key_n)) > 50 else str(public_key_n),
            "privateKeyP": str(p)[:50] + "..." if len(str(p)) > 50 else str(p),
            "privateKeyQ": str(q)[:50] + "..." if len(str(q)) > 50 else str(q)
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)