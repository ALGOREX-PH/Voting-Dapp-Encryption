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

# BGN Encryption Functions - SAFER VERSION
def string_to_int_safe(s: str) -> int:
    """Convert string to integer using a safer method"""
    if not s:
        return 0
    # First encode to base64 to ensure we can reverse it safely
    b64_encoded = base64.b64encode(s.encode('utf-8')).decode('ascii')
    # Then convert the base64 string to int
    bytes_data = b64_encoded.encode('ascii')
    return int.from_bytes(bytes_data, byteorder='big')

def int_to_string_safe(num: int) -> str:
    """Convert integer back to original string safely"""
    if num == 0:
        return ""
    try:
        # Convert int back to bytes
        byte_length = (num.bit_length() + 7) // 8
        bytes_data = num.to_bytes(byte_length, byteorder='big')
        
        # Convert bytes to ASCII string (this should be base64)
        ascii_str = bytes_data.decode('ascii')
        
        # Decode the base64 to get original string
        return base64.b64decode(ascii_str).decode('utf-8')
    except Exception as e:
        # If we can't decode properly, return an error message instead of crashing
        return f"[DECRYPTION_ERROR: {str(e)}]"

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

def bgn_decrypt(ciphertext: int, p: int, q: int) -> int:
    """
    Simplified BGN-style decryption
    This is a basic implementation for the simplified encryption above
    """
    n = p * q
    n_squared = n * n
    
    # For our simplified BGN: c = (1 + m*n) * r^n mod n^2
    # To decrypt: m = ((c mod n^2) - 1) / n mod n
    try:
        # Compute (c - 1) / n mod n
        # This works for our simplified scheme
        temp = (ciphertext - 1) % n_squared
        if temp % n != 0:
            # Try alternative decryption method
            # Use modular inverse approach
            temp = pow(ciphertext, 1, n_squared)
            message_int = ((temp - 1) // n) % n
        else:
            message_int = (temp // n) % n
        
        return message_int
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

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
    """Encrypt a string using BGN encryption with safe encoding"""
    try:
        # Convert string to integer using safe method
        message_int = string_to_int_safe(message)
        
        # Check if the message integer is too large for the encryption scheme
        # Use a much more aggressive reduction for safety
        max_safe_size = min(public_key_n // 100000, 2**200)  # Very conservative
        
        if message_int >= max_safe_size:
            # Use modulo to reduce the size instead of throwing an error
            message_int = message_int % max_safe_size
            print(f"Warning: Message reduced from {len(str(message_int))} to {len(str(message_int % max_safe_size))} digits")
        
        # Encrypt the integer
        encrypted_int = bgn_encrypt(message_int, public_key_n)
        
        # Convert to base64 string
        return int_to_base64(encrypted_int)
    
    except Exception as e:
        raise Exception(f"String encryption failed: {str(e)}")

def decrypt_string(encrypted_b64: str, p: int, q: int) -> str:
    """Decrypt a base64 encoded encrypted string back to original string"""
    try:
        # Convert base64 to integer
        encrypted_int = base64_to_int(encrypted_b64)
        
        # Decrypt the integer
        decrypted_int = bgn_decrypt(encrypted_int, p, q)
        
        # Convert integer back to original string using safe method
        return int_to_string_safe(decrypted_int)
    
    except Exception as e:
        raise Exception(f"String decryption failed: {str(e)}")

def encrypt_string_chunked(message: str, public_key_n: int) -> str:
    """Encrypt a string by chunking it into smaller pieces if needed"""
    try:
        # For very long strings, split them into chunks
        chunk_size = 8  # Process 8 characters at a time
        if len(message) <= chunk_size:
            return encrypt_string(message, public_key_n)
        
        # Split into chunks and encrypt each
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        encrypted_chunks = []
        
        for chunk in chunks:
            encrypted_chunk = encrypt_string(chunk, public_key_n)
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine encrypted chunks with a separator
        return "|".join(encrypted_chunks)
    
    except Exception as e:
        raise Exception(f"Chunked string encryption failed: {str(e)}")

def decrypt_string_chunked(encrypted_b64: str, p: int, q: int) -> str:
    """Decrypt a chunked encrypted string"""
    try:
        # Check if this is a chunked message (contains separators)
        if "|" in encrypted_b64:
            # Split and decrypt each chunk
            chunks = encrypted_b64.split("|")
            decrypted_chunks = []
            
            for chunk in chunks:
                decrypted_chunk = decrypt_string(chunk, p, q)
                decrypted_chunks.append(decrypted_chunk)
            
            return "".join(decrypted_chunks)
        else:
            # Single chunk, decrypt normally
            return decrypt_string(encrypted_b64, p, q)
    
    except Exception as e:
        raise Exception(f"Chunked string decryption failed: {str(e)}")

def encrypt_vote_data(vote_data: VoteData) -> EncryptedVoteData:
    """Encrypt all fields in the vote data using chunked encryption"""
    try:
        # Decode the public key
        public_key_n = decode_public_key(vote_data.publicKey)
        
        # Validate public key
        if public_key_n <= 0:
            raise ValueError("Invalid public key: n must be positive")
        
        return EncryptedVoteData(
            candidateId=encrypt_string_chunked(vote_data.candidateId, public_key_n),
            timestamp=encrypt_string_chunked(vote_data.timestamp, public_key_n),
            walletAddress=encrypt_string_chunked(vote_data.walletAddress, public_key_n),
            voteHash=encrypt_string_chunked(vote_data.voteHash, public_key_n),
            blockNumber=encrypt_string_chunked(vote_data.blockNumber, public_key_n),
            transactionHash=encrypt_string_chunked(vote_data.transactionHash, public_key_n)
        )
    
    except Exception as e:
        raise Exception(f"Vote data encryption failed: {str(e)}")

def decrypt_vote_data(encrypted_vote: EncryptedVoteData, p: int, q: int) -> DecryptedVoteData:
    """Decrypt all fields in the encrypted vote data using chunked decryption"""
    try:
        return DecryptedVoteData(
            candidateId=decrypt_string_chunked(encrypted_vote.candidateId, p, q),
            timestamp=decrypt_string_chunked(encrypted_vote.timestamp, p, q),
            walletAddress=decrypt_string_chunked(encrypted_vote.walletAddress, p, q),
            voteHash=decrypt_string_chunked(encrypted_vote.voteHash, p, q),
            blockNumber=decrypt_string_chunked(encrypted_vote.blockNumber, p, q),
            transactionHash=decrypt_string_chunked(encrypted_vote.transactionHash, p, q)
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
        
        # Decrypt the string using chunked method
        decrypted = decrypt_string_chunked(request.encrypted_data, p, q)
        
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
        },
        "example_decrypt_request": {
            "encrypted_data": "base64_encoded_encrypted_string",
            "private_key": "eyJwIjogIjEyMzQ1NiIsICJxIjogIjc4OTEwMSJ9"
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

@app.post("/test-private-key")
async def test_private_key_decoding(request: dict):
    """
    Test endpoint to debug private key decoding
    """
    try:
        private_key = request.get("privateKey")
        if not private_key:
            raise HTTPException(status_code=400, detail="privateKey field required")
        
        # Decode the private key using the helper function
        priv = _b64_or_json_to_privkey(private_key)
        
        return {
            "status": "success",
            "decoded_p": str(priv["p"])[:50] + "..." if len(str(priv["p"])) > 50 else str(priv["p"]),
            "decoded_q": str(priv["q"])[:50] + "..." if len(str(priv["q"])) > 50 else str(priv["q"]),
            "p_length": len(str(priv["p"])),
            "q_length": len(str(priv["q"])),
            "original_key": private_key[:50] + "..." if len(private_key) > 50 else private_key
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

@app.post("/test-decryption")
async def test_decryption(request: dict):
    """
    Test endpoint to debug decryption process
    """
    try:
        encrypted_data = request.get("encrypted_data")
        private_key = request.get("private_key")
        
        if not encrypted_data or not private_key:
            raise HTTPException(status_code=400, detail="encrypted_data and private_key fields required")
        
        # Parse private key
        priv = _b64_or_json_to_privkey(private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Test decryption
        decrypted = decrypt_string(encrypted_data, p, q)
        
        return {
            "status": "success",
            "encrypted_data": encrypted_data,
            "decrypted_message": decrypted,
            "private_key_p": str(p)[:50] + "..." if len(str(p)) > 50 else str(p),
            "private_key_q": str(q)[:50] + "..." if len(str(q)) > 50 else str(q)
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.post("/test-roundtrip")
async def test_roundtrip_encryption(request: dict):
    """
    Test endpoint to encrypt and then decrypt a message to verify it works
    """
    try:
        public_key = request.get("publicKey")
        private_key = request.get("privateKey")
        test_message = request.get("message", "Hello!")  # Shorter default message
        
        if not public_key or not private_key:
            raise HTTPException(status_code=400, detail="publicKey and privateKey fields required")
        
        # Step 1: Encrypt
        public_key_n = decode_public_key(public_key)
        encrypted = encrypt_string(test_message, public_key_n)
        
        # Step 2: Decrypt
        priv = _b64_or_json_to_privkey(private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        decrypted = decrypt_string(encrypted, p, q)
        
        return {
            "status": "success",
            "original_message": test_message,
            "encrypted_message": encrypted,
            "decrypted_message": decrypted,
            "roundtrip_successful": test_message == decrypted
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

# Your actual decryption function (compatible with your system)
def decrypt_value(encrypted_int: int, p: int, q: int) -> int:
    """
    Compatible decrypt_value function matching your system
    Replace this with your actual decryption logic
    """
    n = p * q
    
    # This is a basic implementation - adjust based on your actual decrypt_value function
    try:
        # Simple modular arithmetic decryption (adjust as needed)
        decrypted = encrypted_int % n
        return decrypted
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def decrypt_string_compatible(encrypted_b64: str, p: int, q: int) -> str:
    """
    Decrypt using your exact process:
    encrypted_salary = int(base64.b64decode(value).decode())
    decrypted_salary_cents = decrypt_value(encrypted_salary, p, q)
    """
    try:
        # Follow your exact process
        encrypted_int = int(base64.b64decode(encrypted_b64).decode())
        decrypted_int = decrypt_value(encrypted_int, p, q)
        return str(decrypted_int)
    except Exception as e:
        raise Exception(f"Compatible decryption failed: {str(e)}")

@app.post("/decrypt-string-compatible", response_model=DecryptResponse)
async def decrypt_string_compatible_endpoint(request: DecryptRequest):
    """
    Decrypt using your exact system process
    """
    try:
        # Parse private key
        priv = _b64_or_json_to_privkey(request.private_key)
        p = int(priv["p"])
        q = int(priv["q"])
        
        # Decrypt using your exact process
        decrypted = decrypt_string_compatible(request.encrypted_data, p, q)
        
        return {"decrypted_message": decrypted}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Compatible decryption error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Compatible decryption failed: {str(e)}"
        )

@app.post("/test-your-process")
async def test_your_exact_process(request: dict):
    """
    Test endpoint that exactly follows your decryption process
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
        
        # Step 1: Your exact process
        # encrypted_salary = int(base64.b64decode(ws[f'G{row}'].value).decode())
        try:
            encrypted_int = int(base64.b64decode(encrypted_data).decode())
            print(f"Successfully decoded to int: {encrypted_int}")
        except Exception as decode_err:
            return {
                "status": "decode_error",
                "error": f"Could not decode base64 to int: {str(decode_err)}",
                "encrypted_data_sample": encrypted_data[:50] + "..." if len(encrypted_data) > 50 else encrypted_data
            }
        
        # Step 2: Your decryption
        # decrypted_salary_cents = decrypt_value(encrypted_salary, p, q)
        try:
            decrypted_int = decrypt_value(encrypted_int, p, q)
            print(f"Successfully decrypted to: {decrypted_int}")
        except Exception as decrypt_err:
            return {
                "status": "decrypt_error", 
                "error": f"Decryption failed: {str(decrypt_err)}",
                "encrypted_int": encrypted_int
            }
        
        return {
            "status": "success",
            "encrypted_data": encrypted_data,
            "encrypted_int": encrypted_int,
            "decrypted_int": decrypted_int,
            "decrypted_message": str(decrypted_int),
            "p_info": f"{str(p)[:20]}... (length: {len(str(p))})",
            "q_info": f"{str(q)[:20]}... (length: {len(str(q))})"
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
    """
    Test endpoint with very simple messages to debug step by step
    """
    try:
        public_key = request.get("publicKey")
        private_key = request.get("privateKey")
        
        if not public_key or not private_key:
            raise HTTPException(status_code=400, detail="publicKey and privateKey fields required")
        
        # Test with very simple messages
        test_messages = ["a", "hi", "test", "123"]
        results = []
        
        for msg in test_messages:
            try:
                # Encrypt
                public_key_n = decode_public_key(public_key)
                encrypted = encrypt_string(msg, public_key_n)
                
                # Decrypt
                priv = _b64_or_json_to_privkey(private_key)
                p = int(priv["p"])
                q = int(priv["q"])
                decrypted = decrypt_string(encrypted, p, q)
                
                results.append({
                    "original": msg,
                    "encrypted": encrypted,
                    "decrypted": decrypted,
                    "success": msg == decrypted
                })
            except Exception as e:
                results.append({
                    "original": msg,
                    "error": str(e)
                })
        
        return {
            "status": "success",
            "results": results
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)