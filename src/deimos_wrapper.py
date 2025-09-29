import ctypes
import os
from pathlib import Path
from typing import Optional

class DeimosError(Exception):
    """Custom exception for Deimos cipher errors"""
    pass

# Define C structures
class EncryptedData(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)),
                ("length", ctypes.c_size_t)]

class DecryptedData(ctypes.Structure):
    _fields_ = [("data", ctypes.c_char_p),
                ("length", ctypes.c_size_t),
                ("success", ctypes.c_int)]

class DeimosCipher:
    """Python wrapper for Deimos Cipher C++ implementation"""
    
    def __init__(self, dll_path: Optional[str] = None):
        """
        Initialize the Deimos cipher wrapper
        
        Args:
            dll_path: Path to the compiled DLL. If None, looks for 'deimos_cipher.dll' in current directory
        """
        if dll_path is None:
            dll_path = Path(__file__).parent.parent / "src" / "deimos_cipher.dll"

        if not os.path.exists(dll_path):
            raise DeimosError(f"DLL not found at {dll_path}")
            
        try:
            self.lib = ctypes.CDLL(str(dll_path))
        except OSError as e:
            raise DeimosError(f"Failed to load DLL: {e}")
        
        self._setup_function_signatures()
        self._initialize()
    
    def _setup_function_signatures(self):
        """Setup ctypes function signatures"""
        
        # deimos_encrypt
        self.lib.deimos_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.deimos_encrypt.restype = ctypes.POINTER(EncryptedData)
        
        # deimos_decrypt  
        self.lib.deimos_decrypt.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_char_p]
        self.lib.deimos_decrypt.restype = ctypes.POINTER(DecryptedData)
        
        # Memory cleanup functions
        self.lib.free_encrypted_data.argtypes = [ctypes.POINTER(EncryptedData)]
        self.lib.free_encrypted_data.restype = None
        
        self.lib.free_decrypted_data.argtypes = [ctypes.POINTER(DecryptedData)]
        self.lib.free_decrypted_data.restype = None
        
        # Initialization
        self.lib.deimos_init.argtypes = []
        self.lib.deimos_init.restype = ctypes.c_int
    
    def _initialize(self):
        """Initialize the cipher library"""
        result = self.lib.deimos_init()
        if result == 0 or result == 1:
            # Both "first initialization" and "already initialized" are success
            pass
        else:
            # Actual error (typically -1)
            raise DeimosError(f"Failed to initialize libsodium: {result}")
    
    def encrypt(self, plaintext: str, password: str) -> bytes:
        """
        Encrypt plaintext using Deimos cipher
        
        Args:
            plaintext: The text to encrypt
            password: The password to use for encryption
            
        Returns:
            Encrypted data as bytes
            
        Raises:
            DeimosError: If encryption fails
        """
        if not isinstance(plaintext, str):
            raise DeimosError("Plaintext must be a string")
        if not isinstance(password, str):
            raise DeimosError("Password must be a string")
            
        # Convert strings to bytes for C interface
        plaintext_bytes = plaintext.encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        # Call C function
        result_ptr = self.lib.deimos_encrypt(plaintext_bytes, password_bytes)
        
        if not result_ptr:
            raise DeimosError("Encryption failed")
        
        try:
            # Extract data from C structure
            result = result_ptr.contents
            
            # Create Python bytes object from C data
            encrypted_bytes = bytes((result.data[i] for i in range(result.length)))
            
            return encrypted_bytes
            
        finally:
            # Always free the C memory
            self.lib.free_encrypted_data(result_ptr)
    
    def decrypt(self, ciphertext: bytes, password: str) -> str:
        """
        Decrypt ciphertext using Deimos cipher
        
        Args:
            ciphertext: The encrypted data to decrypt
            password: The password used for encryption
            
        Returns:
            Decrypted plaintext as string
            
        Raises:
            DeimosError: If decryption fails or integrity check fails
        """
        if not isinstance(ciphertext, bytes):
            raise DeimosError("Ciphertext must be bytes")
        if not isinstance(password, str):
            raise DeimosError("Password must be a string")
        
        # Convert data for C interface
        password_bytes = password.encode('utf-8')
        ciphertext_array = (ctypes.c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext)
        
        # Call C function
        result_ptr = self.lib.deimos_decrypt(ciphertext_array, len(ciphertext), password_bytes)
        
        if not result_ptr:
            raise DeimosError("Decryption failed")
        
        try:
            result = result_ptr.contents
            
            if not result.success:
                # Decryption failed, get error message
                error_msg = result.data.decode('utf-8') if result.data else "Unknown decryption error"
                raise DeimosError(f"Decryption failed: {error_msg}")
            
            # Successful decryption
            plaintext = result.data.decode('utf-8') if result.data else ""
            return plaintext
            
        finally:
            # Always free the C memory
            self.lib.free_decrypted_data(result_ptr)
    
    def encrypt_bytes(self, plaintext: bytes, password: str) -> bytes:
        """
        Encrypt raw bytes using Deimos cipher
        
        Args:
            plaintext: The bytes to encrypt
            password: The password to use for encryption
            
        Returns:
            Encrypted data as bytes
        """
        # Convert bytes to string for the C interface (base64 encoding to handle binary data safely)
        import base64
        plaintext_str = base64.b64encode(plaintext).decode('ascii')
        return self.encrypt(plaintext_str, password)
    
    def decrypt_bytes(self, ciphertext: bytes, password: str) -> bytes:
        """
        Decrypt to raw bytes using Deimos cipher
        
        Args:
            ciphertext: The encrypted data to decrypt
            password: The password used for encryption
            
        Returns:
            Decrypted data as bytes
        """
        import base64
        plaintext_str = self.decrypt(ciphertext, password)
        return base64.b64decode(plaintext_str.encode('ascii'))

# Convenience functions for easy usage
_cipher_instance = None

def get_cipher() -> DeimosCipher:
    """Get a singleton instance of DeimosCipher"""
    global _cipher_instance
    if _cipher_instance is None:
        _cipher_instance = DeimosCipher()
    return _cipher_instance

def encrypt(plaintext: str, password: str) -> bytes:
    """Convenience function for encryption"""
    return get_cipher().encrypt(plaintext, password)

def decrypt(ciphertext: bytes, password: str) -> str:
    """Convenience function for decryption"""
    return get_cipher().decrypt(ciphertext, password)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Convenience function for encrypting bytes"""
    return get_cipher().encrypt_bytes(plaintext, password)

def decrypt_bytes(ciphertext: bytes, password: str) -> bytes:
    """Convenience function for decrypting to bytes"""
    return get_cipher().decrypt_bytes(ciphertext, password)
