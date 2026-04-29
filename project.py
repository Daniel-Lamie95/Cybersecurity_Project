from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

class RSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_Keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        self.public_key = self.private_key.public_key()
        print("Keys generated successfully!")

    def save_Keys(self,private_key_path = "private_key.perm", public_key_path = "public_key.perm", password = None):

        if not self.private_key or not self.public_key:
            print("No keys to save")
            return False  
        if password:
            enc_algo = serialization.BestAvailableEncryption(password.encode())
        else:
            enc_algo = serialization.NoEncryption()  

        # private key serialization 
        priv_pem = self.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
        )
        with open(private_key_path, "wb") as f:
            f.write(priv_pem)    
        
        #public key serialization
        pub_pem = self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as f:
         f.write(pub_pem)

        print(f"Saved private -> {private_key_path}, public -> {public_key_path}")
        return True
          
    def load_Keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem", password=None):
        try:
            #load private_key
            with open(private_key_path, 'rb') as f:
                priv_bytes = f.read()

                #unserialazie private key
            self.private_key = serialization.load_pem_private_key(
                priv_bytes,
                password=(password.encode() if password else None),
                backend=default_backend()
            )

            #load public_key
            with open(public_key_path, 'rb') as f:
                pub_bytes = f.read()

                #unserialazie private key
            self.public_key = serialization.load_pem_public_key(
                pub_bytes,
                backend=default_backend()
            )

            print("Kyes loaded successfully")
            return True
        except FileNotFoundError:
            print("Key files not found")
            return False
        except Exception as e:
         print("Error loading keys:", e)
        return False

    def encrypt_text(self, plaintext):
        if not self.public_key:
            print("Public key not available for encryption")
            return None
        try:
            ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                 )
            )
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            print("Encryption failed:", e)
            return None

    def decrypt_text(self, b64_ciphertext):
        if not self.private_key:
            print("Private key not available for decryption")
            return None
        try:
            
            ciphertext = base64.b64decode(b64_ciphertext)
            plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            print("Decryption failed:", e)
            return None

    #def encrypt_file():







