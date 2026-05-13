from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import re
import base64
from Crypto.Cipher import AES as CryptoAES
from Crypto.Hash import SHA256

class AES:
    def __init__(self, password, key_size):
        self.password = password
        self.key_size = key_size

    def derive_key(self, salt):
        hashed_password = SHA256.new(salt + self.password.encode()).digest()
        return hashed_password[: self.key_size // 8]

    def encrypt_file(self, input_file_path, output_file_path):
        try:
            with open(input_file_path, "rb") as file:
                original_data = file.read()

            salt = os.urandom(16)
            key = self.derive_key(salt)
            cipher = CryptoAES.new(key, CryptoAES.MODE_EAX)
            encrypted_data, tag = cipher.encrypt_and_digest(original_data)

            with open(output_file_path, "wb") as file:
                file.write(salt)
                file.write(cipher.nonce)
                file.write(tag)
                file.write(encrypted_data)

            print(f"File encrypted successfully using AES-{self.key_size}.")

        except FileNotFoundError:
            print("Error: Input file not found.")

        except Exception as error:
            print("Encryption error:", error)

    def decrypt_file(self, input_file_path, output_file_path):
        try:
            with open(input_file_path, "rb") as file:
                salt = file.read(16)
                nonce = file.read(16)
                tag = file.read(16)
                encrypted_data = file.read()

            key = self.derive_key(salt)
            cipher = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

            with open(output_file_path, "wb") as file:
                file.write(decrypted_data)

            print(f"File decrypted successfully using AES-{self.key_size}.")
            print("Decrypted content:")
            print(decrypted_data.decode())

        except FileNotFoundError:
            print("Error: Encrypted file not found.")

        except ValueError:
            print("Error: Wrong password, wrong AES size, or file was modified.")

        except Exception as error:
            print("Decryption error:", error)

def is_strong_password(password):

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return False

    if not re.search(r"[A-Z]", password):
        print("Password must contain an uppercase letter.")
        return False

    if not re.search(r"[a-z]", password):
        print("Password must contain a lowercase letter.")
        return False

    if not re.search(r"[0-9]", password):
        print("Password must contain a number.")
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain a special character.")
        return False

    return True

if __name__ == "__main__":
    # Keep the demo CLI behavior available, but prevent it from running on import.
                
 if __name__ == "__main__":

    while True:

        user_password = input("Enter password: ")

        if is_strong_password(user_password):
            print("Strong password accepted ✅")
            break

        else:
            print("Please try again.\n")

    user_key_size = int(input("Choose AES key size 128 / 192 / 256: "))

    aes_tool = AES(user_password, user_key_size)

    aes_tool.encrypt_file("plain.txt", "encrypted.bin")
    aes_tool.decrypt_file("encrypted.bin", "decrypted.txt")
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

    def save_Keys(self,private_key_path = "private_key.pem", public_key_path = "public_key.pem", password = None):

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
        
        # public key serialization
        pub_pem = self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as f:
         f.write(pub_pem)

        print(f"Saved private -> {private_key_path}, public -> {public_key_path}")
        return True
    # for encrypting in batches 
    def _max_oaep_plaintext_size(self):
        key_bytes = self.key_size // 8
        hash_bytes = hashes.SHA256().digest_size
        return key_bytes - (2 * hash_bytes) - 2
          
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
            if isinstance(plaintext, str):
                plaintext = plaintext.encode()

            ciphertext = self.public_key.encrypt(
                plaintext, #add noise to the data to make it more secure
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            print("Encryption failed:", e)
            return None

    def decrypt_text(self, ciphertext):
        if not self.private_key:
            print("Private key not available for decryption")
            return None
        try:
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            print("Decryption failed:", e)
            return None

    # For encrypting and decrypting files in batches to handle large files that exceed RSA limits
    def encrypt_file(self, file_path, output_path=None):
        if not self.public_key:
            print("Public key not available for encryption")
            return False
        
        if output_path is None:
            output_path = file_path + '.enc'
        
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            max_chunk = self._max_oaep_plaintext_size()
            ciphertext_chunks = []
            #loops for the plaintext in chunks of max_chunk size, encrypts each chunk, 
            # appends the encrypted   chunk to the ciphertext chunks list. 
            # it joins all the encrypted chunks together and writes the complete ciphertext to the output file.
            for i in range(0, len(plaintext), max_chunk):
                chunk = plaintext[i:i + max_chunk]
                encrypted_chunk = self.encrypt_text(chunk)
                if encrypted_chunk is None:
                    return False
                ciphertext_chunks.append(encrypted_chunk)

            ciphertext = b"".join(ciphertext_chunks)

            with open(output_path, "wb") as f:
                f.write(ciphertext)

            print(f"Encrypted file saved to {output_path}")
            return True

        except Exception as e:
            print("Encryption failed:", e)
            return None
        
    def decrypt_file(self, file_path, output_path=None):
        if not self.private_key:
            print("Private key not available for decryption")
            return False

        if output_path is None:
            output_path = file_path.replace(".enc", ".dec")

        try:
            with open(file_path, "rb") as f:
                ciphertext = f.read()

            key_bytes = self.key_size // 8
            if len(ciphertext) == 0 or len(ciphertext) % key_bytes != 0:
                print("Invalid RSA encrypted file format")
                return False

            plaintext_chunks = []
            for i in range(0, len(ciphertext), key_bytes):
                chunk = ciphertext[i:i + key_bytes]
                decrypted_chunk = self.decrypt_text(chunk)
                if decrypted_chunk is None:
                    return False
                plaintext_chunks.append(decrypted_chunk)

            plaintext = b"".join(plaintext_chunks)

            with open(output_path, "wb") as f:
                f.write(plaintext)

            print(f"Decrypted file saved to {output_path}")
            return True

        except Exception as e:
            print("Decryption failed:", e)
            return False    







