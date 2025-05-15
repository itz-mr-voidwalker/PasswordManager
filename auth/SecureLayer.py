from cryptography.fernet import Fernet
import json
import keyring
import bcrypt
import os
from auth.config import get_env_var
from pathlib import Path
from auth.auth_logging import setup_logging

class SecureLayer:
    def __init__(self):
        self.logger = setup_logging()
        self.setup_cipher()        
        self.data_file = Path(get_env_var('DATA_PATH'))
    
    def setup_cipher(self):
        try:
            self.key = keyring.get_password(get_env_var('APP_NAME'), get_env_var('USERNAME'))
            if self.key is None:
                self.key = Fernet.generate_key()
                keyring.set_password(get_env_var('APP_NAME'), get_env_var('USERNAME'), self.key.decode())
            self.cipher = Fernet(self.key)
            
        except Exception as e:
            self.logger.error(f"Exception While Cipher Setup - {e}")
    
    def chk_if_exists(self)->bool:
        return os.path.exists(self.data_file)
    
    def save_data(self, data)->bool:
        try:
            with open(self.data_file, 'w') as file:
                file.write(data.decode())
            return True
        except Exception as e:
            self.logger.error(f"Can't save encrypted data: {e}")
            return False
    
    def encrypt_data(self, name:str, email:str, password:str)->bool:
        try:
            password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            user = [name, email, password.decode()]
            
            user_bytes = json.dumps(user).encode()
            
            encrypted = self.cipher.encrypt(user_bytes)
            
            self.save_data(encrypted)
            return True
            
        except Exception as e:
            self.logger.error(f"Error While Encrypting Data: {e}")
            return False
    
    def load_data(self)->str|bool:
        if self.chk_if_exists():
            try:
                with open(self.data_file, 'r') as file:
                    encrypted_data = file.read()
                return encrypted_data
            except Exception as e:
                self.logger.error(f"Error While Loading Encrypted Data: {e}")
                return False
        else:
            self.logger.error("No File Exists!")
            return False
        
    def decrypt_data(self)->dict|str:
        encrypted_data = self.load_data().encode()
        try:
            user_bytes = self.cipher.decrypt(encrypted_data)
            
            user = json.loads(user_bytes)           
            return user        
            
        except Exception as e:
            self.logger.error(f"Error Occured-{e}")
            
    def validate_user(self, name:str, password:str)->bool:
        try:
            user = self.decrypt_data()
            
            if user[0] ==name:
                if bcrypt.checkpw(password.encode(), user[2].encode()):
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error While Validating User:{e}")
