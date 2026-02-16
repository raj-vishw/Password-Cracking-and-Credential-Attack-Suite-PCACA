import os
import re

class LinuxShadowExtractor:
    HASH_REGEX = re.compile(r'^\$(?P<id>[0-9a-zA-Z]+)\$')

    HASH_TYPES = {
        "1":"MD5",
        "2a":"Blowfish",
        "5":"SHA-256",
        "6":"SHA-512"
    }
    def __init__(self,shadow_path="/etc/shadow"):
        self.shadow_path = shadow_path

    def check_permission(self):
        if not os.path.exists(self.shadow_path):
            raise FileNotFoundError(f"{self.shadow_path} not found")
        
        if not os.access(self.shadow_path,os.R_OK):
            raise PermissionError("Root privileges required to read shadow file")
            
        def identify_hash_type(self,hash_value):
            match = self.HASH_REGEX.match(hash_value)
            if match:
                algo_id = match.group("id")
                return self.HASH_TYPES.get(algo_id,f"Unknown ({algo_id})")
            return "Unknown Format"
    
    def parse_shadow(self):
        self.check_permission()
        
        extracted = []

        with open(self.shadow_path,"r") as file:
            for line in file:
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
            
                username = parts[0]
                password_hash = parts[1]

                if password_hash in ["*","!","!!"]:
                    continue

                hash_type = self.identify_hash_type(password_hash)

                extracted.append({
                    "username":username,
                    "hash":password_hash,
                    "algorithm":hash_type
                })
        return extracted

    def export_hashes(self,output_file="extracted_hashes/linux_hashes.txt"):
        os.makedirs("extracted_hashes",exist_ok=True)

        hashes = self.parse_shadow()

        with open(output_file,"w") as f:
            for entry in hashes:
                f.write(f"{entry['username']}:{entry['hahs']}\n") 
            
        return {"output_file":output_file,
        "total_hashes":len(hashes)
        }