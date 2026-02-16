import os
import re
import struct
import binascii
import hashlib
from Crypto.Cipher import ARC4


class WindowsSAMExtractor:

    def __init__(self, sam_path, system_path):
        self.sam_path = sam_path
        self.system_path = system_path
        self.boot_key = None


    def validate_files(self):
        if not os.path.exists(self.sam_path):
            raise FileNotFoundError(f"SAM file not found: {self.sam_path}")

        if not os.path.exists(self.system_path):
            raise FileNotFoundError(f"SYSTEM file not found: {self.system_path}")

        if os.path.getsize(self.sam_path) < 1024:
            raise ValueError("Invalid SAM file (too small)")

        if os.path.getsize(self.system_path) < 4096:
            raise ValueError("Invalid SYSTEM file (too small)")


    def read_hive(self, path):
        with open(path, "rb") as f:
            data = f.read()

        if data[0:4] != b"regf":
            raise ValueError(f"{path} is not a valid registry hive")

        return data


    def extract_boot_key(self):
        system_data = self.read_hive(self.system_path)


        for i in range(0, len(system_data) - 16, 8):
            chunk = system_data[i:i+16]
            if self._looks_like_key(chunk):
                self.boot_key = chunk
                return chunk

        raise Exception("Boot key could not be located")

    def _looks_like_key(self, data):
        if len(data) != 16:
            return False
        if len(set(data)) < 8:
            return False
        if data.count(b"\x00") > 4:
            return False
        return True


    def decrypt_ntlm_hash(self, encrypted_hash, rid):
        if not self.boot_key:
            self.extract_boot_key()

        rid_bytes = struct.pack("<I", rid)
        user_key = hashlib.md5(self.boot_key + rid_bytes).digest()

        cipher = ARC4.new(user_key)
        decrypted = cipher.decrypt(encrypted_hash)

        if len(decrypted) >= 16:
            return decrypted[:16]

        return None


    def parse_sam(self):
        sam_data = self.read_hive(self.sam_path)
        users = []

        for i in range(0, len(sam_data) - 64, 16):
            possible_rid = struct.unpack("<I", sam_data[i:i+4])[0]

            if possible_rid < 500:
                continue

            encrypted_hash = sam_data[i+16:i+32]

            if self._looks_like_hash(encrypted_hash):
                decrypted = self.decrypt_ntlm_hash(encrypted_hash, possible_rid)

                if decrypted:
                    users.append({
                        "rid": possible_rid,
                        "username": f"USER_{possible_rid}",
                        "ntlm_hash": binascii.hexlify(decrypted).decode().upper(),
                        "lm_hash": None
                    })

        return users

    def _looks_like_hash(self, data):
        if len(data) != 16:
            return False

        printable = sum(1 for b in data if 32 <= b <= 126)
        if printable > 5:
            return False

        if len(set(data)) < 8:
            return False

        return True

    def extract(self):
        """
        Returns:
            List of:
            {
                rid,
                username,
                ntlm_hash,
                lm_hash
            }
        """
        self.validate_files()
        return self.parse_sam()
