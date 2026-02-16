        # 'NTLM': re.compile(r'^[a-fA-F0-9]{32}$'),
        # 'LM': re.compile(r'^[a-fA-F0-9]{32}$'),  
        
        # Unix/Linux shadow hashes
        # 'MD5 (Unix)': re.compile(r'^\$1\$\S{0,8}\$[a-fA-F0-9]{22,34}$'),
        # 'SHA-256 (Unix)': re.compile(r'^\$5\$\S{0,16}\$[a-fA-F0-9/\.]{43,86}$'),
        # 'SHA-512 (Unix)': re.compile(r'^\$6\$\S{0,16}\$[a-fA-F0-9/\.]{86,128}$'),
        # 'bcrypt': re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'),
        # 'yescrypt': re.compile(r'^\$y\$.{1,8}\$.{1,48}\$.{1,48}$'),
        # 'argon2': re.compile(r'^\$argon2[i,d,id]\$v=\d+\$m=\d+,t=\d+,p=\d+\$.*\$.*$'),
        # 'scrypt': re.compile(r'^\$7\$\S{22}.*$'),
        
        # # General hash formats
        # 'MD4': re.compile(r'^[a-fA-F0-9]{32}$'),
        # 'MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
        # 'SHA-1': re.compile(r'^[a-fA-F0-9]{40}$'),
        # 'SHA-224': re.compile(r'^[a-fA-F0-9]{56}$'),
        # 'SHA-256': re.compile(r'^[a-fA-F0-9]{64}$'),
        # 'SHA-384': re.compile(r'^[a-fA-F0-9]{96}$'),
        # 'SHA-512': re.compile(r'^[a-fA-F0-9]{128}$'),
        # 'RIPEMD-160': re.compile(r'^[a-fA-F0-9]{40}$'),
        # 'Whirlpool': re.compile(r'^[a-fA-F0-9]{128}$'),
        
        # # MySQL hashes
        # 'MySQL < 4.1': re.compile(r'^[a-fA-F0-9]{16}$'),
        # 'MySQL 4.1+': re.compile(r'^\*[a-fA-F0-9]{40}$'),
        # 'MySQL 5.7+': re.compile(r'^\$mysql\$.{12,}' ),
        
        # # Oracle hashes
        # 'Oracle 10g+': re.compile(r'^S:[a-fA-F0-9]{60}$'),
        # 'Oracle 11g+': re.compile(r'^[a-fA-F0-9]{40,}$'),
        
        # # PostgreSQL
        # 'PostgreSQL MD5': re.compile(r'^md5[a-fA-F0-9]{32}$'),
        
        # # MSSQL
        # 'MSSQL 2000': re.compile(r'^0x0100[a-fA-F0-9]{80}$'),
        # 'MSSQL 2005+': re.compile(r'^0x0100[a-fA-F0-9]{40}$'),
        
        # # LDAP / Active Directory
        # 'LDAP SSHA': re.compile(r'^\{SSHA\}[a-zA-Z0-9+/=]{32,}$'),
        # 'LDAP SHA': re.compile(r'^\{SHA\}[a-zA-Z0-9+/=]{28,}$'),
        # 'LDAP MD5': re.compile(r'^\{MD5\}[a-zA-Z0-9+/=]{24,}$'),
        
        # 'Cisco Type 5': re.compile(r'^\$1\$.{4}\$.{22}$'),
        # 'Cisco Type 7': re.compile(r'^[a-fA-F0-9]{4,}$'),
        # 'Cisco Type 8': re.compile(r'^\$8\$.{1,16}\$.{43}$'),
        # 'Cisco Type 9': re.compile(r'^\$9\$.{1,16}\$.{86}$'),
        
        # 'Joomla': re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$'),
        
        # 'Drupal 7': re.compile(r'^\$S\$.{52}$'),
        # 'Drupal 8': re.compile(r'^\$S\$.{55}$'),
        
        # 'WordPress': re.compile(r'^\$P\$.{31}$'),
        
        # 'Django MD5': re.compile(r'^md5\$[a-f0-9]+\$[a-f0-9]{32}$'),
        # 'Django SHA-256': re.compile(r'^sha256\$[a-f0-9]+\$[a-f0-9]{64}$'),
        
        # 'PBKDF2-HMAC-SHA1': re.compile(r'^\$pbkdf2-sha1\$\d+\$.{1,16}\$.{32,}$'),
        # 'PBKDF2-HMAC-SHA256': re.compile(r'^\$pbkdf2-sha256\$\d+\$.{1,16}\$.{44,}$'),
        # 'PBKDF2-HMAC-SHA512': re.compile(r'^\$pbkdf2-sha512\$\d+\$.{1,16}\$.{88,}$'),
        
        # 'Kerberos 5 TGS-REP': re.compile(r'^\$krb5tgs\$.+$'),
        # 'Kerberos 5 AS-REP': re.compile(r'^\$krb5asrep\$.+$'),

        # 'Base64 encoded': re.compile(r'^[a-zA-Z0-9+/=]{24,}$'),
        # 'Hex encoded': re.compile(r'^[a-fA-F0-9]+$'),
        # 'CRC32': re.compile(r'^[a-fA-F0-9]{8}$'),
        # 'CRC64': re.compile(r'^[a-fA-F0-9]{16}$'),


import re

class HashIdentifier:
    def identify(self, hash_value):
        """Identify hash type from a single hash value"""
        hash_value = hash_value.strip()
        
        if not hash_value or hash_value in ['*', '!', 'x']:
            return "Empty/Disabled"
        
        # Windows Hashes
        if re.match(r'^[a-fA-F0-9]{32}$', hash_value):
            return "NTLM / MD4 / MD5"
        
        if re.match(r'^[a-fA-F0-9]{16}$', hash_value):
            return "LM Hash / MySQL pre-4.1"
        
        # Unix/Linux Shadow Hashes
        if re.match(r'^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22,34}$', hash_value):
            return "Unix MD5 (crypt)"
        
        if re.match(r'^\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$', hash_value):
            return "bcrypt"
        
        if re.match(r'^\$2[xy]\$[0-9]{2}\$[a-zA-Z0-9./]{53}$', hash_value):
            return "bcrypt (2x/2y)"
        
        if re.match(r'^\$5\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43,86}$', hash_value):
            return "SHA-256 (Unix crypt)"
        
        if re.match(r'^\$6\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86,128}$', hash_value):
            return "SHA-512 (Unix crypt)"
        
        if re.match(r'^\$y\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{1,48}\$[a-zA-Z0-9./]{1,48}$', hash_value):
            return "yescrypt"
        
        if re.match(r'^\$7\$[a-zA-Z0-9./]{22}.*$', hash_value):
            return "scrypt"
        
        if re.match(r'^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$', hash_value):
            return "Argon2i"
        
        if re.match(r'^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$', hash_value):
            return "Argon2id"
        
        if re.match(r'^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+$', hash_value):
            return "Argon2d"
        
        # General Hash Formats
        if re.match(r'^[a-fA-F0-9]{40}$', hash_value):
            return "SHA-1 / RIPEMD-160 / HAVAL-160"
        
        if re.match(r'^[a-fA-F0-9]{56}$', hash_value):
            return "SHA-224 / SHA3-224"
        
        if re.match(r'^[a-fA-F0-9]{64}$', hash_value):
            return "SHA-256 / SHA3-256 / BLAKE2s"
        
        if re.match(r'^[a-fA-F0-9]{96}$', hash_value):
            return "SHA-384 / SHA3-384"
        
        if re.match(r'^[a-fA-F0-9]{128}$', hash_value):
            return "SHA-512 / SHA3-512 / Whirlpool / BLAKE2b"
        
        if re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{16,32}$', hash_value):
            return "Joomla (MD5:salt)"
        
        if re.match(r'^[a-fA-F0-9]{40}:[a-fA-F0-9]{16,32}$', hash_value):
            return "Joomla (SHA1:salt)"
        
        # Database Hashes
        if re.match(r'^\*[a-fA-F0-9]{40}$', hash_value):
            return "MySQL 4.1+ (SHA-1)"
        
        if re.match(r'^[a-fA-F0-9]{16}$', hash_value):
            return "MySQL pre-4.1 / Oracle older"
        
        if re.match(r'^md5[a-fA-F0-9]{32}$', hash_value):
            return "PostgreSQL MD5"
        
        if re.match(r'^0x0100[a-fA-F0-9]{80}$', hash_value):
            return "MSSQL (2000)"
        
        if re.match(r'^0x0100[a-fA-F0-9]{40}$', hash_value):
            return "MSSQL (2005+)"
        
        if re.match(r'^S:[a-fA-F0-9]{60}$', hash_value):
            return "Oracle 10g+"
        
        if re.match(r'^[a-fA-F0-9]{60}$', hash_value):
            return "Oracle 11g+ / HAVAL-240"
        
        # Web Application Hashes
        if re.match(r'^\$P\$\$[a-zA-Z0-9./]{31}$', hash_value):
            return "WordPress (phpass)"
        
        if re.match(r'^\$H\$\$[a-zA-Z0-9./]{31}$', hash_value):
            return "phpBB3 (phpass)"
        
        if re.match(r'^\$S\$[a-zA-Z0-9./]{52,55}$', hash_value):
            return "Drupal 7+"
        
        if re.match(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$', hash_value):
            return "Joomla"
        
        if re.match(r'^md5\$[a-f0-9]+\$[a-f0-9]{32}$', hash_value):
            return "Django MD5"
        
        if re.match(r'^sha1\$[a-f0-9]+\$[a-f0-9]{40}$', hash_value):
            return "Django SHA-1"
        
        if re.match(r'^sha256\$[a-f0-9]+\$[a-f0-9]{64}$', hash_value):
            return "Django SHA-256"
        
        if re.match(r'^pbkdf2_sha256\$\d+\$[a-zA-Z0-9]+\$[a-zA-Z0-9+/=]+$', hash_value):
            return "Django PBKDF2"
        
        # LDAP / Active Directory
        if re.match(r'^\{SSHA\}[a-zA-Z0-9+/=]{32,}$', hash_value):
            return "LDAP SSHA"
        
        if re.match(r'^\{SHA\}[a-zA-Z0-9+/=]{28,}$', hash_value):
            return "LDAP SHA"
        
        if re.match(r'^\{MD5\}[a-zA-Z0-9+/=]{24,}$', hash_value):
            return "LDAP MD5"
        
        if re.match(r'^\{SMD5\}[a-zA-Z0-9+/=]{24,}$', hash_value):
            return "LDAP SMD5"
        
        if re.match(r'^\{SSHA256\}[a-zA-Z0-9+/=]{48,}$', hash_value):
            return "LDAP SSHA256"
        
        if re.match(r'^\{SSHA512\}[a-zA-Z0-9+/=]{88,}$', hash_value):
            return "LDAP SSHA512"
        
        # Cisco Hashes
        if re.match(r'^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$', hash_value):
            return "Cisco Type 5 (MD5)"
        
        if re.match(r'^[a-fA-F0-9]{4,16}$', hash_value):
            return "Cisco Type 7 (Vigenère)"
        
        if re.match(r'^\$8\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43}$', hash_value):
            return "Cisco Type 8 (PBKDF2)"
        
        if re.match(r'^\$9\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}$', hash_value):
            return "Cisco Type 9 (SCrypt)"
        
        # PBKDF2 Variants
        if re.match(r'^\$pbkdf2-sha1\$\d+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{32,}$', hash_value):
            return "PBKDF2-HMAC-SHA1"
        
        if re.match(r'^\$pbkdf2-sha256\$\d+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{44,}$', hash_value):
            return "PBKDF2-HMAC-SHA256"
        
        if re.match(r'^\$pbkdf2-sha512\$\d+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{88,}$', hash_value):
            return "PBKDF2-HMAC-SHA512"
        
        # Kerberos
        if re.match(r'^\$krb5tgs\$.+\$.+:\$.+$', hash_value):
            return "Kerberos 5 TGS-REP"
        
        if re.match(r'^\$krb5asrep\$.+\$.+$', hash_value):
            return "Kerberos 5 AS-REP"
        
        if re.match(r'^\$krb5pa\$.+$', hash_value):
            return "Kerberos 5 PA-ENC"
        
        # Other Formats
        if re.match(r'^[a-fA-F0-9]{8}$', hash_value):
            return "CRC32 / Adler-32"
        
        if re.match(r'^[a-fA-F0-9]{16}$', hash_value):
            return "CRC64 / MySQL pre-4.1 / Oracle"
        
        if re.match(r'^[a-zA-Z0-9+/=]{24,}$', hash_value):
            return "Base64 Encoded"
        
        if re.match(r'^[a-fA-F0-9]+$', hash_value):
            return "Hex Encoded"
        
        # Check for common prefixes
        if hash_value.startswith('$'):
            return "Unix Crypt Format (unknown type)"
        
        if ':' in hash_value:
            parts = hash_value.split(':')
            if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) <= 32:
                return "Hash with salt (possible Joomla format)"
        
        return "Unknown"