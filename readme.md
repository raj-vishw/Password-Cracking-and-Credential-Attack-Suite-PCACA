# 📘 Password Cracking & Credential Attack Suite  
## A Modular Red Team & Blue Team Credential Security Assessment Toolkit

---

# 1️⃣ Project Overview

The **Password Cracking & Credential Attack Suite** is a structured cybersecurity toolkit designed to simulate credential attacks and perform password strength audits in a controlled and ethical environment.

The system demonstrates:

- Dictionary-based password attacks  
- Brute-force attack simulation  
- Linux shadow hash extraction  
- Windows SAM hash extraction (offline)  
- Password entropy and complexity analysis  
- Organizational risk evaluation  

This project bridges offensive (Red Team) and defensive (Blue Team) cybersecurity methodologies in a unified architecture.

---

# 2️⃣ Practical Motivation

Passwords remain the most widely used authentication mechanism. Weak password practices lead to:

- Account takeovers  
- Privilege escalation  
- Credential stuffing attacks  
- Lateral movement inside networks  
- Data breaches  

This project enables understanding of:

- How passwords are stored  
- How hashes are extracted  
- How attackers attempt cracking  
- How defenders evaluate password strength  
- How organizations assess password risk  

---

# 3️⃣ System Architecture

```
                ┌───────────────────────┐
                │        CLI User       │
                └────────────┬──────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │   Dictionary Generator  │
               └────────────┬────────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │     Hash Extraction     │
               │  (Linux / Windows SAM)  │
               └────────────┬────────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │      Attack Engine      │
               │  - Dictionary Attack    │
               │  - Brute Force          │
               │  - Hybrid Mode          │
               └────────────┬────────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │ Password Strength       │
               │ Analyzer                │
               └────────────┬────────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │  Risk Metrics Engine    │
               └────────────┬────────────┘
                             │
                             ▼
               ┌─────────────────────────┐
               │   Report Generation     │
               │  TXT | JSON | PDF       │
               └─────────────────────────┘
```

---

# 4️⃣ Modules Implemented

---

## 🔴 Dictionary Generator

Features:

- Name + DOB pattern generation  
- Template-based combinations  
- Case transformations  
- Leetspeak substitutions  
- Numeric and symbol mutation  
- Custom word support  

Example Output:
```
raja1990
Raja@1990
r4j4
raja123
```

---

## 🔴 Hash Extraction

### Linux Shadow

- Parses `/etc/shadow`
- Detects hash algorithm (MD5, SHA-256, SHA-512)
- Skips locked accounts

### Windows SAM (Offline)

- Reads SAM & SYSTEM hive
- Extracts boot key
- Decrypts NTLM hashes
- Returns structured credential objects

---

## 🔴 Attack Engine

### Dictionary Attack

- Streams large wordlists safely
- Stops on match
- Tracks attempts
- Measures time

### Brute-Force Simulation

- Incremental mode
- Custom charset
- Estimated search space
- Estimated crack time

### Hybrid Mode

1. Dictionary attempt  
2. Brute-force fallback if dictionary fails  

---

## 🔵 Password Strength Analyzer

Analyzes:

- Entropy (log₂ formula)
- Character set diversity
- Pattern detection
- Dictionary exposure risk
- Severity rating

### Entropy Formula

Severity Levels:

- CRITICAL  
- VERY WEAK  
- WEAK  
- MODERATE  
- STRONG  
- VERY STRONG  

---

## 📊 Risk Metrics Engine

Calculates:

- Total accounts
- Crack success rate
- Average entropy
- Severity distribution
- Organizational risk posture

---

# 5️⃣ Features

### 🔴 Red Team

- Dictionary attack simulation  
- Brute-force simulation  
- Hash extraction  
- NTLM processing  

### 🔵 Blue Team

- Entropy evaluation  
- Pattern detection  
- Exposure detection  
- Severity scoring  
- Policy recommendation system  

---

# 6️⃣ Installation

Requirements:

- Python 3.10+
- pycryptodome
- reportlab

Install:

```bash
pip install pycryptodome reportlab
```

---

# 7️⃣ Usage Examples

### Generate Dictionary

```bash
python3 main.py generate-dict --name raja --dob 15081990
```

### Extract Linux Hashes

```bash
python3 main.py extract-linux --shadow /etc/shadow
```

### Extract Windows Hashes

```bash
python3 main.py extract-windows --sam SAM --system SYSTEM
```

### Dictionary Attack

```bash
python3 main.py attack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --mode dictionary --wordlist /usr/share/wordlists/rockyou.txt
```

### Brute Force

```bash
python3 main.py attack --hash <hash> --mode brute --charset lower --min 1 --max 6
```

### Analyze Password

```bash
python3 main.py analyze --password "N@me1990!"
```

---

# 8️⃣ Learning Outcomes

- Understanding password hashing mechanisms  
- Ethical credential extraction techniques  
- Dictionary and brute-force methodologies  
- Entropy-based strength evaluation  
- Risk assessment modeling  
- Red vs Blue team operational workflow  

---

# 9️⃣ Limitations

- Simplified SAM parsing
- CPU-based brute force only
- No GPU acceleration
- No Active Directory integration

---

#  🔟 Future Enhancements

- Multi-threaded attack engine
- GPU integration
- HTML dashboard reporting
- Password reuse detection
- Account lockout simulation
- Enterprise policy integration

---

# ⚠️ Disclaimer

This project is strictly for:

- Educational purposes  
- Controlled lab environments  
- Ethical cybersecurity practice  

Do NOT use this toolkit against unauthorized systems.

---
