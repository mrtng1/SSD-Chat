## SSD Chat Application

Features:
- End-to-end encryption using AES-GCM-256
- Elliptic Curve Diffie-Hellman key exchange
- Message signing with ECDSA
- JWT authentication
- Perfect forward secrecy

Run instructions:
1. Clone repository
2. Configure JWT key in appsettings.json
3. Configure Database connection -> create database with .sql file at ChatServer/Infrastructure/database.sql 
4. dotnet run --project Server
5. dotnet run --project Client

Cryptography choices:
- ECDH for secure key exchange without transmitting secrets
- AES-GCM for confidential+authenticated encryption
- HKDF for key derivation
- ECDSA for message integrity verification

sequenceDiagram
    participant A as User A
    participant B as User B
    participant S as Server

    A->>S: Register (PublicKey_A)
    B->>S: Register (PublicKey_B)

    A->>S: Get PublicKey_B
    S->>A: PublicKey_B

    A->>A: Derive AES Key (PrivateKey_A + PublicKey_B)
    A->>S: Send Encrypted Message (AES-GCM + IV)
    S->>B: Forward Encrypted Message

    B->>B: Derive AES Key (PrivateKey_B + PublicKey_A)
    B->>B: Decrypt Message