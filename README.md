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
