# SSD - Chat Application

A real-time messaging platform implementing end-to-end encryption to ensure confidential communication between two users, protecting against eavesdropping and tampering.

## Project Overview
This application enables secure text-based communication with:
- **Client-side encryption** before message transmission
- **JWT authentication** for user identity verification
- **SignalR** for real-time message delivery
- **Cryptographic integrity checks** to detect message tampering

## Key Security Features
1. **End-to-End Encryption**
    - Messages encrypted using AES-GCM algorithm before leaving sender's device
    - Decryption only possible by intended recipient
    - 256-bit encryption keys derived from combined user public keys

2. **Secure Authentication**
    - JSON Web Tokens (JWT) validate user sessions
    - Token-based authorization for chat connections

3. **Message Integrity Protection**
    - Built-in authentication tags in AES-GCM ensure message authenticity
    - Cryptographic hashing prevents undetected message modification

4. **Forward Secrecy Foundations**
    - Unique initialization vector (IV) per message
    - Session-specific encryption key derivation

## Technical Implementation
### Cryptographic Architecture
- **Key Management**: Combined public keys hashed with SHA-256 to create shared secrets
- **Encryption Workflow**:
    1. Random 12-byte IV generated per message
    2. AES-GCM encryption using derived session key
    3. Encrypted payload transmitted with IV metadata

- **Decryption Process**:
    1. Recipient recreates session key using stored public keys
    2. IV from metadata used for ciphertext decryption
    3. Authentication tag verification prevents tampering

### Infrastructure
- **Real-Time Layer**: SignalR
- **Security Layer**:
    - HTTPS transport encryption
    - JWT token validation middleware
    - Encrypted payload handling (server never accesses plaintext)

## Setup & Usage
### Requirements
- .NET 9 runtime
- Modern web browser with Web Crypto API support
- PostgreSQL database or alternatively InMemoreDatabase (does not work 100% but easier to setup)

### Installation
1. Clone repository and configure connection strings
2. Set JWT secret in server configuration
3. Launch server and client applications

### User Flow
1. Authenticate with credentials to obtain JWT
2. Exchange public keys through secure channel
3. Initiate encrypted chat session
4. Messages automatically encrypted/decrypted during transmission

## Security Considerations
- **Confidentiality**: Third parties (including server operators) cannot read messages
- **Integrity**: Cryptographic verification prevents message alteration
- **Authentication**: JWT tokens ensure participant identity validity
- **Non-Repudiation**: Message authentication prevents sender denial