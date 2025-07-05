## Project Overview

This is a Java-based custom TLS implementation that demonstrates secure communication using the TLS handshake protocol. The implementation includes:

- **Client-Server Architecture**: Socket-based communication between a TLS client and server
- **X.509 Certificate Management**: CA-signed certificates for authentication
- **Diffie-Hellman Key Exchange**: 2048-bit MODP Group for secure key agreement
- **Symmetric Encryption**: AES-GCM for message encryption with HMAC authentication
- **Complete TLS Handshake**: Multi-step process including certificate verification and finished message validation

## Build and Run Commands

**Compile the project:**

```bash
javac -cp . src/*.java src/crypto/*.java src/protocol/*.java
```

**Run the server:**

```bash
java -cp . src.Server
```

**Run the client (in a separate terminal):**

```bash
java -cp . src.Client
```

**Note**: The server must be started first and will listen on port 8443.

## Prerequisites

- **Java Development Kit (JDK) 8 or higher**
- All certificate files must be present in the `certificates/` folder
- No external dependencies required (uses only standard Java libraries)

## Quick Start

1. **Clone/Download the project**
2. **Navigate to project root:** `cd TLS`
3. **Compile:** `javac -cp . src/*.java src/crypto/*.java src/protocol/*.java`
4. **Start server:** `java -cp . src.Server`
5. **Start client (new terminal):** `java -cp . src.Client`

## Code Architecture

### Core Components

1. **Main Entry Points**:
   - `src/Main.java` - Simple hello world main class
   - `src/Client.java` - TLS client implementation
   - `src/Server.java` - TLS server implementation

2. **Cryptographic Layer** (`src/crypto/`):
   - `CertificateManager.java` - Handles X.509 certificates, CA verification, and RSA signing
   - `DiffieHellman.java` - Implements 2048-bit MODP Group DH key exchange
   - `KeyDerivation.java` - Derives session keys from shared secrets
   - `MessageCrypto.java` - Provides AES-GCM encryption/decryption with HMAC

3. **Protocol Layer** (`src/protocol/`):
   - `HandshakeMessage.java` - Defines all TLS handshake message types and structures
   - `SecureMessage.java` - Wrapper for encrypted application data

### Implementation Order and Classes Dependences

1. **Foundation Classes (No Dependencies)**:
	- `src/crypto/DiffieHellman.java`
		- Pure cryptographic math - no dependencies
		- Test: Verify key generation and shared secret calculation
	- `src/crypto/CertificateManager.java`
		- Only uses Java security APIs
		- Test: Load certificates, verify CA signatures, sign/verify data
  	- `src/protocol/HandshakeMessage.java`
  		- Pure data structure, no business logic
    	- Test: Create different message types, serialize/deserialize
  	- `src/protocol/SecureMessage.java`
    	- Test: Create and access encrypted content
2. **Phase 2: Crypto Utilities (Depends only on standard libraries)**:
	- `src/crypto/KeyDerivation.java`
   		- Test: Verify key derivation produces correct different keys for client/server
	- `src/crypto/MessageCrypto.java`
    	- Test: Encrypt/decrypt messages, verify MAC validation
3. **Phase 3: Application Layer (Depends on all previous phases)**:
	- `src/Server.java`
		- Test: Mock handshake components, test individual handshake steps
	- `src/Client.java`
		- Test: Mock handshake components, test against Server
	- `src/Main.java`


### TLS Handshake Flow

1. **Client Hello**: Client sends random nonce
2. **Server Hello**: Server responds with certificate and signed DH public key
3. **Client Key Exchange**: Client sends certificate and signed DH public key
4. **Server Finished**: Server sends HMAC of handshake messages
5. **Client Finished**: Client sends HMAC verification

### Certificate Infrastructure

The project uses a complete PKI setup with all certificate files organized in the `certificates/` folder:
- CA certificate (`certificates/CAcertificate.pem`)
- Server certificate (`certificates/CASignedServerCertificate.pem`) 
- Client certificate (`certificates/CASignedClientCertificate.pem`)
- Private keys in DER format (`certificates/clientPrivateKey.der`, `certificates/serverPrivateKey.der`)
- Configuration and CSR files (`certificates/config.cnf`, `certificates/*.csr`)
- OpenSSL database files (`certificates/index.txt*`, `certificates/serial*`)

## Development Notes
- Certificate paths point to the `certificates/` folder in the Client and Server classes
- The implementation uses Java serialization for message transport
- Error handling includes comprehensive exception catching with detailed logging
- The server accepts one client connection at a time
- Both client and server perform mutual authentication via certificates