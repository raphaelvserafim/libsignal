# libsignal Node (TypeScript)

**Modern TypeScript implementation of the Signal Protocol for Node.js**

A robust, type-safe, and updated version of the Signal protocol implementation, originally based on [libsignal-protocol-javascript](https://github.com/WhisperSystems/libsignal-protocol-javascript), now fully migrated to TypeScript for enhanced developer experience and reliability.

## 🚀 What's New in v3.0

- **Full TypeScript Support**: Complete migration from JavaScript to TypeScript with comprehensive type definitions
- **Enhanced Type Safety**: Strict typing throughout the codebase prevents runtime errors
- **Modern ES Modules**: Support for both CommonJS and ES module imports
- **Improved Developer Experience**: IntelliSense, auto-completion, and compile-time error checking
- **Updated Dependencies**: Latest versions of all dependencies for security and performance
- **Robust Architecture**: Cleaner, more maintainable code structure

## 📦 Installation

```bash
npm install @raphaelvserafim/libsignal
```

## 🛠️ Usage

### TypeScript
```typescript
import { SessionBuilder, SessionCipher, ProtocolAddress, keyhelper } from '@raphaelvserafim/libsignal';

// Generate identity key pair
const identityKeyPair = keyhelper.generateIdentityKeyPair();

// Create protocol address
const address = new ProtocolAddress('user123', 1);

// Build session
const sessionBuilder = new SessionBuilder(storage, address);
await sessionBuilder.initOutgoing(preKeyBundle);

// Encrypt/decrypt messages
const cipher = new SessionCipher(storage, address);
const encrypted = await cipher.encrypt(Buffer.from('Hello, Signal!'));
```

### JavaScript (CommonJS)
```javascript
const { SessionBuilder, SessionCipher, ProtocolAddress, keyhelper } = require('@raphaelvserafim/libsignal');

// Same API as TypeScript examples
```

## 📋 Overview

A ratcheting forward secrecy protocol that works in synchronous and asynchronous messaging environments. This TypeScript implementation provides:

- **Type Safety**: Compile-time guarantees for protocol correctness
- **Modern Async/Await**: Clean asynchronous code patterns
- **Comprehensive Error Handling**: Typed error classes for better debugging
- **Memory Safety**: Proper buffer handling and cleanup

## 🔑 PreKeys

This protocol uses a concept called 'PreKeys'. A PreKey is an ECPublicKey and an associated unique ID which are stored together by a server. PreKeys can also be signed.

At install time, clients generate a single signed PreKey, as well as a large list of unsigned PreKeys, and transmit all of them to the server.

```typescript
// Generate PreKeys
const preKeys = [];
for (let i = 0; i < 100; i++) {
    preKeys.push(keyhelper.generatePreKey(i));
}

// Generate signed PreKey
const signedPreKey = keyhelper.generateSignedPreKey(identityKeyPair, 1);
```

## 🔗 Sessions

Signal Protocol is session-oriented. Clients establish a "session," which is then used for all subsequent encrypt/decrypt operations. There is no need to ever tear down a session once one has been established.

Sessions are established in one of two ways:

1. **PreKeyBundles**: A client that wishes to send a message to a recipient can establish a session by retrieving a PreKeyBundle for that recipient from the server.
2. **PreKeySignalMessages**: A client can receive a PreKeySignalMessage from a recipient and use it to establish a session.

```typescript
interface PreKeyBundle {
    registrationId: number;
    deviceId: number;
    preKeyId?: number;
    preKeyPublic?: ArrayBuffer;
    signedPreKeyId: number;
    signedPreKeyPublic: ArrayBuffer;
    signedPreKeySignature: ArrayBuffer;
    identityKey: ArrayBuffer;
}
```

## 💾 State Management

An established session encapsulates a lot of state between two clients. That state is maintained in durable records which need to be kept for the life of the session.

State is kept in the following places:

- **Identity State**: Clients maintain their own identity key pair and identity keys from other clients
- **PreKey State**: Clients maintain the state of their generated PreKeys
- **Signed PreKey States**: Clients maintain the state of their signed PreKeys  
- **Session State**: Clients maintain the state of established sessions

```typescript
interface SignalProtocolStore {
    // Identity management
    getIdentityKeyPair(): Promise<KeyPair>;
    getLocalRegistrationId(): Promise<number>;
    saveIdentity(name: string, identityKey: ArrayBuffer): Promise<boolean>;
    isTrustedIdentity(name: string, identityKey: ArrayBuffer, direction: Direction): Promise<boolean>;
    
    // PreKey management
    loadPreKey(keyId: number): Promise<KeyPair | undefined>;
    storePreKey(keyId: number, keyPair: KeyPair): Promise<void>;
    removePreKey(keyId: number): Promise<void>;
    
    // Session management
    loadSession(identifier: string): Promise<SessionRecord | undefined>;
    storeSession(identifier: string, record: SessionRecord): Promise<void>;
    removeSession(identifier: string): Promise<void>;
}
```

## 🏗️ Project Structure

```
📦libsignal
 ┣ 📂src
 ┃ ┣ 📂constants      # Protocol constants and enums
 ┃ ┣ 📂crypto         # Cryptographic operations
 ┃ ┣ 📂protocol       # Core protocol implementation
 ┃ ┣ 📂types          # TypeScript type definitions
 ┃ ┣ 📂utils          # Utility functions and helpers
 ┃ ┣ 📂whisper        # Protocol buffer definitions
 ┃ ┗ 📜index.ts       # Main entry point
 ┣ 📂dist             # Compiled JavaScript output
 ┣ 📜tsconfig.json    # TypeScript configuration
 ┗ 📜package.json     # Package configuration
```

## 🔧 Development

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

## 📄 API Reference

### Core Classes

- `SessionBuilder` - Establishes encrypted sessions between clients
- `SessionCipher` - Encrypts and decrypts messages within sessions
- `ProtocolAddress` - Represents a unique client address
- `SessionRecord` - Maintains session state and history

### Utilities

- `keyhelper` - Key generation utilities
- `crypto` - Low-level cryptographic functions
- `curve` - Elliptic curve operations
- `errors` - Typed error classes

### Types

All classes and functions include comprehensive TypeScript definitions for enhanced development experience.

## 🔒 Security

This implementation maintains the same security properties as the original Signal Protocol:

- **Forward Secrecy**: Past communications remain secure even if keys are compromised
- **Future Secrecy**: Future communications remain secure after key compromise
- **Deniability**: Messages cannot be cryptographically proven to have come from a specific sender

## 📜 License

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

* Copyright 2015-2016 Open Whisper Systems
* Copyright 2017-2018 Forsta Inc
* Copyright 2023-2024 Raphael Serafim - TypeScript Migration

## 🤝 Contributing

Contributions are welcome! Please ensure all code follows TypeScript best practices and includes appropriate type definitions.

## 📞 Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/raphaelvserafim/libsignal).