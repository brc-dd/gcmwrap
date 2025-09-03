# GCMWrap

A lightweight and secure JavaScript encryption library offering authenticated encryption with AES-GCM and built-in key wrapping. Built with simplicity and robust security in mind.

## Features

- **Security First**:
  - **Strong Cryptography**: Employs AES-256-GCM for encryption, PBKDF2-SHA256 for password-based key derivation, and AES-KW for key wrapping.
  - **Authenticated Encryption**: Provides both confidentiality and integrity using AES-GCM.
    - **Integrity Protection**: Validates data with AES-GCM's authentication tag to detect tampering.
    - **Context Binding**: Supports Additional Associated Data (AAD) to securely tie ciphertext to a specific context.
  - **Password-Derived Keys**: Safely derives encryption keys from passwords via PBKDF2.
  - **Key Hierarchy**: Implements secure key separation using Key Encryption Keys (KEKs) and Data Encryption Keys (DEKs).
- **Easy-to-Use API**:
  A single, intuitive `CryptoManager` class makes data sealing and unsealing straightforward.
- **Cross-Platform Compatibility**:
  Runs on Deno, Node.js, Bun, and modern browsers, leveraging only the native Web Crypto API and standard builtins.
  ([See compatibility details](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API#browser_compatibility))

## Installation

Install `gcmwrap` with your preferred package manager:

```sh
npm add gcmwrap
pnpm add gcmwrap
yarn add gcmwrap
bun add gcmwrap
deno add npm:gcmwrap
```

Then import it as:

```ts
import { CryptoManager } from 'gcmwrap'
```

### JSR

If you're using JSR, install with one of the following:

```sh
npx jsr add @brc-dd/gcmwrap
pnpx jsr add @brc-dd/gcmwrap
yarn dlx jsr add @brc-dd/gcmwrap
bunx jsr add @brc-dd/gcmwrap
deno add @brc-dd/gcmwrap
```

And import via:

```ts
import { CryptoManager } from '@brc-dd/gcmwrap'
```

### Browser

For direct browser use, you can import from `esm.sh`:

```ts
import { CryptoManager } from 'https://esm.sh/gcmwrap@1'
```

## Usage

The recommended entry point for `gcmwrap` is the `CryptoManager` class, which
takes care of key derivation, encryption, authentication, and key wrapping for
you.

### Basic Example

```ts
import { CryptoManager } from 'gcmwrap'

const password = 'a-very-strong-and-secret-password'
const secret = { message: 'This is top secret!' }

// Create a manager instance from a password
const manager = await CryptoManager.fromPassword(password)

// Seal (encrypt and authenticate) the data
const sealed = await manager.seal(secret)
console.log('Sealed data:', sealed)

// Unseal (decrypt and verify) the data
const unsealed = await manager.unseal(sealed)

if (unsealed) {
  console.log('Unsealed successfully:', unsealed)
} else {
  console.error('Failed to unseal. Wrong password or corrupted data.')
}
```

### Advanced Usage with AAD

You can use Additional Associated Data (AAD) to bind the encrypted data to its context. This data is authenticated but not encrypted. If the AAD doesn't match during unsealing, the operation will fail.

```ts
import { CryptoManager } from 'gcmwrap'

const password = 'another-strong-password'
const report = { content: 'Confidential quarterly report' }

// This context data will be authenticated along with the ciphertext
const aad = { documentId: 'doc-xyz-789', version: 2 }

const manager = await CryptoManager.fromPassword(password)

// Seal the data with the AAD
const sealed = await manager.seal(report, { aad })
console.log('Sealed with AAD:', sealed)

// Unsealing MUST be done with the exact same AAD
const unsealed = await manager.unseal(sealed, { aad })
console.log('Unsealed:', unsealed) // { content: '...' }

// If you try to unseal with different AAD, it will fail
const tampered = await manager.unseal(sealed, { aad: { documentId: 'doc-abc-123' } })
console.log('Unseal attempt with wrong AAD:', tampered) // undefined
```

## API Reference

See [docs](https://www.jsdocs.io/package/gcmwrap).

## Security

`gcmwrap` is designed with security as the top priority. It implements a **Key Encapsulation Mechanism (KEM)** to protect your data.

1. **Key Derivation**: Your password is never used directly as an encryption key. Instead, it's combined with a unique, cryptographically random **16-byte salt** and stretched using **PBKDF2 with 600,000 iterations** of SHA-256. This produces a strong **Key Encryption Key (KEK)** and makes brute-force attacks on the password computationally expensive.

2. **Key Wrapping**: For each `seal` operation, a new, ephemeral **Data Encryption Key (DEK)** is generated. This DEK is used to encrypt your data. The DEK is then "wrapped" (encrypted) by the KEK using **AES-KW (Key Wrap)**.

3. **Authenticated Encryption**: Your actual data is encrypted using **AES-256-GCM**, an Authenticated Encryption with Associated Data (AEAD) cipher. This provides both confidentiality (encryption) and integrity/authenticity (an authentication tag that detects tampering).

The final sealed output is a dot-separated string containing the version, salt, IV, wrapped DEK, and the ciphertext, all encoded in URL-safe Base64:

```txt
[version].[salt].[iv].[wrapped_key].[ciphertext]
```

This library is built specifically for **client-side encryption in web applications**, unlike my earlier project [iron-webcrypto](https://github.com/brc-dd/iron-webcrypto), which did not focus on that use case.

It is especially useful for **offline applications** where data needs to be encrypted with a user-supplied password and stored locally (e.g., in Local Storage or IndexedDB). With this approach:

- Even if an attacker gains access to the sealed data, they cannot decrypt it without the correct password.
- Each sealed payload is protected by a **unique Data Encryption Key (DEK)**. This means that even if one blob was somehow brute-forced, the compromised key would not help in decrypting any other encrypted blobs.

## Credits

This library isn't directly based on this series, but it uses a similar approach: [Client-Side Encryption for Web Apps](https://www.einenlum.com/articles/client-side-encryption-for-web-apps-1). It's a good read but I found it after finishing the initial version of this project.

## Sponsors

<p align="center">
  <a href="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg">
    <img alt="brc-dd's sponsors" src="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg" />
  </a>
</p>
