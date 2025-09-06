# GCMWrap

A lightweight and secure JavaScript encryption library offering authenticated encryption with AES-GCM and built-in key wrapping. Built with simplicity and robust security in mind.

## Features

- **Security First**:
  - **Strong Cryptography**: Employs AES-256-GCM for encryption, PBKDF2-SHA256 for password-based key derivation, and AES-KW for key wrapping.
  - **Authenticated Encryption**: Provides both confidentiality and integrity using AES-GCM.
    - **Integrity Protection**: Validates data with AES-GCM's authentication tag to detect tampering.
    - **Context Binding**: Supports AAD to securely tie ciphertext to a specific context.
  - **Password-Derived Keys**: Safely derives encryption keys from passwords via PBKDF2.
  - **Key Hierarchy**: Implements secure key separation using Key Encryption Keys (KEKs) and Data Encryption Keys (DEKs).
- **Easy-to-Use API**: A single, intuitive `CryptoManager` class makes data sealing and unsealing straightforward.
- **Cross-Platform Compatibility**: Runs on Deno, Node.js, Bun, and modern browsers, leveraging only the native Web Crypto API and standard builtins. See [compatibility details](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API#browser_compatibility).

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

### Browser

For direct browser use, you can import from `esm.sh`:

```ts
import { CryptoManager } from 'https://esm.sh/gcmwrap@1'
```

## Quick Start

The recommended entry point for `gcmwrap` is the `CryptoManager` class, which takes care of key derivation, encryption, authentication, and key wrapping for you.

```ts
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

## API Reference

See [docs](https://www.jsdocs.io/package/gcmwrap).

## Advanced Usage

### Additional Authenticated Data (AAD)

You can use AAD to bind the encrypted data to its context. This data is authenticated but not encrypted. If the AAD doesn't match during unsealing, the operation will fail.

```ts
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
const unsealed2 = await manager.unseal(sealed, { aad: { documentId: 'doc-abc-123' } })
console.log('Unseal attempt with wrong AAD:', unsealed2) // undefined
```

> [!IMPORTANT]
> AAD must serialize to the exact same byte sequence during both sealing and unsealing. With the default `JSON.stringify`, even differences in object key order will cause verification to fail. To avoid this, you can provide custom `encode` and `decode` functions that ensure consistent serialization.

### Custom Encoding/Decoding

> [!NOTE]
> The same encoder is also applied to your data before sealing, not just AAD. You must make sure the chosen encoder/decoder preserves your data correctly:
>
> - The default encoder uses `JSON.stringify` and performs a pre-check to verify the data can be losslessly round-tripped (encoded and then decoded without change).
> - Other encoders like CBOR or MessagePack may silently drop unsupported types without throwing an error, which could lead to data loss on unseal.

#### Example with CBOR

```ts
import { decode, encode } from 'cbor2'

const password = 'custom-encoding-password'
const data = { info: 'Using CBOR for encoding' }

const manager = await CryptoManager.fromPassword(password, {
  encode: (data) => encode(data, { cde: true }),
  decode: (bytes) => decode(bytes, { cde: true }),
})

const aad = { user: 'alice', userId: 42 }
const sealed = await manager.seal(data, { aad })

// Even though the key order differs, CDE ensures deterministic encoding
const aad2 = { userId: 42, user: 'alice' }
const unsealed = await manager.unseal(sealed, { aad: aad2 })

console.log('Unsealed with custom encoding:', unsealed) // { info: '...' }
```

Alternative:

```ts
import { decode, encode } from 'cborg'

const manager = await CryptoManager.fromPassword(password, { encode, decode })
```

#### Example with MessagePack

```ts
import { decode, encode } from '@msgpack/msgpack'

const manager = await CryptoManager.fromPassword(password, {
  encode: (data) => encode(data, { sortKeys: true }),
  decode,
})
```

### Custom Iteration Count

You can tune PBKDF2 iterations when creating the manager. For example, to set 1M iterations (default is 600K):

```ts
import { CryptoManager } from 'gcmwrap'

const manager = await CryptoManager.fromPassword(password, {
  iterations: 1_000_000,
})
```

### App-Level Versioning

You may want to evolve parameters (e.g., iteration count) over time while keeping old data readable. A common pattern is to prefix the sealed token with a version (not secret), bind that version in AAD, and override options per call using method-level options (which merge with instance options).

```ts
const manager = await CryptoManager.fromPassword(password, {
  iterations: 1_000_000, // default for new data
})

const v = 2 // current app version

async function seal(data: unknown) {
  return `${v}.${await manager.seal(data, { aad: { v } })}` // bind version in AAD
}

function unseal(sealed: string) {
  const [ver, ...rest] = sealed.split('.')
  const payload = rest.join('.')

  if (ver === '1') {
    // Old version with fewer iterations
    return manager.unseal(payload, { aad: { v: 1 }, iterations: 600_000 })
  }

  if (ver === '2') {
    // Current version (default params)
    return manager.unseal(payload, { aad: { v: 2 } })
  }

  // Unknown version
  return undefined

  // Alternatively, fall back for unprefixed legacy tokens:
  // return manager.unseal(sealed, { iterations: 600_000 })
}
```

### Lower-Level API

If you don't want to use the `CryptoManager` class, you can use these functions directly. They have a similar API as the methods on `CryptoManager` but require you to pass the KEK as the first argument.

```ts
import { generateKey, seal, unseal } from 'gcmwrap'

const key = await generateKey(password) // derive KEK from password
const sealed = await seal(key, secret) // seal data with KEK
const unsealed = await unseal(key, sealed) // unseal data with KEK
```

## How It Works

`gcmwrap` is designed with security as the top priority. It implements a **Key Encapsulation Mechanism (KEM)** to protect your data.

1. **Key Derivation**: Your password is never used directly as an encryption key. Instead, it's combined with a unique, cryptographically random **16-byte salt** and stretched using **PBKDF2 with 600,000 iterations** of SHA-256. This produces a strong **Key Encryption Key (KEK)** and makes brute-force attacks on the password computationally expensive.

2. **Key Wrapping**: For each `seal` operation, a new, ephemeral **Data Encryption Key (DEK)** is generated. This DEK is used to encrypt your data. The DEK is then "wrapped" (encrypted) by the KEK using **AES-KW**.

3. **Authenticated Encryption**: Your actual data is encrypted using **AES-256-GCM**, an Authenticated Encryption with Associated Data (AEAD) cipher. This provides both confidentiality and integrity.

### Data Format

The final sealed output is a dot-separated string containing the version, salt, IV, wrapped DEK, and the ciphertext, all encoded in URL-safe Base64:

```txt
[version].[salt].[iv].[wrapped_key].[ciphertext]
```

- **Version**: Indicates the format version (currently `1`).
- **Salt**: The random salt used for PBKDF2 (16 bytes).
- **IV**: The random initialization vector for AES-GCM (12 bytes).
- **Wrapped Key**: The DEK encrypted with the KEK (40 bytes).
- **Ciphertext**: The encrypted data along with the authentication tag.

### Error Handling

`unseal` returns `undefined` if any error occurs. This is to avoid leaking information about what went wrong (e.g., whether the password was incorrect or the data was tampered with). Treat `undefined` as a hard failure and do not reuse any partial state from the failed attempt.

## Use Cases

This library is built specifically for client-side encryption in web applications, unlike my earlier project [iron-webcrypto](https://github.com/brc-dd/iron-webcrypto), which did not focus on that use case.

It is especially useful for offline applications where data needs to be encrypted with a user-supplied password and stored locally (e.g., in Local Storage or IndexedDB). With this approach:

- Even if an attacker gains access to the sealed data, they cannot decrypt it without the correct password.
- Each sealed payload is protected by a unique Data Encryption Key (DEK). This means that even if one blob was somehow brute-forced, the compromised key would not help in decrypting any other encrypted blobs.

## Security Considerations

Most cryptographic failures stem from misuse of primitives, not from weaknesses in the algorithms themselves. Keep the following in mind when using this library:

### Passwords and Key Derivation

- **Password Strength**: Encryption is only as strong as the password chosen. Always use strong, high-entropy passwords.
- **Iteration Count**: By default, PBKDF2 runs with 600,000 iterations - a balance between security and performance. You may raise this for stronger protection, but higher counts will slow down key derivation.
- **Avoid Unbounded Parameters**: Never use unbounded or excessively large iteration counts (or similar parameters). They may cause denial-of-service conditions by making legitimate operations impractically slow or consuming excessive resources.

### Usage Guidelines

- **Not for Password Storage**: Do **not** use this library to encrypt or store user passwords. Instead, rely on established authentication flows and server-side, one-way hashing with a modern KDF such as Argon2.
- **Runtime Environment**: This library builds on the Web Crypto API, which is considered secure. Make sure your environment (browser, Node.js, etc.) is up-to-date and not compromised.

### Memory Safety

- JavaScript does not provide guarantees about clearing sensitive data from memory. Secrets such as plaintext passwords may remain in memory longer than intended. For high-sensitivity use cases, consider secure runtimes, native modules, or languages that support explicit memory management and stronger isolation.

### A Note from MDN

From [MDN's Web Crypto API documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API):

> The Web Crypto API provides a number of low-level cryptographic primitives. It's very easy to misuse them, and the pitfalls involved can be very subtle.
>
> Even assuming you use the basic cryptographic functions correctly, secure key management and overall security system design are extremely hard to get right, and are generally the domain of specialist security experts.
>
> Errors in security system design and implementation can make the security of the system completely ineffective.

## Performance Tips

- **Derive once, reuse**: Create a `CryptoManager` instance per password and reuse it for multiple `seal`/`unseal` operations to amortize PBKDF2 cost.
- **Batch work**: If you must process many items, derive once, then parallelize `seal`/`unseal` calls using `Promise.all`.
- **Persist tokens, not keys**: Store only sealed tokens (e.g., in IndexedDB/localStorage). Never persist raw keys or passwords.

## FAQs

- **Why PBKDF2 and not Argon2/script?**\
  The Web Crypto API does not support Argon2 or scrypt (<https://github.com/WICG/proposals/issues/59>). PBKDF2 with a high iteration count is a reasonable alternative for password-based key derivation in this context. If/when Argon2 becomes available natively, future versions could support it.
- **What does AAD actually protect?**\
  AAD is included in the authentication tag of AES-GCM. This means that if the AAD is altered or does not match during unsealing, the decryption will fail. It effectively binds the ciphertext to its context, preventing certain types of attacks where an attacker might try to reuse ciphertext in a different context.
- **Can I change the encoder later?**\
  Yes, but treat it like a format change. Either re-seal existing data with the new encoder or maintain versioning in your application to handle different encodings.

## Credits

This library isn't directly based on this series, but it uses a similar approach: [Client-Side Encryption for Web Apps](https://www.einenlum.com/articles/client-side-encryption-for-web-apps-1). It's a good read but I found it after finishing the initial version of this project.

## Sponsors

<p align="center">
  <a href="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg">
    <img alt="brc-dd's sponsors" src="https://cdn.jsdelivr.net/gh/brc-dd/static/sponsors.svg" />
  </a>
</p>
