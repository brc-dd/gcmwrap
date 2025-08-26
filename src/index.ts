import {
  base64ToUint8Array as _base64ToUint8Array,
  stringToUint8Array as _stringToUint8Array,
  toUint8Array as _toUint8Array,
  type TypedArray,
  uint8ArrayToBase64 as _uint8ArrayToBase64,
  uint8ArrayToString,
} from 'npm:uint8array-extras@^1.5.0'

export type StringOrBuffer = string | TypedArray | ArrayBuffer | DataView

/**
 * Derive a CryptoKey from a password using PBKDF2.
 * @param password - The password to derive the key from.
 * @returns A promise that resolves to the derived CryptoKey.
 */
export function keyFromPassword(password: StringOrBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toUint8Array(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )
}

/**
 * Seal (encrypt and wrap) data using a CryptoKey derived from a password.
 * @param key - A CryptoKey derived from a password using PBKDF2.
 * @param data - The data to seal (encrypt and wrap).
 * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000).
 * @returns A promise that resolves to the sealed data as a JSON string.
 */
export async function seal(
  key: CryptoKey,
  data: unknown,
  options?: { iterations?: number },
): Promise<string> {
  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    dek,
    toUint8Array(JSON.stringify(data)),
  )

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iterations = options?.iterations ?? 600_000
  const kek = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  )

  const wrappedDek = await crypto.subtle.wrapKey(
    'raw',
    dek,
    kek,
    { name: 'AES-KW' },
  )

  return JSON.stringify({
    v: 1,
    ct: toBase64(ct),
    it: iterations,
    iv: toBase64(iv),
    s: toBase64(salt),
    w: toBase64(wrappedDek),
  })
}

/**
 * Unseal (decrypt and unwrap) data using a CryptoKey derived from a password.
 * @param key - A CryptoKey derived from a password using PBKDF2.
 * @param payload - The sealed data as a JSON string.
 * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
 */
export async function unseal(
  key: CryptoKey,
  payload: string,
): Promise<unknown> {
  try {
    const { v, ct, it, iv, s, w } = JSON.parse(payload)
    if (
      v !== 1 ||
      typeof ct !== 'string' ||
      typeof it !== 'number' || !(it > 0) ||
      typeof iv !== 'string' ||
      typeof s !== 'string' ||
      typeof w !== 'string'
    ) throw new Error('Invalid payload format')

    const kek = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: toUint8Array(s, 'base64'), iterations: it >>> 0, hash: 'SHA-256' },
      key,
      { name: 'AES-KW', length: 256 },
      false,
      ['wrapKey', 'unwrapKey'],
    )

    const dek = await crypto.subtle.unwrapKey(
      'raw',
      toUint8Array(w, 'base64'),
      kek,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )

    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toUint8Array(iv, 'base64'), tagLength: 128 },
      dek,
      toUint8Array(ct, 'base64'),
    )

    return JSON.parse(uint8ArrayToString(pt))
  } catch {
    return undefined
  }
}

/**
 * CryptoManager class to manage sealing and unsealing data using a base key derived from a password.
 *
 * @example
 * ```ts
 * const manager = await CryptoManager.fromPassword('my-secret-password')
 * const sealed = await manager.seal({ hello: 'world' })
 * const unsealed = await manager.unseal(sealed)
 * console.log(unsealed) // { hello: 'world' }
 * ```
 */
export class CryptoManager {
  #baseKey: CryptoKey

  constructor(baseKey: CryptoKey) {
    this.#baseKey = baseKey
  }

  /**
   * Create a CryptoManager instance from a password.
   * @param password - The password to derive the key from.
   * @returns A promise that resolves to a CryptoManager instance.
   */
  static async fromPassword(password: StringOrBuffer): Promise<CryptoManager> {
    return new CryptoManager(await keyFromPassword(password))
  }

  /**
   * Seal (encrypt and wrap) data using the CryptoManager's base key.
   * @param data - The data to seal (encrypt and wrap).
   * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000).
   * @returns A promise that resolves to the sealed data as a JSON string.
   */
  seal(data: unknown, options?: { iterations?: number }): Promise<string> {
    return seal(this.#baseKey, data, options)
  }

  /**
   * Unseal (decrypt and unwrap) data using the CryptoManager's base key.
   * @param payload - The sealed data as a JSON string.
   * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
   */
  unseal(payload: string): Promise<unknown> {
    return unseal(this.#baseKey, payload)
  }
}

/** @internal */
function toUint8Array(input: StringOrBuffer, fromEncoding?: 'base64'): Uint8Array {
  if (typeof input !== 'string') return _toUint8Array(input)
  if (fromEncoding === 'base64') return _base64ToUint8Array(input)
  return _stringToUint8Array(input)
}

/** @internal */
function toBase64(input: StringOrBuffer): string {
  return _uint8ArrayToBase64(toUint8Array(input))
}
