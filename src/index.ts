import {
  base64ToUint8Array as _base64ToUint8Array,
  stringToUint8Array as _stringToUint8Array,
  toUint8Array as _toUint8Array,
  type TypedArray,
  uint8ArrayToBase64 as _uint8ArrayToBase64,
  uint8ArrayToString,
} from 'npm:uint8array-extras@^1.5.0'

export type StringOrBuffer = string | TypedArray | ArrayBuffer | DataView
export type SealOptions = { iterations?: number; aad?: Record<string, unknown> }

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
 * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000) and additional authenticated data (AAD).
 * @returns A promise that resolves to the sealed data as a JSON string.
 */
export async function seal(
  key: CryptoKey,
  data: unknown,
  options?: SealOptions,
): Promise<string> {
  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const it = options?.iterations ?? 600_000
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const meta = { v: 1, it, s: toBase64(salt) }

  const aad = toUint8Array(JSON.stringify({ ...options?.aad, ...meta }))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    dek,
    toUint8Array(JSON.stringify(data)),
  )

  const kek = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: it, hash: 'SHA-256' },
    key,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey'],
  )

  const wrappedDek = await crypto.subtle.wrapKey(
    'raw',
    dek,
    kek,
    { name: 'AES-KW' },
  )

  return JSON.stringify({
    ...meta,
    iv: toBase64(iv),
    ct: toBase64(ct),
    w: toBase64(wrappedDek),
  })
}

/**
 * Unseal (decrypt and unwrap) data using a CryptoKey derived from a password.
 * @param key - A CryptoKey derived from a password using PBKDF2.
 * @param data - The sealed data as a JSON string.
 * @param options - Options for unsealing, including additional authenticated data (AAD).
 * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
 */
export async function unseal(
  key: CryptoKey,
  data: string,
  options?: SealOptions,
): Promise<unknown> {
  try {
    const { v, ct, it, iv, s, w } = JSON.parse(data)
    if (
      v !== 1 ||
      typeof ct !== 'string' ||
      it !== (it | 0) || it < 1 || it > 2_147_483_647 ||
      typeof iv !== 'string' ||
      typeof s !== 'string' ||
      typeof w !== 'string'
    ) throw new Error('Invalid payload format')

    const kek = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: toUint8Array(s, 'base64'), iterations: it, hash: 'SHA-256' },
      key,
      { name: 'AES-KW', length: 256 },
      false,
      ['unwrapKey'],
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

    const aad = toUint8Array(JSON.stringify({ ...options?.aad, v, it, s }))
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toUint8Array(iv, 'base64'), additionalData: aad, tagLength: 128 },
      dek,
      toUint8Array(ct, 'base64'),
    )

    return JSON.parse(uint8ArrayToString(pt))
  } catch {
    // FIXME: side-channel attacks are still possible, maybe add jitter?
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
  #options?: SealOptions

  constructor(
    baseKey: CryptoKey,
    options?: SealOptions,
  ) {
    this.#baseKey = baseKey
    this.#options = options
  }

  /**
   * Create a CryptoManager instance from a password.
   * @param password - The password to derive the key from.
   * @returns A promise that resolves to a CryptoManager instance.
   */
  static async fromPassword(
    password: StringOrBuffer,
    options?: SealOptions,
  ): Promise<CryptoManager> {
    return new CryptoManager(await keyFromPassword(password), options)
  }

  /**
   * Seal (encrypt and wrap) data using the CryptoManager's base key.
   * @param data - The data to seal (encrypt and wrap).
   * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000) and additional authenticated data (AAD).
   * @returns A promise that resolves to the sealed data as a JSON string.
   */
  seal(
    data: unknown,
    options?: SealOptions,
  ): Promise<string> {
    return seal(this.#baseKey, data, { ...this.#options, ...options })
  }

  /**
   * Unseal (decrypt and unwrap) data using the CryptoManager's base key.
   * @param data - The sealed data as a JSON string.
   * @param options - Options for unsealing, including additional authenticated data (AAD).
   * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
   */
  unseal(
    data: string,
    options?: SealOptions,
  ): Promise<unknown> {
    return unseal(this.#baseKey, data, { ...this.#options, ...options })
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
