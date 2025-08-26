import { decode, encode } from 'npm:cborg@~4.2.14'
import {
  base64ToUint8Array as _base64ToUint8Array,
  isUint8Array,
  stringToUint8Array as _stringToUint8Array,
  toUint8Array as _toUint8Array,
  type TypedArray,
  uint8ArrayToBase64 as _uint8ArrayToBase64,
} from 'npm:uint8array-extras@^1.5.0'

export type SealOptions = { iterations?: number; aad?: Record<string, unknown> }
type StringOrBuffer = string | TypedArray | ArrayBuffer | DataView
type V1 = { v: 1; it: number; s: Uint8Array; iv: Uint8Array; ct: Uint8Array; w: Uint8Array }

/**
 * Derive a CryptoKey from the password for deriving KEKs.
 * @param password - The password to derive the key from.
 * @returns A promise that resolves to the derived CryptoKey.
 */
export async function keyFromPassword(password: string): Promise<CryptoKey> {
  const pw = toUint8Array(password)
  try {
    return await crypto.subtle.importKey(
      'raw',
      pw,
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    )
  } finally {
    pw.fill(0)
  }
}

/**
 * Seal (encrypt and wrap) data.
 * @param key - A CryptoKey to derive the KEK for wrapping the DEK.
 * @param data - The data to seal (encrypt and wrap).
 * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000) and additional authenticated data (AAD).
 * @returns A promise that resolves to the sealed data.
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
  const meta = { v: 1, it, s: salt }

  const aad = encode({ ...options?.aad, ...meta })
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    dek,
    encode(data),
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

  return toBase64(encode({ ...meta, iv, ct, w: wrappedDek }))
}

/**
 * Unseal (decrypt and unwrap) data.
 * @param key - A CryptoKey to derive the KEK for unwrapping the DEK.
 * @param data - The sealed data.
 * @param options - Options for unsealing, including additional authenticated data (AAD).
 * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
 */
export async function unseal(
  key: CryptoKey,
  data: string,
  options?: SealOptions,
): Promise<unknown> {
  try {
    const parsed = decode(toUint8Array(data, 'base64'))
    if (!validateV1(parsed)) throw new Error('Invalid payload format')
    const { v, it, s, iv, ct, w } = parsed

    const kek = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: s, iterations: it, hash: 'SHA-256' },
      key,
      { name: 'AES-KW', length: 256 },
      false,
      ['unwrapKey'],
    )

    const dek = await crypto.subtle.unwrapKey(
      'raw',
      w,
      kek,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )

    const aad = encode({ ...options?.aad, v, it, s })
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      dek,
      ct,
    )

    return decode(toUint8Array(pt))
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

  constructor(baseKey: CryptoKey, options?: SealOptions) {
    this.#baseKey = baseKey
    this.#options = options
  }

  /**
   * Create a CryptoManager instance from a password.
   * @param password - The password to derive the key from.
   * @returns A promise that resolves to a CryptoManager instance.
   */
  static async fromPassword(password: string, options?: SealOptions): Promise<CryptoManager> {
    return new CryptoManager(await keyFromPassword(password), options)
  }

  /**
   * Seal (encrypt and wrap) data using the CryptoManager's base key.
   * @param data - The data to seal (encrypt and wrap).
   * @param options - Options for sealing, including the number of PBKDF2 iterations (default: 600,000) and additional authenticated data (AAD).
   * @returns A promise that resolves to the sealed data.
   */
  seal(data: unknown, options?: SealOptions): Promise<string> {
    return seal(this.#baseKey, data, { ...this.#options, ...options })
  }

  /**
   * Unseal (decrypt and unwrap) data using the CryptoManager's base key.
   * @param data - The sealed data.
   * @param options - Options for unsealing, including additional authenticated data (AAD).
   * @returns A promise that resolves to the unsealed (decrypted and unwrapped) data, or undefined if unsealing fails.
   */
  unseal(data: string, options?: SealOptions): Promise<unknown> {
    return unseal(this.#baseKey, data, { ...this.#options, ...options })
  }
}

/** @internal */
function validateV1(data: unknown): data is V1 {
  if (!data || typeof data !== 'object') return false
  // deno-lint-ignore no-explicit-any
  const d = data as any
  if (d.v !== 1) return false
  if (!Number.isSafeInteger(d.it) || d.it < 1 || d.it > 2_000_000) return false
  if (!isUint8Array(d.s) || d.s.byteLength !== 16) return false
  if (!isUint8Array(d.iv) || d.iv.byteLength !== 12) return false
  if (!isUint8Array(d.w) || d.w.byteLength !== 40) return false
  if (!isUint8Array(d.ct) || d.ct.byteLength < 16) return false
  return true
}

/** @internal */
export function toUint8Array(input: StringOrBuffer, fromEncoding?: 'base64'): Uint8Array {
  if (typeof input !== 'string') return _toUint8Array(input)
  if (fromEncoding === 'base64') return _base64ToUint8Array(input)
  return _stringToUint8Array(input)
}

/** @internal */
export function toBase64(input: StringOrBuffer): string {
  return _uint8ArrayToBase64(toUint8Array(input), { urlSafe: true })
}
