import {
  base64ToUint8Array as _base64ToUint8Array,
  uint8ArrayToBase64 as _uint8ArrayToBase64,
} from 'npm:uint8array-extras@^1.5.0'
import { isJson } from './utils.ts'

const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: true })

const v = 1
const header = toBase64(Uint8Array.of(v))

const fakeDekPromise = crypto.subtle.importKey(
  'raw',
  new Uint8Array(32),
  { name: 'AES-GCM', length: 256 },
  false,
  ['decrypt'],
)

/**
 * Options for customizing the sealing and unsealing process.
 */
export interface SealOptions {
  /**
   * Additional Associated Data (AAD) to be authenticated but not encrypted.
   * This can be used to bind the ciphertext to a specific context.
   */
  aad?: Record<string, unknown>
  /**
   * The number of iterations to use for the PBKDF2 key derivation function.
   * A higher number increases security but also increases the time it takes to seal/unseal.
   * @default 600_000
   */
  iterations?: number
  /**
   * A function to encode the input data into a Uint8Array before encryption.
   * @default // A function that handles JSON-serializable data.
   */
  encode?: (data: unknown) => Uint8Array
  /**
   * A function to decode a Uint8Array back into the original data format after decryption.
   * @default // A function that parses a UTF-8 string as JSON.
   */
  decode?: (data: Uint8Array) => unknown
}

/**
 * Represents the structure of the version 1 sealed data payload.
 */
export interface SealedV1 {
  /** The version identifier (always 1 for this version). */
  v: 1
  /** The 16-byte salt used for PBKDF2 key derivation. */
  s: Uint8Array
  /** The 12-byte initialization vector (IV) used for AES-GCM encryption. */
  iv: Uint8Array
  /** The 40-byte wrapped (encrypted) Data Encryption Key (DEK). */
  w: Uint8Array
  /** The ciphertext (encrypted data). */
  ct: Uint8Array
}

/**
 * Default options for the seal and unseal operations.
 */
export const defaults: Readonly<Required<Omit<SealOptions, 'aad'>>> = Object.freeze({
  iterations: 600_000,
  encode(data) {
    if (!isJson(data)) throw new TypeError('Data is not JSON-serializable.')
    return enc.encode(JSON.stringify(data))
  },
  decode(data) {
    return JSON.parse(dec.decode(data))
  },
})

/**
 * Generates a `CryptoKey` from a password string for use in key derivation.
 * The key is suitable for use with PBKDF2.
 *
 * @param password The password to derive the key from.
 * @returns A promise that resolves to a `CryptoKey`.
 */
export async function generateKey(password: string): Promise<CryptoKey> {
  const pw = enc.encode(password)
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
 * Encrypts and authenticates data using a password-derived key.
 * This process uses a Key-Wrapping mechanism (AES-KW) with a Data Encryption Key (DEK)
 * and AES-GCM for the actual encryption.
 *
 * @param key The master `CryptoKey` derived from a password, used as a Key Encryption Key (KEK).
 * @param data The data to be encrypted. Must be serializable by the `encode` function.
 * @param options Optional settings to customize the sealing process.
 * @returns A promise that resolves to a base64url-encoded string representing the sealed data.
 */
export async function seal(
  key: CryptoKey,
  data: unknown,
  {
    aad: custom,
    iterations: it = defaults.iterations,
    encode = defaults.encode,
  }: SealOptions = {},
): Promise<string> {
  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  )

  const s = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aad = encode({ v, it, s, custom })

  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    dek,
    encode(data),
  )

  const kek = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: s, iterations: it, hash: 'SHA-256' },
    key,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey'],
  )

  const w = await crypto.subtle.wrapKey(
    'raw',
    dek,
    kek,
    { name: 'AES-KW' },
  )

  return `${header}.${toBase64(s)}.${toBase64(iv)}.` +
    `${toBase64(new Uint8Array(w))}.${toBase64(new Uint8Array(ct))}`
}

/**
 * Decrypts and authenticates data that was sealed with the `seal` function.
 * It performs the operations in reverse, unwrapping the DEK and then decrypting the ciphertext.
 * This function is time-safe; it takes a similar amount of time to execute whether
 * the decryption is successful or not, which helps prevent timing attacks.
 *
 * @param key The master `CryptoKey` that was used to seal the data.
 * @param sealed The base64url-encoded string from the `seal` function.
 * @param options Optional settings to customize the unsealing process. Must match the options used for sealing.
 * @returns A promise that resolves with the decrypted data, or `undefined` if decryption or authentication fails for any reason.
 */
export async function unseal(
  key: CryptoKey,
  sealed: string,
  {
    aad: custom,
    iterations: it = defaults.iterations,
    encode = defaults.encode,
    decode = defaults.decode,
  }: SealOptions = {},
): Promise<unknown> {
  try {
    const {
      s = new Uint8Array(16),
      iv = new Uint8Array(12),
      w = new Uint8Array(40),
      ct = new Uint8Array(16),
      ok: ok,
    } = parseSealedV1(sealed)

    let isValid = ok
    const aad = encode({ v: 1, it, s, custom })

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
    ).catch(() => {
      isValid = false
      return fakeDekPromise
    })

    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
      dek,
      ct,
    ).catch(() => {
      isValid = false
      return new ArrayBuffer(0)
    })

    const data = decode(new Uint8Array(pt))
    return isValid ? data : undefined
  } catch {
    return undefined
  }
}

/**
 * A manager class that encapsulates a base key and provides convenience methods
 * for sealing and unsealing data.
 */
export class CryptoManager {
  #baseKey: CryptoKey
  #options?: SealOptions

  /**
   * Creates a new CryptoManager instance with a pre-existing CryptoKey.
   * @param baseKey The master `CryptoKey` to be used for all operations.
   * @param options Default `SealOptions` to apply to all seal/unseal operations.
   */
  constructor(baseKey: CryptoKey, options?: SealOptions) {
    this.#baseKey = baseKey
    this.#options = options
  }

  /**
   * Creates a new `CryptoManager` instance by deriving a key from a password.
   *
   * @param password The password to generate the key from.
   * @param options Default `SealOptions` to apply to all seal/unseal operations.
   * @returns A promise that resolves to a new `CryptoManager` instance.
   */
  static async fromPassword(password: string, options?: SealOptions): Promise<CryptoManager> {
    return new CryptoManager(await generateKey(password), options)
  }

  /**
   * Seals data using the manager's internal base key and default options.
   *
   * @param data The data to seal.
   * @param options Options to override the manager's default seal options for this operation.
   * @returns A promise that resolves to the sealed data string.
   */
  seal(data: unknown, options?: SealOptions): Promise<string> {
    return seal(this.#baseKey, data, { ...this.#options, ...options })
  }

  /**
   * Unseals data using the manager's internal base key and default options.
   *
   * @param data The sealed data string to unseal.
   * @param options Options to override the manager's default unseal options for this operation.
   * @returns A promise that resolves with the decrypted data, or `undefined` on failure.
   */
  unseal(data: string, options?: SealOptions): Promise<unknown> {
    return unseal(this.#baseKey, data, { ...this.#options, ...options })
  }
}

function toBase64(u8: Uint8Array): string {
  return _uint8ArrayToBase64(u8, { urlSafe: true })
}

function fromBase64(b64: string): Uint8Array | undefined {
  try {
    return _base64ToUint8Array(b64)
  } catch {
    return undefined
  }
}

function parseSealedV1(sealed: string): Partial<SealedV1> & { ok: boolean } {
  try {
    if (sealed.length > 5 * 1024 * 1024) return { ok: false }
    const parts = sealed.split('.')
    if (parts.length !== 5) return { ok: false }
    const [ver, s, iv, w, ct] = parts.map(fromBase64)
    let ok = true
    ok &&= ver?.byteLength === 1 && ver[0] === v
    ok &&= s?.byteLength === 16
    ok &&= iv?.byteLength === 12
    ok &&= w?.byteLength === 40
    ok &&= !!ct && ct.byteLength >= 16
    return { v, s, iv, w, ct, ok }
  } catch {
    return { ok: false }
  }
}
