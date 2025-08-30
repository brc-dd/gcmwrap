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

export interface SealOptions {
  aad?: Record<string, unknown>
  iterations?: number
  encode?: (data: unknown) => Uint8Array
  decode?: (data: Uint8Array) => unknown
}

export interface SealedV1 {
  v: 1
  s: Uint8Array
  iv: Uint8Array
  w: Uint8Array
  ct: Uint8Array
}

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
