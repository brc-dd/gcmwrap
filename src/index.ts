import {
  stringToUint8Array,
  toUint8Array,
  uint8ArrayToBase64,
  uint8ArrayToString,
} from 'npm:uint8array-extras@1.5.0'

export class CryptoManager {
  #baseKey!: CryptoKey

  static async fromPassword(password: string | Uint8Array) {
    const bytes = typeof password === 'string' ? stringToUint8Array(password) : password.slice()
    const baseKey = await crypto.subtle.importKey(
      'raw',
      bytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey'],
    )

    bytes.fill(0)

    const cm = new CryptoManager()
    cm.#baseKey = baseKey
    return cm
  }

  destroy() {
    this.#baseKey = undefined as unknown as CryptoKey
  }

  async seal(data: unknown, { iterations = 600_000 }: { iterations?: number } = {}) {
    this.#ensureReady()

    const dek = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const bytes = stringToUint8Array(JSON.stringify(data))
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      dek,
      bytes,
    )

    const salt = crypto.getRandomValues(new Uint8Array(16))
    const kek = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      this.#baseKey,
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

    const payload = {
      v: 1,
      it: iterations,
      s: uint8ArrayToBase64(salt),
      iv: uint8ArrayToBase64(iv),
      w: uint8ArrayToBase64(toUint8Array(wrappedDek)),
      ct: uint8ArrayToBase64(toUint8Array(ct)),
    }
    return JSON.stringify(payload)
  }

  async unseal(payload: string) {
    this.#ensureReady()

    const { v, it, s, iv, w, ct } = JSON.parse(payload)
    if (v !== 1) {
      throw new Error('Unsupported payload version')
    }
    if (typeof it !== 'number' || it < 1) {
      throw new Error('Invalid iteration count')
    }
    if (
      typeof s !== 'string' || typeof iv !== 'string' || typeof w !== 'string' ||
      typeof ct !== 'string'
    ) {
      throw new Error('Invalid payload format')
    }

    const salt = stringToUint8Array(s)
    const kek = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: it >>> 0, hash: 'SHA-256' },
      this.#baseKey,
      { name: 'AES-KW', length: 256 },
      false,
      ['wrapKey', 'unwrapKey'],
    )

    const wrappedDek = stringToUint8Array(w)
    const dek = await crypto.subtle.unwrapKey(
      'raw',
      wrappedDek,
      kek,
      { name: 'AES-KW' },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )

    const ciphertext = stringToUint8Array(ct)
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: stringToUint8Array(iv), tagLength: 128 },
      dek,
      ciphertext,
    )

    return JSON.parse(uint8ArrayToString(plaintext))
  }

  #ensureReady() {
    if (!this.#baseKey) {
      throw new Error('CryptoManager is not initialized or has been destroyed.')
    }
  }
}
