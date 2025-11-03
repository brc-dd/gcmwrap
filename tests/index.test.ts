import { decode as msgpackdecode, encode as msgpackencode } from '@msgpack/msgpack'
import { assert, assertEquals, assertNotEquals, assertRejects } from '@std/assert'
import { decode as cbor2decode, encode as cbor2encode } from 'cbor2'
import { decode as cborgdecode, encode as cborgencode } from 'cborg'
import { describe, it } from 'cross-bdd'
import { CryptoManager, generateKey, seal, unseal } from 'gcmwrap'
import {
  base64ToUint8Array as toUint8Array,
  uint8ArrayToBase64 as toBase64,
} from 'uint8array-extras'

const password = 'correct-horse-battery-staple-secure-password'
const data = { foo: 'bar', num: 42, nested: { a: 1, b: [1, 2, 3] } }
const aad = { context: 'user-session', version: 2 }

describe('CryptoManager', () => {
  describe('seal/unseal roundtrips', async () => {
    const manager = await CryptoManager.fromPassword(password)

    const dataSamples = [
      { description: 'a simple object', data: { a: 1, b: 'hello' } },
      { description: 'a string', data: 'just a simple string' },
      { description: 'a number', data: 12345.6789 },
      { description: 'an array', data: [1, 'two', { three: true }] },
      { description: 'null', data: null },
    ]

    for (const sample of dataSamples) {
      it(`seals and unseals ${sample.description}`, async () => {
        const sealed = await manager.seal(sample.data)
        assert(typeof sealed === 'string' && sealed.length > 0)
        const unsealed = await manager.unseal(sealed)
        assertEquals(unsealed, sample.data)
      })
    }
  })

  it('produces different sealed output for repeated seal calls', async () => {
    const manager = await CryptoManager.fromPassword(password)
    const sealed1 = await manager.seal(data)
    const sealed2 = await manager.seal(data)
    assertNotEquals(sealed1, sealed2)
  })

  it('works across different instances sharing the same password', async () => {
    const manager1 = await CryptoManager.fromPassword(password)
    const manager2 = await CryptoManager.fromPassword(password)
    const sealed = await manager1.seal(data)
    const unsealed = await manager2.unseal(sealed)
    assertEquals(unsealed, data)
  })

  it('fails to unseal with an incorrect password', async () => {
    const manager1 = await CryptoManager.fromPassword(password)
    const manager2 = await CryptoManager.fromPassword('a-completely-different-password')
    const sealed = await manager1.seal(data)
    const unsealed = await manager2.unseal(sealed)
    assertEquals(unsealed, undefined)
  })

  describe('Additional Authenticated Data (AAD)', async () => {
    const managerWithAad = await CryptoManager.fromPassword(password, { aad })
    const managerWithoutAad = await CryptoManager.fromPassword(password)

    it('succeeds with matching AAD', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithAad.unseal(sealed)
      assertEquals(unsealed, data)
    })

    it('fails when AAD is expected but omitted', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithoutAad.unseal(sealed)
      assertEquals(unsealed, undefined)
    })

    it('fails when AAD does not match', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithAad.unseal(sealed, { aad: { context: 'wrong-context' } })
      assertEquals(unsealed, undefined)
    })

    it('merges per-call AAD with instance AAD', async () => {
      const sealed = await managerWithAad.seal(data, { aad: { additional: true } })

      // Fails with only instance AAD
      const unsealedFail = await managerWithAad.unseal(sealed)
      assertEquals(unsealedFail, undefined)

      // Succeeds with merged AAD
      const unsealedSuccess = await managerWithAad.unseal(sealed, { aad: { additional: true } })
      assertEquals(unsealedSuccess, data)
    })

    it('fails when the order of AAD properties changes', async () => {
      const sealed = await managerWithAad.seal(data, { aad: { a: 1, b: 2 } })
      const unsealed = await managerWithAad.unseal(sealed, { aad: { b: 2, a: 1 } })
      assertEquals(unsealed, undefined)
    })
  })

  describe('serialization formats', () => {
    const formats = [
      {
        name: 'CBOR (cbor2 / cde)',
        encode: (data: unknown) => cbor2encode(data, { cde: true }),
        decode: (data: Uint8Array) => cbor2decode(data, { cde: true }),
      },
      {
        name: 'CBOR (cbor2 / dcbor)',
        encode: (data: unknown) => cbor2encode(data, { dcbor: true, rejectUndefined: false }),
        decode: (data: Uint8Array) => cbor2decode(data, { dcbor: true, rejectUndefined: true }),
      },
      {
        name: 'CBOR (cborg)',
        encode: cborgencode,
        decode: cborgdecode,
      },
      {
        name: 'MessagePack',
        encode: (data: unknown) => msgpackencode(data, { sortKeys: true }),
        decode: msgpackdecode,
      },
    ]

    for (const fmt of formats) {
      describe(`with ${fmt.name}`, async () => {
        const manager = await CryptoManager.fromPassword(password, {
          encode: fmt.encode,
          decode: fmt.decode,
        })

        it('seals and unseals data', async () => {
          const sealed = await manager.seal(data)
          const unsealed = await manager.unseal(sealed)
          assertEquals(unsealed, data)
        })

        it('handles AAD', async () => {
          const sealed = await manager.seal(data, { aad })
          const unsealed = await manager.unseal(sealed, { aad })
          assertEquals(unsealed, data)
        })

        it('treats differently ordered AAD keys as equal', async () => {
          const aad1 = { x: 1, y: 2 }
          const aad2 = { y: 2, x: 1 }
          const sealed = await manager.seal(data, { aad: aad1 })
          const unsealed = await manager.unseal(sealed, { aad: aad2 })
          assertEquals(unsealed, data)
        })

        it('rejects incorrect AAD', async () => {
          const sealed = await manager.seal(data, { aad })
          const unsealed = await manager.unseal(sealed, { aad: { context: 'wrong' } })
          assertEquals(unsealed, undefined)
        })

        it('handles additional data types', async () => {
          const complexData = {
            nil: null,
            integer: 1,
            float: Math.PI,
            string: 'Hello, world!',
            binary: Uint8Array.from([1, 2, 3]),
            array: [10, 20, 30],
            map: { foo: 'bar' },
            bool: true,
          }
          const sealed = await manager.seal(complexData)
          const unsealed = await manager.unseal(sealed)
          assertEquals(unsealed, complexData)
        })
      })
    }
  })

  describe('custom PBKDF2 iterations', async () => {
    // Use a low iteration count for faster tests
    const lowIterManager = await CryptoManager.fromPassword(password, { iterations: 100 })

    it('uses instance-level iterations', async () => {
      const sealed = await lowIterManager.seal(data)
      const unsealed = await lowIterManager.unseal(sealed)
      assertEquals(unsealed, data)
    })

    it('allows per-call iterations to override the instance default', async () => {
      const sealed = await lowIterManager.seal(data, { iterations: 200 })
      const unsealed = await lowIterManager.unseal(sealed) // uses 100 iterations, should fail
      assertEquals(unsealed, undefined)
      const unsealed2 = await lowIterManager.unseal(sealed, { iterations: 200 })
      assertEquals(unsealed2, data)
    })
  })

  describe('tampered payloads', async () => {
    const manager = await CryptoManager.fromPassword(password, { iterations: 100 })
    const sealed = await manager.seal(data)
    const [v, s, iv, w, ct] = sealed.split('.').map(toUint8Array)
    assert(
      v?.byteLength === 1 && v[0] === 1 && s?.byteLength === 16 && iv?.byteLength === 12 &&
        w?.byteLength === 40 && ct && ct.byteLength > 16,
    )

    const tamperAndTest = async (
      field: string,
      manipulation: (val: Uint8Array) => void,
      expected: unknown = undefined,
    ) => {
      const payload = { v, s, iv, w, ct }
      manipulation(payload[field as keyof typeof payload])
      const tampered = Object.values(payload).map((data) => toBase64(data, { urlSafe: true }))
        .join('.')
      const unsealed = await manager.unseal(tampered)
      assertEquals(unsealed, expected)
    }

    // sanity check
    it('succeeds without tampering', () => tamperAndTest('ct', () => {}, data))
    it('fails when altering the salt', () => tamperAndTest('s', (s) => s[0]! ^= 0x01))
    it('fails when altering the IV', () => tamperAndTest('iv', (iv) => iv[0]! ^= 0x01))
    it('fails when altering the wrapped key', () => tamperAndTest('w', (w) => w[0]! ^= 0x01))
    it('fails when altering the ciphertext', () => tamperAndTest('ct', (ct) => ct[0]! ^= 0x01))
  })
})

describe('generateKey', () => {
  it('creates a valid PBKDF2 CryptoKey', async () => {
    const key = await generateKey(password)
    assert(key instanceof CryptoKey)
    assertEquals(key.type, 'secret')
    assertEquals(key.extractable, false)
    assertEquals(key.algorithm.name, 'PBKDF2')
    assertEquals(key.usages, ['deriveKey'])
  })
})

describe('seal/unseal', () => {
  it('performs a basic roundtrip', async () => {
    const key = await generateKey(password)
    const sealed = await seal(key, data)
    const unsealedData = await unseal(key, sealed)
    assertEquals(unsealedData, data)
  })

  it('works with non-object data', async () => {
    const key = await generateKey(password)

    const stringData = 'test string'
    const sealedString = await seal(key, stringData)
    assertEquals(await unseal(key, sealedString), stringData)

    const numberData = 123.45
    const sealedNumber = await seal(key, numberData)
    assertEquals(await unseal(key, sealedNumber), numberData)

    const arrayData = [1, 'two', { three: 3 }]
    const sealedArray = await seal(key, arrayData)
    assertEquals(await unseal(key, sealedArray), arrayData)
  })

  it('rejects non-JSON-serializable data by default', async () => {
    const key = await generateKey(password)

    // deno-lint-ignore no-explicit-any
    const circularReference: any = { data: 123 }
    circularReference.myself = circularReference
    await assertRejects(
      () => seal(key, circularReference),
      TypeError,
      'Data is not JSON-serializable',
    )

    const dateData = new Date()
    await assertRejects(
      () => seal(key, dateData),
      TypeError,
      'Data is not JSON-serializable',
    )
  })

  describe('malformed input', async () => {
    const key = await generateKey(password)

    it('returns undefined when payload has too few parts', async () => {
      const sealed = 'a.b.c'
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })

    it('returns undefined when payload contains invalid base64', async () => {
      const sealed = 'a.b.c.d.e'
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })

    it('returns undefined when payload is empty', async () => {
      const sealed = ''
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })
  })

  it('maintains consistent unseal timing to mitigate timing attacks', async () => {
    const key = await generateKey(password)
    const sealed = await seal(key, data)

    const startValid = performance.now()
    const unsealedValid = await unseal(key, sealed)
    const durationValid = performance.now() - startValid
    assertEquals(unsealedValid, data)

    const tamperAndCollectTime = async (field: string, manipulation: (val: Uint8Array) => void) => {
      const [v, s, iv, w, ct] = sealed.split('.').map(toUint8Array)
      const payload = { v: v!, s: s!, iv: iv!, w: w!, ct: ct! }
      manipulation(payload[field as keyof typeof payload])
      const tampered = Object.values(payload).map((data) => toBase64(data, { urlSafe: true }))
        .join('.')
      const start = performance.now()
      const unsealed = await unseal(key, tampered)
      const duration = performance.now() - start
      assertEquals(unsealed, undefined)
      return duration
    }

    const fieldsToTamper = ['v', 's', 'iv', 'w', 'ct']
    for (const field of fieldsToTamper) {
      const duration = await tamperAndCollectTime(field, (arr) => arr[0]! ^= 0x01)
      assert(
        duration >= durationValid * 0.8 && duration <= durationValid * 1.2,
        `Tampering "${field}" caused unseal time to be out of expected range`,
      )
    }
  })
})
