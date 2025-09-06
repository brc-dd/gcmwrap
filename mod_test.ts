import { CryptoManager, generateKey, seal, unseal } from 'gcmwrap'
import { assert, assertEquals, assertNotEquals, assertRejects } from 'jsr:@std/assert'
import { decode as msgpackdecode, encode as msgpackencode } from 'npm:@msgpack/msgpack'
import { decode as cbor2decode, encode as cbor2encode } from 'npm:cbor2'
import { decode as cborgdecode, encode as cborgencode } from 'npm:cborg'
import {
  base64ToUint8Array as toUint8Array,
  uint8ArrayToBase64 as toBase64,
} from 'npm:uint8array-extras@^1.5.0'

const password = 'correct-horse-battery-staple-secure-password'
const data = { foo: 'bar', num: 42, nested: { a: 1, b: [1, 2, 3] } }
const aad = { context: 'user-session', version: 2 }

Deno.test('CryptoManager', async (t) => {
  await t.step('should perform a successful seal/unseal roundtrip', async (t) => {
    const manager = await CryptoManager.fromPassword(password)

    const data_samples = [
      { description: 'simple object', data: { a: 1, b: 'hello' } },
      { description: 'string', data: 'just a simple string' },
      { description: 'number', data: 12345.6789 },
      { description: 'array', data: [1, 'two', { three: true }] },
      { description: 'null', data: null },
    ]

    for (const sample of data_samples) {
      await t.step(`with data type: ${sample.description}`, async () => {
        const sealed = await manager.seal(sample.data)
        assert(typeof sealed === 'string' && sealed.length > 0)
        const unsealed = await manager.unseal(sealed)
        assertEquals(unsealed, sample.data)
      })
    }
  })

  await t.step('should produce different sealed output for the same input', async () => {
    const manager = await CryptoManager.fromPassword(password)
    const sealed1 = await manager.seal(data)
    const sealed2 = await manager.seal(data)
    assertNotEquals(sealed1, sealed2)
  })

  await t.step('should work across different instances with the same password', async () => {
    const manager1 = await CryptoManager.fromPassword(password)
    const manager2 = await CryptoManager.fromPassword(password)
    const sealed = await manager1.seal(data)
    const unsealed = await manager2.unseal(sealed)
    assertEquals(unsealed, data)
  })

  await t.step('should fail to unseal with the wrong password', async () => {
    const manager1 = await CryptoManager.fromPassword(password)
    const manager2 = await CryptoManager.fromPassword('a-completely-different-password')
    const sealed = await manager1.seal(data)
    const unsealed = await manager2.unseal(sealed)
    assertEquals(unsealed, undefined)
  })

  await t.step('should correctly handle Additional Authenticated Data (AAD)', async (t) => {
    const managerWithAad = await CryptoManager.fromPassword(password, { aad })
    const managerWithoutAad = await CryptoManager.fromPassword(password)

    await t.step('should succeed with matching AAD', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithAad.unseal(sealed)
      assertEquals(unsealed, data)
    })

    await t.step('should fail when AAD is expected but not provided', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithoutAad.unseal(sealed)
      assertEquals(unsealed, undefined)
    })

    await t.step('should fail with mismatched AAD', async () => {
      const sealed = await managerWithAad.seal(data)
      const unsealed = await managerWithAad.unseal(sealed, { aad: { context: 'wrong-context' } })
      assertEquals(unsealed, undefined)
    })

    await t.step('should allow per-call AAD to merge with instance AAD', async () => {
      const sealed = await managerWithAad.seal(data, { aad: { additional: true } })

      // Fails with only instance AAD
      const unsealedFail = await managerWithAad.unseal(sealed)
      assertEquals(unsealedFail, undefined)

      // Succeeds with merged AAD
      const unsealedSuccess = await managerWithAad.unseal(sealed, { aad: { additional: true } })
      assertEquals(unsealedSuccess, data)
    })

    await t.step('should fail when order of AAD properties is changed', async () => {
      const sealed = await managerWithAad.seal(data, { aad: { a: 1, b: 2 } })
      const unsealed = await managerWithAad.unseal(sealed, { aad: { b: 2, a: 1 } })
      assertEquals(unsealed, undefined)
    })
  })

  await t.step('should support different serialization formats', async (t) => {
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
      await t.step(`using ${fmt.name}`, async (t) => {
        const manager = await CryptoManager.fromPassword(password, {
          encode: fmt.encode,
          decode: fmt.decode,
        })

        await t.step('should seal and unseal data correctly', async () => {
          const sealed = await manager.seal(data)
          const unsealed = await manager.unseal(sealed)
          assertEquals(unsealed, data)
        })

        await t.step('should work with AAD', async () => {
          const sealed = await manager.seal(data, { aad })
          const unsealed = await manager.unseal(sealed, { aad })
          assertEquals(unsealed, data)
        })

        await t.step('should work with different key order in AAD', async () => {
          const aad1 = { x: 1, y: 2 }
          const aad2 = { y: 2, x: 1 }
          const sealed = await manager.seal(data, { aad: aad1 })
          const unsealed = await manager.unseal(sealed, { aad: aad2 })
          assertEquals(unsealed, data)
        })

        await t.step('should fail with incorrect AAD', async () => {
          const sealed = await manager.seal(data, { aad })
          const unsealed = await manager.unseal(sealed, { aad: { context: 'wrong' } })
          assertEquals(unsealed, undefined)
        })

        await t.step('should allow additional data types', async () => {
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

  await t.step('should handle custom PBKDF2 iterations', async (t) => {
    // Use a low iteration count for faster tests
    const lowIterManager = await CryptoManager.fromPassword(password, { iterations: 100 })

    await t.step('should use instance-level iterations', async () => {
      const sealed = await lowIterManager.seal(data)
      const unsealed = await lowIterManager.unseal(sealed)
      assertEquals(unsealed, data)
    })

    await t.step('should allow call-level iterations to override instance-level', async () => {
      const sealed = await lowIterManager.seal(data, { iterations: 200 })
      const unsealed = await lowIterManager.unseal(sealed) // uses 100 iterations, should fail
      assertEquals(unsealed, undefined)
      const unsealed2 = await lowIterManager.unseal(sealed, { iterations: 200 })
      assertEquals(unsealed2, data)
    })
  })

  await t.step('should fail to unseal tampered data', async (t) => {
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
    await t.step('should succeed without tampering', () => tamperAndTest('ct', () => {}, data))
    await t.step('by altering the salt', () => tamperAndTest('s', (s) => s[0]! ^= 0x01))
    await t.step('by altering the IV', () => tamperAndTest('iv', (iv) => iv[0]! ^= 0x01))
    await t.step('by altering the wrapped key', () => tamperAndTest('w', (w) => w[0]! ^= 0x01))
    await t.step('by altering the ciphertext', () => tamperAndTest('ct', (ct) => ct[0]! ^= 0x01))
  })
})

Deno.test('generateKey', async (t) => {
  await t.step('should create a valid PBKDF2 CryptoKey', async () => {
    const key = await generateKey(password)
    assert(key instanceof CryptoKey)
    assertEquals(key.type, 'secret')
    assertEquals(key.extractable, false)
    assertEquals(key.algorithm.name, 'PBKDF2')
    assertEquals(key.usages, ['deriveKey'])
  })
})

Deno.test('seal/unseal', async (t) => {
  await t.step('should perform a basic roundtrip', async () => {
    const key = await generateKey(password)
    const sealed = await seal(key, data)
    const unsealedData = await unseal(key, sealed)
    assertEquals(unsealedData, data)
  })

  await t.step('should work with non-object data', async () => {
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

  await t.step('should reject non-JSON-serializable data by default', async () => {
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

  await t.step('should fail with malformed input', async (t) => {
    const key = await generateKey(password)

    await t.step('too few parts', async () => {
      const sealed = 'a.b.c'
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })

    await t.step('invalid base64', async () => {
      const sealed = 'a.b.c.d.e'
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })

    await t.step('empty string', async () => {
      const sealed = ''
      const unsealed = await unseal(key, sealed)
      assertEquals(unsealed, undefined)
    })
  })

  await t.step('should have consistent unseal timing to mitigate timing attacks', async () => {
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
