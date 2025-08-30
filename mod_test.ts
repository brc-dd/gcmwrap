import { CryptoManager, generateKey, seal, unseal } from 'gcmwrap'
import { assert, assertEquals, assertNotEquals } from 'jsr:@std/assert'

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

    // await t.step('should succeed regardless of order of AAD properties', async () => {
    //   const sealed = await managerWithAad.seal(data, { aad: { b: 2, a: 1 } })
    //   const unsealed = await managerWithAad.unseal(sealed, { aad: { a: 1, b: 2 } })
    //   assertEquals(unsealed, data)
    // })
  })

  // await t.step('should handle custom PBKDF2 iterations', async (t) => {
  //   // Use a low iteration count for faster tests
  //   const lowIterManager = await CryptoManager.fromPassword(password, { iterations: 100 })

  //   await t.step('should use instance-level iterations', async () => {
  //     const sealed = await lowIterManager.seal(data)
  //     const decodedPayload = decode(toUint8Array(sealed, 'base64'))
  //     assertEquals(decodedPayload.it, 100)
  //     const unsealed = await lowIterManager.unseal(sealed)
  //     assertEquals(unsealed, data)
  //   })

  //   await t.step('should allow call-level iterations to override instance-level', async () => {
  //     const sealed = await lowIterManager.seal(data, { iterations: 200 })
  //     const decodedPayload = decode(toUint8Array(sealed, 'base64')) as { it: number }
  //     assertEquals(decodedPayload.it, 200)
  //     const unsealed = await lowIterManager.unseal(sealed)
  //     assertEquals(unsealed, data)
  //   })

  //   await t.step('should clamp iteration values to the valid range [1, 2_000_000]', async () => {
  //     const sealedLow = await lowIterManager.seal(data, { iterations: -100 })
  //     assertEquals((decode(toUint8Array(sealedLow, 'base64')) as { it: number }).it, 1)

  //     const sealedHigh = await lowIterManager.seal(data, { iterations: 5_000_000 })
  //     assertEquals((decode(toUint8Array(sealedHigh, 'base64')) as { it: number }).it, 2_000_000)
  //   })
  // })

  // await t.step('should fail to unseal tampered data', async (t) => {
  //   const manager = await CryptoManager.fromPassword(password, { iterations: 100 })
  //   const sealed = await manager.seal(data)
  //   const originalPayload = decode(toUint8Array(sealed, 'base64'))

  //   const tamperAndTest = async (field: string, manipulation: (val: Uint8Array) => void) => {
  //     const tamperedPayload = {
  //       ...originalPayload,
  //       [field]: new Uint8Array(originalPayload[field]),
  //     }
  //     manipulation(tamperedPayload[field])
  //     const tamperedSealed = toBase64(encode(tamperedPayload))
  //     const unsealed = await manager.unseal(tamperedSealed)
  //     assertEquals(unsealed, undefined)
  //   }

  //   await t.step('by altering the ciphertext', () => tamperAndTest('ct', (ct) => ct[0]! ^= 0x01))
  //   await t.step('by altering the IV', () => tamperAndTest('iv', (iv) => iv[0]! ^= 0x01))
  //   await t.step('by altering the salt', () => tamperAndTest('s', (s) => s[0]! ^= 0x01))
  //   await t.step('by altering the wrapped key', () => tamperAndTest('w', (w) => w[0]! ^= 0x01))
  // })

  // await t.step('should fail gracefully for malformed or garbage input', async (t) => {
  //   const manager = await CryptoManager.fromPassword(password)

  //   const mockSealed =
  //     `pmFzUM1nMrz1vDQQ9pCYxk8ku4FhdgFhd1gop8IHD4X0fTXmcYH8jbp2jYrt1HBdO-3tTRvr286gCxie3vNGn6LKvGJjdFgwEy4aEhvRCL5Hu1BVNmcn5xXQgYF3YjrPb40JCg6EwZFlMuI3hcWnNCb2OCtuBlSeYml0GgAJJ8BiaXZM4lOUKPJMyrgHdowv`
  //   const mockSealedDecoded = decode(toUint8Array(mockSealed, 'base64'))
  //   const createMockPayload = (overrides = {}) =>
  //     toBase64(encode({ ...mockSealedDecoded, ...overrides }))

  //   await t.step('with non-base64 input', async () => {
  //     assertEquals(await manager.unseal('not-valid-base64-or-cbor'), undefined)
  //   })
  //   await t.step('with non-CBOR input', async () => {
  //     assertEquals(await manager.unseal(toBase64(new Uint8Array([1, 2, 3]))), undefined)
  //   })
  //   await t.step('with missing required fields', async () => {
  //     assertEquals(await manager.unseal(toBase64(encode({ v: 1, wrong: 'field' }))), undefined)
  //   })
  //   await t.step('with unsupported version', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ v: 2 })), undefined)
  //   })
  //   await t.step('with out-of-bounds iterations (0)', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ it: 0 })), undefined)
  //   })
  //   await t.step('with out-of-bounds iterations (2,000,001)', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ it: 2_000_001 })), undefined)
  //   })
  //   await t.step('with invalid salt length', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ s: new Uint8Array(15) })), undefined)
  //   })
  //   await t.step('with invalid IV length', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ iv: new Uint8Array(11) })), undefined)
  //   })
  //   await t.step('with invalid wrapped key length', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ w: new Uint8Array(39) })), undefined)
  //   })
  //   await t.step('with invalid ciphertext length', async () => {
  //     assertEquals(await manager.unseal(createMockPayload({ ct: new Uint8Array(15) })), undefined)
  //   })
  // })
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
    const sealed = await seal(key, data, { iterations: 100 })
    const unsealedData = await unseal(key, sealed, { iterations: 100 })
    assertEquals(unsealedData, data)
  })
})
