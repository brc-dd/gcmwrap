import { assertEquals } from 'jsr:@std/assert'
import { CryptoManager } from '../src/index.ts'

const data = { foo: 'bar', num: 42, nested: { a: 1, b: [1, 2, 3] } }
const aad = { info: 'additional-authenticated-data' }

Deno.test('seal and unseal data works', async () => {
  const manager = await CryptoManager.fromPassword('my-secret-password')

  const sealed = await manager.seal(data)
  const unsealed = await manager.unseal(sealed)

  assertEquals(unsealed, data)
})

Deno.test('unseal with wrong password returns undefined', async () => {
  const manager1 = await CryptoManager.fromPassword('password1')
  const manager2 = await CryptoManager.fromPassword('password2')

  const sealed = await manager1.seal(data)
  const unsealed = await manager2.unseal(sealed)

  assertEquals(unsealed, undefined)
})

Deno.test('multiple instances with same password can unseal data', async () => {
  const manager1 = await CryptoManager.fromPassword('instance1')
  const manager2 = await CryptoManager.fromPassword('instance1')

  const sealed = await manager1.seal(data)
  const unsealed = await manager2.unseal(sealed)

  assertEquals(unsealed, data)
})

Deno.test('supports custom aad', async () => {
  const manager1 = await CryptoManager.fromPassword('my-secret-password', { aad })
  const manager2 = await CryptoManager.fromPassword('my-secret-password')

  const sealed = await manager1.seal(data)
  const unsealed1 = await manager1.unseal(sealed)
  const unsealed2 = await manager2.unseal(sealed)

  assertEquals(unsealed1, data)
  assertEquals(unsealed2, undefined)
})

Deno.test('tampering with sealed data returns undefined', async () => {
  const manager = await CryptoManager.fromPassword('my-secret-password')

  const sealed = await manager.seal(data)
  const tampered = JSON.stringify({ ...JSON.parse(sealed), it: 1000 })
  const unsealed = await manager.unseal(tampered)

  assertEquals(unsealed, undefined)
})
