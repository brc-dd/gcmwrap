import { assertEquals } from 'jsr:@std/assert'
import { CryptoManager } from '../src/index.ts'

const data = { foo: 'bar', num: 42, nested: { a: 1, b: [1, 2, 3] } }

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
