export function isJson(v: unknown): boolean {
  const t = typeof v
  if (v === null || t === 'string' || t === 'boolean') return true
  if (t === 'number') return Number.isFinite(v)
  if (t !== 'object') return false

  const stack = [v!]
  const seen = new WeakSet([v!])
  let i = 0

  while (stack.length) {
    const o = stack.pop()!

    if (Array.isArray(o)) {
      i = o.length
      while (i--) {
        const v = o[i]
        const t = typeof v
        if (v === null || t === 'string' || t === 'boolean') continue
        if (t === 'number') {
          if (!Number.isFinite(v)) return false
          continue
        }
        if (t !== 'object') return false
        if (seen.has(v)) return false
        seen.add(v)
        stack.push(v)
      }
      continue
    }

    const proto = Object.getPrototypeOf(o)
    if (proto !== null && proto !== Object.prototype) return false

    if (Object.getOwnPropertySymbols(o).length) return false
    const keys = Object.getOwnPropertyNames(o)
    i = keys.length

    while (i--) {
      const k = keys[i]!
      const v = (o as Record<string, unknown>)[k]
      const tv = typeof v
      if (v == null || tv === 'string' || tv === 'boolean') continue
      if (tv === 'number') {
        if (!Number.isFinite(v)) return false
        continue
      }
      if (tv !== 'object') return false
      if (seen.has(v)) return false
      seen.add(v)
      stack.push(v)
    }
  }

  return true
}
