const b4a = require('b4a')

// Systematic random-linear fountain code over GF(256), used by the optional
// coded replication path (see lib/coded.js). A group of k source blocks is
// turned into a limitless stream of encoding symbols: symbol ids esi < k are
// the (padded) source blocks verbatim, esi >= k are random linear combinations
// of all k blocks. Any k linearly independent symbols reconstruct the group,
// so a downloader gathers repair symbols from any mix of seeders and absorbs
// loss by pulling extras rather than retransmitting specific blocks.
//
// This is not RFC 6330 RaptorQ: decode is dense Gauss-Jordan elimination, O(k^2
// * symbolSize), with no LDPC/HDPC precode or LT peeling. That is intentional -
// coded replication runs in small groups (default 16 blocks) where the matrix
// cost is negligible next to the network, and the "any k symbols" property is
// the only thing the transport needs. Reconstructed blocks are never trusted on
// their own; they are verified against the core's Merkle tree exactly like a
// block that arrived in a data message (see lib/coded.js).

const POLY = 0x11d
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)

for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x
  LOG[x] = i
  x <<= 1
  if (x & 0x100) x ^= POLY
  x &= 0xff
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]

function inv(a) {
  return EXP[255 - LOG[a]]
}

// dst[j] ^= factor * src[j] over GF(256), the inner loop of both encode and
// elimination.
function addScaled(dst, src, factor, len) {
  if (factor === 0) return
  const base = LOG[factor]
  for (let j = 0; j < len; j++) {
    const s = src[j]
    if (s !== 0) dst[j] ^= EXP[base + LOG[s]]
  }
}

function scale(dst, factor, len) {
  if (factor === 1) return
  const base = LOG[factor]
  for (let j = 0; j < len; j++) {
    const s = dst[j]
    if (s !== 0) dst[j] = EXP[base + LOG[s]]
  }
}

// Deterministic coefficient row for a repair symbol, keyed by esi. Both encoder
// and decoder derive it, so no coefficients travel on the wire. The mixing is
// nonlinear (Math.imul, not GF(2)-linear shifts) so k-byte rows span the full
// field rather than collapsing into a rank-32 subspace, which a plain xorshift
// PRNG would do and cap decode at k <= 32.
function deriveRow(esi, k) {
  const row = new Uint8Array(k)
  let nonzero = false
  for (let i = 0; i < k; i++) {
    let z = (Math.imul(esi + 1, 0x9e3779b1) ^ Math.imul(i + 1, 0x85ebca6b)) >>> 0
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad) >>> 0
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97) >>> 0
    z = (z ^ (z >>> 15)) >>> 0
    row[i] = z & 0xff
    if (row[i] !== 0) nonzero = true
  }
  if (!nonzero) row[esi % k] = 1
  return row
}

function rowFor(esi, k) {
  if (esi < k) {
    const e = new Uint8Array(k)
    e[esi] = 1
    return e
  }
  return deriveRow(esi, k)
}

class Encoder {
  constructor(blocks, symbolSize) {
    this.k = blocks.length
    this.symbolSize = symbolSize
    this.blocks = new Array(this.k)

    for (let i = 0; i < this.k; i++) {
      const b = blocks[i]
      if (b.byteLength === symbolSize) {
        this.blocks[i] = b
      } else {
        const padded = b4a.alloc(symbolSize)
        padded.set(b)
        this.blocks[i] = padded
      }
    }
  }

  symbol(esi) {
    if (esi < this.k) return this.blocks[esi]

    const row = deriveRow(esi, this.k)
    const out = b4a.alloc(this.symbolSize)
    for (let i = 0; i < this.k; i++) addScaled(out, this.blocks[i], row[i], this.symbolSize)
    return out
  }
}

class Decoder {
  constructor(k, symbolSize) {
    this.k = k
    this.symbolSize = symbolSize
    this.rank = 0
    // pivots[col], when set, is a row in reduced row echelon form with
    // coef[col] === 1 and eliminated against every other pivot.
    this.pivots = new Array(k).fill(null)
  }

  get decodable() {
    return this.rank >= this.k
  }

  // Feed one received symbol; returns true once k independent symbols are in.
  add(esi, symbol) {
    if (this.rank >= this.k) return true

    const coef = rowFor(esi, this.k)
    const data = new Uint8Array(this.symbolSize)
    data.set(symbol)

    for (let col = 0; col < this.k; col++) {
      const f = coef[col]
      if (f === 0) continue
      const p = this.pivots[col]
      if (p) {
        addScaled(coef, p.coef, f, this.k)
        addScaled(data, p.data, f, this.symbolSize)
      }
    }

    let pivotCol = -1
    for (let col = 0; col < this.k; col++) {
      if (coef[col] !== 0) {
        pivotCol = col
        break
      }
    }
    if (pivotCol === -1) return this.rank >= this.k // linearly dependent, drop

    const lead = inv(coef[pivotCol])
    scale(coef, lead, this.k)
    scale(data, lead, this.symbolSize)

    for (let col = 0; col < this.k; col++) {
      const p = this.pivots[col]
      if (!p) continue
      const f = p.coef[pivotCol]
      if (f === 0) continue
      addScaled(p.coef, coef, f, this.k)
      addScaled(p.data, data, f, this.symbolSize)
    }

    this.pivots[pivotCol] = { coef, data }
    this.rank++
    return this.rank >= this.k
  }

  // The k reconstructed blocks, trimmed to `lengths[i]` bytes. Requires rank ===
  // k (RREF makes pivots[i].data === source symbol i).
  decode(lengths) {
    const out = new Array(this.k)
    for (let i = 0; i < this.k; i++) {
      out[i] = b4a.from(this.pivots[i].data.subarray(0, lengths[i]))
    }
    return out
  }
}

module.exports = { Encoder, Decoder, rowFor }
