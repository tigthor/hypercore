const test = require('brittle')
const b4a = require('b4a')
const { create, replicate, replicateDebugStream, eventFlush } = require('./helpers')
const { Encoder, Decoder } = require('../lib/fountain')
const { serveCodedRequest } = require('../lib/coded')

// a minimal peer stub for unit-testing serveCodedRequest in isolation
function fakePeer(core, symbols) {
  const stat = { tx: 0, rx: 0 }
  return {
    core,
    protomux: { drained: true },
    codedServing: 0,
    stats: { wireCodedData: stat },
    replicator: { stats: { wireCodedData: stat }, codedGroup: 16 },
    wireCodedData: { send: (m) => symbols.push(m) }
  }
}

test('fountain codec: any k independent symbols reconstruct the group', function (t) {
  const k = 16
  const symbolSize = 40
  const blocks = []
  for (let i = 0; i < k; i++) blocks.push(b4a.from(('block-' + i + '-').padEnd(symbolSize, 'x')))

  const enc = new Encoder(blocks, symbolSize)
  const dec = new Decoder(k, symbolSize)

  // feed only the last 4 systematic symbols and repair symbols for the rest -
  // stands in for losing the first 12 blocks on the wire
  for (let i = k - 4; i < k; i++) dec.add(i, enc.symbol(i))
  let esi = k
  while (dec.decodable === false) dec.add(esi, enc.symbol(esi++))

  const out = dec.decode(blocks.map((b) => b.byteLength))
  for (let i = 0; i < k; i++) t.alike(out[i], blocks[i], 'block ' + i + ' reconstructed')
  t.ok(esi - k <= 14, 'reconstructed from ~k symbols (' + (esi - k) + ' repair)')
})

test('fountain codec: a tampered repair symbol corrupts the decode (caught by verify upstream)', function (t) {
  const k = 8
  const symbolSize = 32
  const blocks = []
  for (let i = 0; i < k; i++) blocks.push(b4a.from(('b' + i).padEnd(symbolSize, 'y')))

  const enc = new Encoder(blocks, symbolSize)
  const dec = new Decoder(k, symbolSize)

  for (let esi = k; dec.decodable === false; esi++) {
    const sym = enc.symbol(esi)
    if (esi === k + 1) sym[0] ^= 0xff // flip a byte in one repair symbol
    dec.add(esi, sym)
  }

  const out = dec.decode(blocks.map((b) => b.byteLength))
  let corrupted = 0
  for (let i = 0; i < k; i++) if (!b4a.equals(out[i], blocks[i])) corrupted++
  t.ok(
    corrupted > 0,
    'a tampered symbol perturbs the reconstruction (the leaf-hash verify then rejects it)'
  )
})

test('coded is opt-in: negotiated only when both sides enable it', async function (t) {
  const a = await create(t, { coded: true })
  await a.append('hello')

  const b = await create(t, a.key, { coded: true })
  const c = await create(t, a.key) // no coded

  replicate(a, b, t)
  replicate(a, c, t)
  await eventFlush()
  await b.get(0)
  await c.get(0)

  t.ok(a.core.replicator.peers.length >= 1, 'peers connected')
  // the coded controller only exists on cores that opted in
  t.ok(b.core.replicator.peers[0].coded !== null, 'coded reader has a controller')
  t.ok(b.core.replicator.peers[0].remoteCoded === true, 'coded reader sees coded seeder')
  t.ok(c.core.replicator.peers[0].coded === null, 'non-coded reader has no controller')
  t.ok(
    c.core.replicator.peers[0].remoteCoded === false,
    'non-coded reader does not negotiate coded'
  )
})

test('a coded core replicates normally against a non-coded core', async function (t) {
  const a = await create(t, { coded: true })
  for (let i = 0; i < 40; i++) await a.append(b4a.from('block-' + i))

  const b = await create(t, a.key) // stock, no coded
  replicate(a, b, t)

  await b.download({ start: 0, end: 40 }).done()
  t.is(b.length, 40, 'stock reader downloaded every block from a coded seeder')
  for (let i = 0; i < 40; i++) t.alike(await b.get(i), b4a.from('block-' + i), 'block ' + i)
})

test('serveCodedRequest yields symbols a decoder can reconstruct from', async function (t) {
  const k = 16
  const a = await create(t, { coded: true })
  for (let i = 0; i < k; i++) await a.append(b4a.from(('src-' + i + '-').padEnd(50, 'z')))

  // a minimal fake peer that captures the symbols the seeder would send
  const symbols = []
  await serveCodedRequest(fakePeer(a.core, symbols), {
    start: 0,
    k,
    fork: a.core.state.fork,
    count: k
  })
  t.ok(symbols.length === k, 'seeder produced ' + symbols.length + ' repair symbols')

  const symbolSize = symbols[0].symbol.byteLength
  const dec = new Decoder(k, symbolSize)
  for (const s of symbols) {
    if (dec.add(s.esi, s.symbol)) break
  }
  t.ok(dec.decodable, 'decoder reached full rank from repair symbols alone')

  const lengths = []
  for (let i = 0; i < k; i++) {
    const rx = a.core.state.storage.read()
    const node = rx.getTreeNode(2 * i)
    rx.tryFlush()
    lengths.push((await node).size)
  }
  const out = dec.decode(lengths)
  for (let i = 0; i < k; i++) {
    t.alike(
      out[i],
      await a.get(i, { raw: true }),
      'reconstructed raw block ' + i + ' matches seeder'
    )
  }
})

test('serveCodedRequest bounds untrusted input and refuses partial groups', async function (t) {
  const a = await create(t, { coded: true })
  for (let i = 0; i < 8; i++) await a.append(b4a.from('x' + i))

  const symbols = []
  const peer = fakePeer(a.core, symbols)
  const fork = a.core.state.fork

  await serveCodedRequest(peer, { start: 0, k: 1000, fork, count: 2 }) // k too large
  await serveCodedRequest(peer, { start: 0, k: 8, fork, count: 999 }) // count too large
  await serveCodedRequest(peer, { start: 4, k: 8, fork, count: 4 }) // runs past length
  await serveCodedRequest(peer, { start: 0, k: 8, fork: fork + 1, count: 4 }) // wrong fork
  t.is(symbols.length, 0, 'every out-of-bounds / partial request was refused, no symbols sent')

  await serveCodedRequest(peer, { start: 0, k: 8, fork, count: 4 }) // valid
  t.is(symbols.length, 4, 'a valid request is answered')
})

test('an opted-out node is never asked for and never serves coded', async function (t) {
  const a = await create(t) // NOT coded
  for (let i = 0; i < 16; i++) await a.append(b4a.from('block-' + i))

  const b = await create(t, a.key, { coded: true })
  replicate(a, b, t)
  await eventFlush()
  await b.get(0)

  // opted-out seeder has no coded controller, so serveCodedRequest is gated off
  t.ok(a.core.replicator.peers[0].coded === null, 'opted-out seeder has no coded controller')
  // and the coded reader sees the seeder is not coded, so it never sends a request
  t.is(
    b.core.replicator.peers[0].remoteCoded,
    false,
    'coded reader will not send coded requests to an opted-out seeder'
  )
  // download still completes fully over the normal path
  await b.download({ start: 0, end: 16 }).done()
  t.is(b.length, 16, 'download completed against the opted-out seeder')
})

test('coded repair reconstructs real block bodies end-to-end (only coded fills them)', async function (t) {
  const k = 16
  const a = await create(t, { coded: true })
  for (let i = 0; i < k; i++) await a.append(b4a.from(('payload-' + i + '-').padEnd(64, 'q')))

  const b = await create(t, a.key, { coded: true })
  replicate(a, b, t)

  // b syncs only the signed tree - no block bodies, no leaf hashes yet
  await b.update({ wait: true })
  t.is(b.length, k, 'b synced the tree')
  for (let i = 0; i < k; i++) t.absent(b.core.bitfield.get(i), 'body ' + i + ' absent before coded')

  await eventFlush()
  const peer = b.core.replicator.peers[0]
  t.ok(peer && peer.coded !== null, 'coded controller present')

  // drive one coded group directly (no range/get => the normal scheduler never
  // requests a body, so anything b ends up with came through coded repair)
  peer.coded.active = { start: 0, phase: 'leaves' }
  await peer.coded._start(0)

  const deadline = Date.now() + 30000
  while (b.core.bitfield.get(k - 1) === false) {
    if (Date.now() > deadline) throw new Error('coded repair did not complete')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }

  t.is(peer.coded.filled, k, 'all ' + k + ' bodies were filled by coded repair')
  for (let i = 0; i < k; i++) {
    t.alike(
      await b.get(i),
      b4a.from(('payload-' + i + '-').padEnd(64, 'q')),
      'block ' + i + ' byte-identical'
    )
  }
})

test('a coded download matches a stock download exactly (coded never corrupts)', async function (t) {
  const n = 50
  const a = await create(t, { coded: true })
  for (let i = 0; i < n; i++) await a.append(b4a.from(('data-' + i + '-').padEnd(80, 'k')))

  const coded = await create(t, a.key, { coded: true })
  const stock = await create(t, a.key)

  replicate(a, coded, t)
  replicate(a, stock, t)

  await coded.download({ start: 0, end: n }).done()
  await stock.download({ start: 0, end: n }).done()

  t.is(coded.length, n, 'coded reader completed')
  t.is(stock.length, n, 'stock reader completed')
  for (let i = 0; i < n; i++) {
    const want = b4a.from(('data-' + i + '-').padEnd(80, 'k'))
    t.alike(await coded.get(i), want, 'coded block ' + i)
    t.alike(await stock.get(i), await coded.get(i), 'coded and stock agree on block ' + i)
  }
})

test('coded repair completes over a high-latency link', async function (t) {
  t.timeout(90000)

  const k = 16
  const a = await create(t, { coded: true })
  for (let i = 0; i < k; i++) await a.append(b4a.from(('slow-' + i + '-').padEnd(64, 's')))

  const b = await create(t, a.key, { coded: true })
  replicateDebugStream(a, b, t, { latency: 20, jitter: 10 })

  await b.update({ wait: true })
  await eventFlush()
  const peer = b.core.replicator.peers[0]
  peer.coded.active = { start: 0, phase: 'leaves' }
  await peer.coded._start(0)

  const deadline = Date.now() + 60000
  while (b.core.bitfield.get(k - 1) === false) {
    if (Date.now() > deadline) {
      throw new Error('coded repair did not complete over the latency link')
    }
    await new Promise((resolve) => setTimeout(resolve, 25))
  }

  t.is(peer.coded.filled, k, 'coded filled every block despite latency')
  for (let i = 0; i < k; i++) {
    t.alike(await b.get(i), b4a.from(('slow-' + i + '-').padEnd(64, 's')), 'block ' + i)
  }
})

test('an all-empty group resets instead of wedging the coded controller', async function (t) {
  const k = 16
  const a = await create(t, { coded: true })
  for (let i = 0; i < k; i++) await a.append(b4a.alloc(0))
  for (let i = 0; i < k; i++) await a.append(b4a.from(('after-' + i + '-').padEnd(64, 'e')))

  const b = await create(t, a.key, { coded: true })
  replicate(a, b, t)

  await b.update({ wait: true })
  await eventFlush()
  const peer = b.core.replicator.peers[0]

  // group 0 is all zero-length blocks - nothing to code, the controller must
  // release it (a leaked group has no timer and blocks update() forever)
  peer.coded.active = { start: 0, phase: 'leaves' }
  await peer.coded._start(0)
  t.is(peer.coded.active, null, 'the unusable group was released')

  // and the controller is still usable for the next, non-empty group
  peer.coded.active = { start: k, phase: 'leaves' }
  await peer.coded._start(k)

  const deadline = Date.now() + 30000
  while (b.core.bitfield.get(2 * k - 1) === false) {
    if (Date.now() > deadline) throw new Error('coded repair did not recover after the empty group')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }

  t.is(peer.coded.filled, k, 'coded filled the whole next group')
  for (let i = 0; i < k; i++) {
    t.alike(await b.get(k + i), b4a.from(('after-' + i + '-').padEnd(64, 'e')), 'block ' + (k + i))
  }
})

test('codedGroup above the served maximum is clamped, not silently broken', async function (t) {
  const n = 80 // more than one max-size group, so an unclamped k would exceed the cap
  const a = await create(t, { coded: true, codedGroup: 4096 })
  for (let i = 0; i < n; i++) await a.append(b4a.from(('big-' + i + '-').padEnd(64, 'g')))

  const b = await create(t, a.key, { coded: true, codedGroup: 4096 })
  t.is(b.core.replicator.codedGroup, 64, 'oversized codedGroup clamped to the wire maximum')

  const c = await create(t, { coded: true, codedGroup: 0 })
  t.is(c.core.replicator.codedGroup, 1, 'zero codedGroup clamped up to 1')

  replicate(a, b, t)
  await b.update({ wait: true })
  await eventFlush()
  const peer = b.core.replicator.peers[0]

  // an unclamped downloader would ask for k=80 and be refused by every
  // conformant seeder; clamped, the first group is 64 blocks and fills
  peer.coded.active = { start: 0, phase: 'leaves' }
  await peer.coded._start(0)

  const deadline = Date.now() + 30000
  while (b.core.bitfield.get(63) === false) {
    if (Date.now() > deadline) throw new Error('clamped coded group did not fill')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }

  t.is(peer.coded.filled, 64, 'coded filled a full clamped group')
  for (let i = 0; i < 64; i++) {
    t.alike(await b.get(i), b4a.from(('big-' + i + '-').padEnd(64, 'g')), 'block ' + i)
  }
})
