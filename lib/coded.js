const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const { Encoder, Decoder } = require('./fountain')
const { MerkleTree } = require('./merkle-tree')

// Optional coded (fountain) block repair, negotiated by the handshake `coded`
// flag. It rides alongside the normal want/have scheduler as an additive fill
// strategy: for a group of blocks a downloader is missing, it pulls a handful
// of coded repair symbols from a peer and reconstructs the group, absorbing
// packet loss by gathering a few extra symbols instead of retransmitting each
// lost block. Coding never touches authentication - reconstructed blocks are
// verified against the core's Merkle tree by the same core.verify() path a
// block from a data message goes through, so a corrupt or forged symbol is
// caught exactly like a corrupt data message.

const MAX_GROUP = 64 // hard upper bound on k, before the per-node clamp below
const REPAIR_MARGIN = 2 // extra symbols over the deficit, to cover the ~1/255 dependent-symbol chance
const MAX_SYMBOL_SIZE = 1024 * 1024 // refuse to encode absurd per-symbol sizes
const MAX_SERVE_BYTES = 8 * 1024 * 1024 // cap the total repair payload one request may generate
const MAX_CODED_SERVING = 4 // concurrent coded encodes per peer (bounds the amplifier)
const GROUP_TIMEOUT = 15000 // ms before a stalled group is abandoned to the normal scheduler

// Seeder: answer a coded request with repair symbols generated on demand from
// the stored blocks of the group. Every field of the untrusted request is
// bounded before any work, the served window is clamped to our own group size
// (so a peer can't force the largest one), and concurrent encodes per peer are
// capped so pipelined requests can't stack into an amplifier.
async function serveCodedRequest(peer, msg) {
  const core = peer.core
  const { start, k, count } = msg

  const localGroup = Math.min(MAX_GROUP, peer.replicator.codedGroup)
  if (msg.fork !== core.state.fork) return
  if (k <= 0 || k > localGroup) return
  if (count <= 0 || count > k + REPAIR_MARGIN) return
  if (start < 0 || start + k > core.state.length) return

  // shed load rather than pile onto a congested or already-busy connection
  if (peer.protomux.drained === false) return
  if (peer.codedServing >= MAX_CODED_SERVING) return

  for (let i = 0; i < k; i++) {
    if (core.bitfield.get(start + i) !== true) return // only a full-group holder answers
  }

  peer.codedServing++
  try {
    const rx = core.state.storage.read()
    const reads = new Array(k)
    for (let i = 0; i < k; i++) reads[i] = rx.getBlock(start + i)
    rx.tryFlush()

    const blocks = await Promise.all(reads)

    let symbolSize = 0
    for (const b of blocks) {
      if (b === null) return
      if (b.byteLength > symbolSize) symbolSize = b.byteLength
    }
    if (symbolSize === 0 || symbolSize > MAX_SYMBOL_SIZE) return
    if (count * symbolSize > MAX_SERVE_BYTES) return // cap total amplification per request

    const enc = new Encoder(blocks, symbolSize)
    const fork = core.state.fork

    for (let j = 0; j < count; j++) {
      const esi = k + j // repair symbols only; the downloader has the systematic ones it holds
      peer.wireCodedData.send({ start, k, fork, esi, symbol: enc.symbol(esi) })
      peer.stats.wireCodedData.tx++
      peer.replicator.stats.wireCodedData.tx++
    }
  } catch (err) {
    safetyCatch(err)
  } finally {
    peer.codedServing--
  }
}

// Downloader: one coded repair controller per peer. Holds at most one active
// group at a time.
class CodedRepair {
  constructor(peer) {
    this.peer = peer
    this.core = peer.core
    this.replicator = peer.replicator
    this.group = peer.replicator.codedGroup
    this.refs = [] // ref target for the hash requests we drive
    this.active = null
    this.destroyed = false
    this.completing = false
    this.filled = 0 // blocks reconstructed + verified via coded repair (observability)
  }

  // Cheap no-op unless there is a fillable group and no group is in flight.
  update() {
    if (this.destroyed || this.active !== null || this.completing) return
    if (this.peer.remoteCoded !== true) return
    if (this.peer.isActive() === false || this.peer.remoteUploading !== true) return

    const start = this._pickGroup()
    if (start === -1) return

    this.active = { start, phase: 'leaves' }
    this._start(start).catch((err) => {
      safetyCatch(err)
      this._reset()
    })
  }

  // Lowest aligned group that has a missing block inside an active range, is
  // fully within our synced length, and is fully held by the remote. Jumps
  // between groups via firstUnset so the scan is bounded by the number of
  // groups with gaps, not the range length.
  _pickGroup() {
    const length = this.core.state.length
    if (length === 0) return -1

    for (const r of this.replicator._ranges) {
      if (r.blocks !== null) continue // non-contiguous ranges use the normal path
      const end = r.end === -1 ? length : Math.min(r.end, length)
      let index = this.core.bitfield.firstUnset(r.start)
      while (index !== -1 && index < end) {
        const start = index - (index % this.group)
        const k = Math.min(this.group, length - start)
        if (start + k <= this.peer.remoteLength && this._remoteHasGroup(start, k)) return start
        index = this.core.bitfield.firstUnset(start + this.group)
      }
    }

    return -1
  }

  _remoteHasGroup(start, k) {
    for (let i = 0; i < k; i++) {
      if (this.peer._remoteHasBlock(start + i) !== true) return false
    }
    return true
  }

  async _start(start) {
    const length = this.core.state.length
    const k = Math.min(this.group, length - start)
    const fork = this.core.state.fork

    const missing = []
    for (let i = 0; i < k; i++) {
      if (this.core.bitfield.get(start + i) !== true) missing.push(start + i)
    }
    if (missing.length === 0) return this._reset()

    // 1) make sure every missing block's leaf hash is present and trusted, via
    //    ordinary hash requests that hypercore verifies against the signed root.
    await this._ensureLeaves(missing)
    if (this._stale(start, fork)) return

    // 2) size the group from the tree and seed the decoder with the systematic
    //    symbols for blocks we already hold.
    const lengths = new Array(k)
    let symbolSize = 0
    for (let i = 0; i < k; i++) {
      const node = await MerkleTree.get(this.core.state, 2 * (start + i))
      if (node === null) return this._reset() // leaf still missing, bail to the normal path
      lengths[i] = node.size
      if (node.size > symbolSize) symbolSize = node.size
    }
    if (this._stale(start, fork) || symbolSize === 0) return

    const decoder = new Decoder(k, symbolSize)
    let seeded = 0
    for (let i = 0; i < k; i++) {
      if (this.core.bitfield.get(start + i) !== true) continue
      const raw = await this._readRaw(start + i)
      if (raw === null) continue
      decoder.add(i, pad(raw, symbolSize))
      seeded++
    }
    if (this._stale(start, fork)) return

    // 3) pull just the deficit (+ margin) as repair symbols.
    const count = Math.min(k, k - seeded + REPAIR_MARGIN)
    this.active = {
      start,
      k,
      fork,
      missing,
      decoder,
      lengths,
      symbolSize,
      phase: 'repair',
      timer: null,
      count,
      received: 0
    }
    if (count <= 0) return this._complete()
    this.peer.wireCodedRequest.send({ start, k, fork, count })
    this.peer.stats.wireCodedRequest.tx++
    this.replicator.stats.wireCodedRequest.tx++

    // if too few independent symbols come back (or the peer never answers),
    // abandon the group so the normal scheduler fills it and coded moves on.
    const timer = setTimeout(onGroupTimeout, GROUP_TIMEOUT, this)
    if (timer.unref) timer.unref()
    this.active.timer = timer
  }

  async _ensureLeaves(missing) {
    const pending = []
    for (const index of missing) {
      if (await hasLeaf(this.core, index)) continue
      const ref = this.peer._requestHashAt(index, this.refs)
      if (ref !== null) pending.push(ref.promise)
    }
    if (pending.length > 0) await Promise.allSettled(pending)
  }

  ondata(msg) {
    const a = this.active
    if (a === null || a.phase !== 'repair') return
    if (msg.start !== a.start || msg.k !== a.k || msg.fork !== a.fork) return
    if (msg.symbol.byteLength !== a.symbolSize) return
    // never do more elimination work than the symbols we actually asked for
    if (++a.received > a.count) return this._kick()

    if (a.decoder.add(msg.esi, msg.symbol) === true) this._complete().catch(safetyCatch)
  }

  async _complete() {
    const a = this.active
    if (a === null) return
    if (a.timer !== null) clearTimeout(a.timer)
    this.active = null
    // hold the single-active invariant across the verify awaits below, so a
    // reentrant updatePeer cannot start a second group mid-completion
    this.completing = true

    let blocks
    try {
      blocks = a.decoder.decode(a.lengths)
    } catch (err) {
      safetyCatch(err)
      this.completing = false
      return this._kick()
    }

    for (const index of a.missing) {
      if (this.core.bitfield.get(index) === true) continue
      const value = blocks[index - a.start]
      try {
        if (
          await this.core.verify({ fork: a.fork, block: { index, value, nodes: [] } }, this.peer)
        ) {
          this.filled++
        }
      } catch (err) {
        // a tampered symbol perturbs the whole reconstruction, so the first
        // verify throws INVALID_CHECKSUM; drop the group and let the normal
        // scheduler refetch.
        safetyCatch(err)
        break
      }
    }

    this.completing = false
    this._kick()
  }

  _stale(start, fork) {
    return (
      this.destroyed ||
      this.active === null ||
      this.active.start !== start ||
      this.core.state.fork !== fork
    )
  }

  _reset() {
    this._clearActive()
  }

  _kick() {
    this._clearActive()
    if (!this.destroyed) this.replicator.updatePeer(this.peer)
  }

  _clearActive() {
    if (this.active !== null && this.active.timer) clearTimeout(this.active.timer)
    this.active = null
  }

  async _readRaw(index) {
    const rx = this.core.state.storage.read()
    const p = rx.getBlock(index)
    rx.tryFlush()
    try {
      return await p
    } catch (err) {
      safetyCatch(err)
      return null
    }
  }

  destroy() {
    this.destroyed = true
    this._clearActive()
    for (const ref of this.refs.slice()) {
      if (ref.context !== null) ref.context.detach(ref, null)
    }
    this.refs = []
  }
}

function onGroupTimeout(repair) {
  if (repair.destroyed || repair.active === null) return
  repair._kick()
}

async function hasLeaf(core, index) {
  const node = await MerkleTree.get(core.state, 2 * index)
  return node !== null
}

function pad(buf, symbolSize) {
  if (buf.byteLength === symbolSize) return buf
  const out = b4a.alloc(symbolSize)
  out.set(buf)
  return out
}

module.exports = { CodedRepair, serveCodedRequest }
