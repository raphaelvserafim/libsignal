/**
 * Minimal protobuf encode/decode for Signal Group Protocol messages.
 * Self-contained — no dependency on @raphaelvserafim/whatsapp-proto.
 *
 * SenderKeyMessage:        { id: uint32, iteration: uint32, ciphertext: bytes }
 * SenderKeyDistributionMessage: { id: uint32, iteration: uint32, chainKey: bytes, signingKey: bytes }
 */
import $protobuf from 'protobufjs/minimal.js'

interface ProtoWriter {
  uint32(value: number): ProtoWriter
  bytes(value: Uint8Array): ProtoWriter
  finish(): Uint8Array
}

interface ProtoReader {
  pos: number
  len: number
  uint32(): number
  bytes(): Uint8Array
  skipType(wireType: number): void
}

const createWriter = (): ProtoWriter => $protobuf.Writer.create() as unknown as ProtoWriter
const createReader = (data: Uint8Array): ProtoReader => $protobuf.Reader.create(data) as unknown as ProtoReader

// ---- SenderKeyMessage ----

export interface ISenderKeyMessageProto {
  id: number
  iteration: number
  ciphertext: Uint8Array
}

export const SenderKeyMessageProto = {
  create(props: Partial<ISenderKeyMessageProto>): ISenderKeyMessageProto {
    return {
      id: props.id ?? 0,
      iteration: props.iteration ?? 0,
      ciphertext: props.ciphertext ?? new Uint8Array(0),
    }
  },

  encode(message: ISenderKeyMessageProto): Uint8Array {
    const w = createWriter()
    if (message.id) w.uint32(8).uint32(message.id)
    if (message.iteration) w.uint32(16).uint32(message.iteration)
    if (message.ciphertext.length) w.uint32(26).bytes(message.ciphertext)
    return w.finish()
  },

  decode(data: Uint8Array): ISenderKeyMessageProto {
    const r = createReader(data)
    const msg: ISenderKeyMessageProto = { id: 0, iteration: 0, ciphertext: new Uint8Array(0) }
    while (r.pos < r.len) {
      const tag = r.uint32()
      switch (tag >>> 3) {
        case 1:
          msg.id = r.uint32()
          break
        case 2:
          msg.iteration = r.uint32()
          break
        case 3:
          msg.ciphertext = r.bytes()
          break
        default:
          r.skipType(tag & 7)
      }
    }
    return msg
  },
}

// ---- SenderKeyDistributionMessage ----

export interface ISenderKeyDistributionMessageProto {
  id: number
  iteration: number
  chainKey: Uint8Array
  signingKey: Uint8Array
}

export const SenderKeyDistributionMessageProto = {
  create(props: Partial<ISenderKeyDistributionMessageProto>): ISenderKeyDistributionMessageProto {
    return {
      id: props.id ?? 0,
      iteration: props.iteration ?? 0,
      chainKey: props.chainKey ?? new Uint8Array(0),
      signingKey: props.signingKey ?? new Uint8Array(0),
    }
  },

  encode(message: ISenderKeyDistributionMessageProto): Uint8Array {
    const w = createWriter()
    if (message.id) w.uint32(8).uint32(message.id)
    if (message.iteration) w.uint32(16).uint32(message.iteration)
    if (message.chainKey.length) w.uint32(26).bytes(message.chainKey)
    if (message.signingKey.length) w.uint32(34).bytes(message.signingKey)
    return w.finish()
  },

  decode(data: Uint8Array): ISenderKeyDistributionMessageProto {
    const r = createReader(data)
    const msg: ISenderKeyDistributionMessageProto = {
      id: 0,
      iteration: 0,
      chainKey: new Uint8Array(0),
      signingKey: new Uint8Array(0),
    }
    while (r.pos < r.len) {
      const tag = r.uint32()
      switch (tag >>> 3) {
        case 1:
          msg.id = r.uint32()
          break
        case 2:
          msg.iteration = r.uint32()
          break
        case 3:
          msg.chainKey = r.bytes()
          break
        case 4:
          msg.signingKey = r.bytes()
          break
        default:
          r.skipType(tag & 7)
      }
    }
    return msg
  },
}
