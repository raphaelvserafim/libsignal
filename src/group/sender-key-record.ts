import { SenderKeyState, SenderKeyStateStructure } from './sender-key-state.js'

/** BufferJSON reviver for deserializing Buffer instances from JSON */
const BufferJSONReviver = (_key: string, value: unknown): unknown => {
  if (
    value &&
    typeof value === 'object' &&
    'type' in (value as Record<string, unknown>) &&
    (value as Record<string, unknown>).type === 'Buffer' &&
    'data' in (value as Record<string, unknown>)
  ) {
    return Buffer.from((value as { data: number[] }).data)
  }
  return value
}

export class SenderKeyRecord {
  private readonly MAX_STATES = 5
  private readonly senderKeyStates: SenderKeyState[] = []

  constructor(serialized?: SenderKeyStateStructure[]) {
    if (serialized) {
      for (const structure of serialized) {
        this.senderKeyStates.push(new SenderKeyState(null, null, null, null, null, null, structure))
      }
    }
  }

  public isEmpty(): boolean {
    return this.senderKeyStates.length === 0
  }

  public getSenderKeyState(keyId?: number): SenderKeyState | undefined {
    if (keyId === undefined && this.senderKeyStates.length) {
      return this.senderKeyStates[this.senderKeyStates.length - 1]
    }

    return this.senderKeyStates.find((state) => state.getKeyId() === keyId)
  }

  public addSenderKeyState(id: number, iteration: number, chainKey: Uint8Array, signatureKey: Uint8Array): void {
    this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, null, signatureKey))
    if (this.senderKeyStates.length > this.MAX_STATES) {
      this.senderKeyStates.shift()
    }
  }

  public setSenderKeyState(
    id: number,
    iteration: number,
    chainKey: Uint8Array,
    keyPair: { public: Uint8Array; private: Uint8Array },
  ): void {
    this.senderKeyStates.length = 0
    this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, keyPair))
  }

  public serialize(): SenderKeyStateStructure[] {
    return this.senderKeyStates.map((state) => state.getStructure())
  }

  static deserialize(data: Uint8Array | string | SenderKeyStateStructure[]): SenderKeyRecord {
    let parsed: SenderKeyStateStructure[]
    if (typeof data === 'string') {
      parsed = JSON.parse(data, BufferJSONReviver)
    } else if (data instanceof Uint8Array) {
      const str = Buffer.from(data).toString('utf-8')
      parsed = JSON.parse(str, BufferJSONReviver)
    } else {
      parsed = data
    }

    return new SenderKeyRecord(parsed)
  }
}
