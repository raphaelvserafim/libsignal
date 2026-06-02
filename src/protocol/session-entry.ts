import { Chain, ChainType, IndexInfo, PendingPreKey, Ratchet, SerializedChain, SerializedSessionEntry } from "../types/index.js";

export class SessionEntry {
  _chains: Record<string, Chain>;
  indexInfo!: IndexInfo;
  currentRatchet!: Ratchet;
  pendingPreKey?: PendingPreKey;
  registrationId!: number;

  constructor() {
    this._chains = {};
  }

  toString() {
    const baseKey = this.indexInfo && this.indexInfo.baseKey &&
      this.indexInfo.baseKey.toString('base64');
    return `<SessionEntry [baseKey=${baseKey}]>`;
  }

  inspect() {
    return this.toString();
  }

  addChain(key: Uint8Array, value: Chain) {
    const id = Buffer.from(key).toString('base64');
    if (this._chains.hasOwnProperty(id)) {
      throw new Error("Overwrite attempt");
    }
    this._chains[id] = value;
  }

  getChain(key: Uint8Array): Chain | undefined {
    return this._chains[Buffer.from(key).toString('base64')];
  }

  deleteChain(key: Uint8Array) {
    const id = Buffer.from(key).toString('base64');
    if (!this._chains.hasOwnProperty(id)) {
      throw new ReferenceError("Not Found");
    }
    delete this._chains[id];
  }

  *chains(): Generator<[Buffer, Chain]> {
    for (const [k, v] of Object.entries(this._chains)) {
      yield [Buffer.from(k, 'base64'), v];
    }
  }

  serialize(): SerializedSessionEntry {
    const data: SerializedSessionEntry = {
      registrationId: this.registrationId,
      currentRatchet: {
        ephemeralKeyPair: {
          pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
          privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
        },
        lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
        previousCounter: this.currentRatchet.previousCounter,
        rootKey: this.currentRatchet.rootKey.toString('base64')
      },
      indexInfo: {
        baseKey: this.indexInfo.baseKey.toString('base64'),
        baseKeyType: this.indexInfo.baseKeyType,
        closed: this.indexInfo.closed,
        used: this.indexInfo.used,
        created: this.indexInfo.created,
        remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
      },
      _chains: this._serializeChains(this._chains),
      ...(this.pendingPreKey ? {
        pendingPreKey: {
          signedKeyId: this.pendingPreKey.signedKeyId,
          baseKey: this.pendingPreKey.baseKey.toString('base64'),
          ...(this.pendingPreKey.preKeyId !== undefined ? { preKeyId: this.pendingPreKey.preKeyId } : {})
        }
      } : {})
    };
    return data;
  }

  static deserialize(data: SerializedSessionEntry): SessionEntry {
    const obj = new this();
    obj.registrationId = data.registrationId;
    obj.currentRatchet = {
      ephemeralKeyPair: {
        pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
        privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
      },
      lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
      previousCounter: data.currentRatchet.previousCounter,
      rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
    };
    obj.indexInfo = {
      baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
      baseKeyType: data.indexInfo.baseKeyType,
      closed: data.indexInfo.closed,
      used: data.indexInfo.used,
      created: data.indexInfo.created,
      remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
    };
    obj._chains = this._deserializeChains(data._chains);
    if (data.pendingPreKey) {
      obj.pendingPreKey = {
        signedKeyId: data.pendingPreKey.signedKeyId,
        baseKey: Buffer.from(data.pendingPreKey.baseKey, 'base64'),
        ...(data.pendingPreKey.preKeyId !== undefined ? { preKeyId: data.pendingPreKey.preKeyId } : {})
      };
    }
    return obj;
  }

  private _serializeChains(chains: Record<string, Chain>): Record<string, SerializedChain> {
    const r: Record<string, SerializedChain> = {};
    for (const key of Object.keys(chains)) {
      const c = chains[key];
      const messageKeys: Record<string, string> = {};
      for (const [idx, value] of Object.entries(c.messageKeys)) {
        messageKeys[idx] = value.toString('base64');
      }
      r[key] = {
        chainKey: {
          counter: c.chainKey.counter,
          key: c.chainKey.key ? c.chainKey.key.toString('base64') : null
        },
        chainType: c.chainType,
        messageKeys: messageKeys
      };
    }
    return r;
  }

  static _deserializeChains(chainsData: Record<string, SerializedChain>): Record<string, Chain> {
    const r: Record<string, Chain> = {};
    for (const key of Object.keys(chainsData)) {
      const c = chainsData[key];
      const messageKeys: Record<number, Buffer> = {};
      for (const [idx, value] of Object.entries(c.messageKeys)) {
        messageKeys[Number(idx)] = Buffer.from(value, 'base64');
      }
      r[key] = {
        chainKey: {
          counter: c.chainKey.counter,
          key: c.chainKey.key ? Buffer.from(c.chainKey.key, 'base64') : undefined
        },
        chainType: c.chainType,
        messageKeys: messageKeys
      };
    }
    return r;
  }
}
