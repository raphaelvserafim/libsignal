export class SessionEntry {
  _chains: { [key: string]: any };
  indexInfo: any;
  currentRatchet: any;
  pendingPreKey: any;
  registrationId: number;

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

  addChain(key: any, value: any) {
    const id = key.toString('base64');
    if (this._chains.hasOwnProperty(id)) {
      throw new Error("Overwrite attempt");
    }
    this._chains[id] = value;
  }

  getChain(key: any) {
    return this._chains[key.toString('base64')];
  }

  deleteChain(key: any) {
    const id = key.toString('base64');
    if (!this._chains.hasOwnProperty(id)) {
      throw new ReferenceError("Not Found");
    }
    delete this._chains[id];
  }

  *chains() {
    for (const [k, v] of Object.entries(this._chains)) {
      yield [Buffer.from(k, 'base64'), v];
    }
  }

  serialize() {
    const data: any = {
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
      _chains: this._serialize_chains(this._chains)
    };
    if (this.pendingPreKey) {
      data.pendingPreKey = Object.assign({}, this.pendingPreKey);
      data.pendingPreKey.baseKey = this.pendingPreKey.baseKey.toString('base64');
    }
    return data;
  }

  static deserialize(data: any) {
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
    obj._chains = this._deserialize_chains(data._chains);
    if (data.pendingPreKey) {
      obj.pendingPreKey = Object.assign({}, data.pendingPreKey);
      obj.pendingPreKey.baseKey = Buffer.from(data.pendingPreKey.baseKey, 'base64');
    }
    return obj;
  }

  _serialize_chains(chains: any) {
    const r: any = {};
    for (const key of Object.keys(chains)) {
      const c = chains[key];
      const messageKeys: any = {};
      for (const [idx, key] of Object.entries(c.messageKeys)) {
        // @ts-ignore
        messageKeys[idx] = key.toString('base64');
      }
      r[key] = {
        chainKey: {
          counter: c.chainKey.counter,
          key: c.chainKey.key && c.chainKey.key.toString('base64')
        },
        chainType: c.chainType,
        messageKeys: messageKeys
      };
    }
    return r;
  }

  static _deserialize_chains(chains_data: any) {
    const r: any = {};
    for (const key of Object.keys(chains_data)) {
      const c = chains_data[key];
      const messageKeys: any = {};
      for (const [idx, key] of Object.entries(c.messageKeys)) {
        // @ts-ignore
        messageKeys[idx] = Buffer.from(key, 'base64');
      }
      r[key] = {
        chainKey: {
          counter: c.chainKey.counter,
          key: c.chainKey.key && Buffer.from(c.chainKey.key, 'base64')
        },
        chainType: c.chainType,
        messageKeys: messageKeys
      };
    }
    return r;
  }

}
