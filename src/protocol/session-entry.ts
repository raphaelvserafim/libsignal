/**
 * SessionEntry represents a single session state with its chains and ratchet information.
 * @raphaelvserafim
 */

/**
 * Limpa um buffer de forma segura
 */
function secureZeroBuffer(buffer: Buffer | null | undefined): void {
  if (buffer && Buffer.isBuffer(buffer)) {
    buffer.fill(0);
  }
}

/**
 * Limpa um objeto contendo buffers de forma recursiva
 */
function secureZeroObject(obj: any): void {
  if (!obj) return;

  if (Buffer.isBuffer(obj)) {
    secureZeroBuffer(obj);
    return;
  }

  if (typeof obj === 'object') {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        secureZeroObject(obj[key]);
      }
    }
  }
}

export class SessionEntry {
  _chains: { [key: string]: any };
  indexInfo: any;
  currentRatchet: any;
  pendingPreKey: any;
  registrationId: number;

  constructor() {
    this._chains = {};
    this.indexInfo = null;
    this.currentRatchet = null;
    this.pendingPreKey = null;
    this.registrationId = 0;
  }

  toString(): string {
    const baseKeyPreview = this.indexInfo?.baseKey ? `${this.indexInfo.baseKey.toString('base64').substring(0, 8)}...` : 'null';
    return `<SessionEntry [baseKey=${baseKeyPreview}]>`;
  }

  inspect(): string {
    return this.toString();
  }

  addChain(key: any, value: any): void {
    // Validação de entrada
    if (!key) {
      throw new TypeError("key is required");
    }
    if (!Buffer.isBuffer(key)) {
      throw new TypeError("key must be a Buffer");
    }
    if (!value) {
      throw new TypeError("value is required");
    }
    if (typeof value !== 'object') {
      throw new TypeError("value must be an object");
    }

    // Validação da estrutura do valor
    if (!value.chainKey || typeof value.chainKey !== 'object') {
      throw new TypeError("value must have a chainKey object");
    }
    if (value.chainKey.counter === undefined || !Number.isInteger(value.chainKey.counter)) {
      throw new TypeError("value.chainKey.counter must be an integer");
    }
    if (!value.messageKeys || typeof value.messageKeys !== 'object') {
      throw new TypeError("value must have a messageKeys object");
    }
    if (value.chainType === undefined) {
      throw new TypeError("value must have a chainType");
    }

    const id = key.toString('base64');
    if (this._chains.hasOwnProperty(id)) {
      throw new Error("Chain already exists - overwrite attempt");
    }

    // Clone profundo para evitar modificações externas
    this._chains[id] = {
      chainKey: {
        counter: value.chainKey.counter,
        key: value.chainKey.key ? Buffer.from(value.chainKey.key) : undefined
      },
      chainType: value.chainType,
      messageKeys: { ...value.messageKeys }
    };
  }

  getChain(key: any): any | undefined {
    if (!key) {
      throw new TypeError("key is required");
    }
    if (!Buffer.isBuffer(key)) {
      throw new TypeError("key must be a Buffer");
    }

    const chain = this._chains[key.toString('base64')];

    // Retornar clone para evitar modificações externas
    if (chain) {
      return {
        chainKey: {
          counter: chain.chainKey.counter,
          key: chain.chainKey.key ? Buffer.from(chain.chainKey.key) : undefined
        },
        chainType: chain.chainType,
        messageKeys: { ...chain.messageKeys }
      };
    }

    return undefined;
  }

  deleteChain(key: any): void {
    if (!key) {
      throw new TypeError("key is required");
    }
    if (!Buffer.isBuffer(key)) {
      throw new TypeError("key must be a Buffer");
    }

    const id = key.toString('base64');
    if (!this._chains.hasOwnProperty(id)) {
      throw new ReferenceError("Chain not found");
    }

    const chain = this._chains[id];
    if (chain) {
      // Limpar chaves de mensagens
      if (chain.messageKeys) {
        for (const msgKey in chain.messageKeys) {
          secureZeroBuffer(chain.messageKeys[msgKey]);
        }
      }
      // Limpar chave da cadeia
      secureZeroBuffer(chain.chainKey?.key);
    }

    delete this._chains[id];
  }

  *chains(): Generator<[Buffer, any], void, unknown> {
    for (const [k, v] of Object.entries(this._chains)) {
      // Retornar clones para evitar modificações externas
      yield [
        Buffer.from(k, 'base64'),
        {
          chainKey: {
            counter: v.chainKey.counter,
            key: v.chainKey.key ? Buffer.from(v.chainKey.key) : undefined
          },
          chainType: v.chainType,
          messageKeys: { ...v.messageKeys }
        }
      ];
    }
  }

  serialize(): any {
    // Validação de campos obrigatórios
    if (this.registrationId === undefined || this.registrationId === null) {
      throw new Error("Cannot serialize: registrationId is missing");
    }
    if (!this.currentRatchet) {
      throw new Error("Cannot serialize: currentRatchet is missing");
    }
    if (!this.indexInfo) {
      throw new Error("Cannot serialize: indexInfo is missing");
    }

    // Validação do currentRatchet
    if (!this.currentRatchet.ephemeralKeyPair?.pubKey || !this.currentRatchet.ephemeralKeyPair?.privKey) {
      throw new Error("Cannot serialize: currentRatchet.ephemeralKeyPair is incomplete");
    }
    if (!this.currentRatchet.lastRemoteEphemeralKey) {
      throw new Error("Cannot serialize: currentRatchet.lastRemoteEphemeralKey is missing");
    }
    if (this.currentRatchet.previousCounter === undefined) {
      throw new Error("Cannot serialize: currentRatchet.previousCounter is missing");
    }
    if (!this.currentRatchet.rootKey) {
      throw new Error("Cannot serialize: currentRatchet.rootKey is missing");
    }

    // Validação do indexInfo
    if (!this.indexInfo.baseKey) {
      throw new Error("Cannot serialize: indexInfo.baseKey is missing");
    }
    if (this.indexInfo.baseKeyType === undefined) {
      throw new Error("Cannot serialize: indexInfo.baseKeyType is missing");
    }
    if (!this.indexInfo.remoteIdentityKey) {
      throw new Error("Cannot serialize: indexInfo.remoteIdentityKey is missing");
    }

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
        closed: this.indexInfo.closed ?? -1,
        used: this.indexInfo.used ?? Date.now(),
        created: this.indexInfo.created ?? Date.now(),
        remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
      },
      _chains: this._serialize_chains(this._chains)
    };

    if (this.pendingPreKey) {
      if (!this.pendingPreKey.baseKey) {
        throw new Error("Cannot serialize: pendingPreKey.baseKey is missing");
      }
      if (this.pendingPreKey.signedKeyId === undefined) {
        throw new Error("Cannot serialize: pendingPreKey.signedKeyId is missing");
      }

      data.pendingPreKey = {
        signedKeyId: this.pendingPreKey.signedKeyId,
        baseKey: this.pendingPreKey.baseKey.toString('base64')
      };

      if (this.pendingPreKey.preKeyId !== undefined) {
        data.pendingPreKey.preKeyId = this.pendingPreKey.preKeyId;
      }
    }

    return data;
  }

  static deserialize(data: any): SessionEntry {
    // Validação de entrada
    if (!data || typeof data !== 'object') {
      throw new TypeError("data must be an object");
    }
    if (data.registrationId === undefined || data.registrationId === null) {
      throw new Error("Invalid serialized data: registrationId is missing");
    }
    if (!data.currentRatchet || typeof data.currentRatchet !== 'object') {
      throw new Error("Invalid serialized data: currentRatchet is missing or invalid");
    }
    if (!data.indexInfo || typeof data.indexInfo !== 'object') {
      throw new Error("Invalid serialized data: indexInfo is missing or invalid");
    }
    if (!data._chains || typeof data._chains !== 'object') {
      throw new Error("Invalid serialized data: _chains is missing or invalid");
    }

    const obj = new this();

    try {
      obj.registrationId = data.registrationId;

      // Desserializar currentRatchet com validação
      if (!data.currentRatchet.ephemeralKeyPair?.pubKey || !data.currentRatchet.ephemeralKeyPair?.privKey) {
        throw new Error("Invalid currentRatchet.ephemeralKeyPair");
      }
      if (!data.currentRatchet.lastRemoteEphemeralKey) {
        throw new Error("Invalid currentRatchet.lastRemoteEphemeralKey");
      }
      if (!data.currentRatchet.rootKey) {
        throw new Error("Invalid currentRatchet.rootKey");
      }

      obj.currentRatchet = {
        ephemeralKeyPair: {
          pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
          privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
        },
        lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
        previousCounter: data.currentRatchet.previousCounter ?? 0,
        rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
      };

      // Desserializar indexInfo com validação
      if (!data.indexInfo.baseKey) {
        throw new Error("Invalid indexInfo.baseKey");
      }
      if (!data.indexInfo.remoteIdentityKey) {
        throw new Error("Invalid indexInfo.remoteIdentityKey");
      }

      obj.indexInfo = {
        baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
        baseKeyType: data.indexInfo.baseKeyType,
        closed: data.indexInfo.closed ?? -1,
        used: data.indexInfo.used ?? Date.now(),
        created: data.indexInfo.created ?? Date.now(),
        remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
      };

      obj._chains = this._deserialize_chains(data._chains);

      if (data.pendingPreKey) {
        if (!data.pendingPreKey.baseKey) {
          throw new Error("Invalid pendingPreKey.baseKey");
        }
        if (data.pendingPreKey.signedKeyId === undefined) {
          throw new Error("Invalid pendingPreKey.signedKeyId");
        }

        obj.pendingPreKey = {
          signedKeyId: data.pendingPreKey.signedKeyId,
          baseKey: Buffer.from(data.pendingPreKey.baseKey, 'base64')
        };

        if (data.pendingPreKey.preKeyId !== undefined) {
          obj.pendingPreKey.preKeyId = data.pendingPreKey.preKeyId;
        }
      }

      return obj;
    } catch (error) {
      // Limpar dados sensíveis em caso de erro
      secureZeroObject(obj);
      throw new Error(`Failed to deserialize SessionEntry: ${(error as Error).message}`);
    }
  }

  _serialize_chains(chains: any): any {
    if (!chains || typeof chains !== 'object') {
      throw new TypeError("chains must be an object");
    }

    const r: any = {};
    for (const key of Object.keys(chains)) {
      const c = chains[key];

      if (!c || typeof c !== 'object') {
        throw new Error(`Invalid chain at key ${key}`);
      }
      if (!c.chainKey || typeof c.chainKey !== 'object') {
        throw new Error(`Invalid chainKey at key ${key}`);
      }
      if (c.chainKey.counter === undefined) {
        throw new Error(`Missing chainKey.counter at key ${key}`);
      }

      const messageKeys: any = {};
      if (c.messageKeys && typeof c.messageKeys === 'object') {
        for (const [idx, msgKey] of Object.entries(c.messageKeys)) {
          if (!Buffer.isBuffer(msgKey)) {
            throw new Error(`Invalid messageKey at chain ${key}, index ${idx}`);
          }
          messageKeys[idx] = (msgKey as Buffer).toString('base64');
        }
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

  static _deserialize_chains(chains_data: any): any {
    if (!chains_data || typeof chains_data !== 'object') {
      throw new TypeError("chains_data must be an object");
    }

    const r: any = {};
    for (const key of Object.keys(chains_data)) {
      const c = chains_data[key];

      if (!c || typeof c !== 'object') {
        throw new Error(`Invalid chain data at key ${key}`);
      }
      if (!c.chainKey || typeof c.chainKey !== 'object') {
        throw new Error(`Invalid chainKey data at key ${key}`);
      }
      if (c.chainKey.counter === undefined) {
        throw new Error(`Missing chainKey.counter at key ${key}`);
      }

      const messageKeys: any = {};
      if (c.messageKeys && typeof c.messageKeys === 'object') {
        for (const [idx, msgKey] of Object.entries(c.messageKeys)) {
          if (typeof msgKey !== 'string') {
            throw new Error(`Invalid messageKey at chain ${key}, index ${idx}`);
          }
          try {
            messageKeys[idx] = Buffer.from(msgKey as string, 'base64');
          } catch (error) {
            throw new Error(`Invalid base64 in messageKey at chain ${key}, index ${idx}`);
          }
        }
      }

      r[key] = {
        chainKey: {
          counter: c.chainKey.counter,
          key: c.chainKey.key ? Buffer.from(c.chainKey.key, 'base64') : null
        },
        chainType: c.chainType,
        messageKeys: messageKeys
      };
    }
    return r;
  }

  /**
   * Limpa todos os dados sensíveis desta entrada de sessão
   */
  destroy(): void {
    // Limpar chains
    for (const chainId in this._chains) {
      const chain = this._chains[chainId];
      if (chain) {
        if (chain.messageKeys) {
          for (const msgKey in chain.messageKeys) {
            secureZeroBuffer(chain.messageKeys[msgKey]);
          }
        }
        secureZeroBuffer(chain.chainKey?.key);
      }
    }

    // Limpar currentRatchet
    if (this.currentRatchet) {
      secureZeroBuffer(this.currentRatchet.ephemeralKeyPair?.pubKey);
      secureZeroBuffer(this.currentRatchet.ephemeralKeyPair?.privKey);
      secureZeroBuffer(this.currentRatchet.lastRemoteEphemeralKey);
      secureZeroBuffer(this.currentRatchet.rootKey);
    }

    // Limpar indexInfo
    if (this.indexInfo) {
      secureZeroBuffer(this.indexInfo.baseKey);
      secureZeroBuffer(this.indexInfo.remoteIdentityKey);
    }

    // Limpar pendingPreKey
    if (this.pendingPreKey) {
      secureZeroBuffer(this.pendingPreKey.baseKey);
    }

    // Limpar referências
    this._chains = {};
    this.currentRatchet = null;
    this.indexInfo = null;
    this.pendingPreKey = null;
  }
}