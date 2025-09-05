import { CLOSED_SESSIONS_MAX, SESSION_RECORD_VERSION } from "../constants";
import { BaseKeyType, Chain, CurrentRatchet, IndexInfo, Migration, PendingPreKey, SessionData, SessionRecordData } from "../types";


class SessionEntry {

  public registrationId?: number;
  public currentRatchet?: CurrentRatchet;
  public indexInfo?: IndexInfo;
  public pendingPreKey?: PendingPreKey;
  private _chains: { [key: string]: Chain };

  constructor() {
    this._chains = {};
  }

  toString(): string {
    const baseKey = this.indexInfo && this.indexInfo.baseKey &&
      this.indexInfo.baseKey.toString('base64');
    return `<SessionEntry [baseKey=${baseKey}]>`;
  }

  inspect(): string {
    return this.toString();
  }

  addChain(key: Buffer, value: Chain): void {
    const id = key.toString('base64');
    if (this._chains.hasOwnProperty(id)) {
      throw new Error("Overwrite attempt");
    }
    this._chains[id] = value;
  }

  getChain(key: Buffer): Chain | undefined {
    return this._chains[key.toString('base64')];
  }

  deleteChain(key: Buffer): void {
    const id = key.toString('base64');
    if (!this._chains.hasOwnProperty(id)) {
      throw new ReferenceError("Not Found");
    }
    delete this._chains[id];
  }

  *chains(): Generator<[Buffer, Chain], void, unknown> {
    for (const [k, v] of Object.entries(this._chains)) {
      yield [Buffer.from(k, 'base64'), v];
    }
  }

  serialize(): SessionData {
    const data: SessionData = {
      registrationId: this.registrationId!,
      currentRatchet: {
        ephemeralKeyPair: {
          pubKey: this.currentRatchet!.ephemeralKeyPair.pubKey.toString('base64'),
          privKey: this.currentRatchet!.ephemeralKeyPair.privKey.toString('base64')
        },
        lastRemoteEphemeralKey: this.currentRatchet!.lastRemoteEphemeralKey.toString('base64'),
        previousCounter: this.currentRatchet!.previousCounter,
        rootKey: this.currentRatchet!.rootKey.toString('base64')
      },
      indexInfo: {
        baseKey: this.indexInfo!.baseKey.toString('base64'),
        baseKeyType: this.indexInfo!.baseKeyType,
        closed: this.indexInfo!.closed,
        used: this.indexInfo!.used,
        created: this.indexInfo!.created,
        remoteIdentityKey: this.indexInfo!.remoteIdentityKey.toString('base64')
      },
      _chains: this._serialize_chains(this._chains)
    };
    if (this.pendingPreKey) {
      data.pendingPreKey = Object.assign({}, this.pendingPreKey);
      data.pendingPreKey.baseKey = this.pendingPreKey.baseKey.toString('base64');
    }
    return data;
  }

  static deserialize(data: SessionData): SessionEntry {
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
      if (obj.pendingPreKey) {
        obj.pendingPreKey.baseKey = Buffer.from(data.pendingPreKey.baseKey, 'base64');
      }
    }
    return obj;
  }

  _serialize_chains(chains: { [key: string]: Chain }): any {
    const r: any = {};
    for (const key of Object.keys(chains)) {
      const c = chains[key];
      if (!c) continue;
      const messageKeys: { [index: string]: string } = {};
      for (const [idx, key] of Object.entries(c.messageKeys)) {
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

  static _deserialize_chains(chains_data: any): { [key: string]: Chain } {
    const r: { [key: string]: Chain } = {};
    for (const key of Object.keys(chains_data)) {
      const c = chains_data[key];
      const messageKeys: { [index: string]: Buffer } = {};
      for (const [idx, key] of Object.entries(c.messageKeys)) {
        messageKeys[idx] = Buffer.from(key as string, 'base64');
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

const migrations: Migration[] = [{
  version: 'v1',
  migrate: function migrateV1(data: SessionRecordData): void {
    const sessions = data._sessions;
    if (data.registrationId) {
      for (const key in sessions) {
        if (sessions[key] && !sessions[key].registrationId) {
          sessions[key].registrationId = data.registrationId;
        }
      }
    } else {
      for (const key in sessions) {
        if (sessions[key] && sessions[key].indexInfo.closed === -1) {
          console.error('V1 session storage migration error: registrationId',
            data.registrationId, 'for open session version',
            data.version);
        }
      }
    }
  }
}];

export class SessionRecord {
  public sessions: { [key: string]: SessionEntry };
  public version: string;

  static createEntry(): SessionEntry {
    return new SessionEntry();
  }

  static migrate(data: SessionRecordData): void {
    let run = (data.version === undefined);
    for (let i = 0; i < migrations.length; ++i) {
      const migration = migrations[i];
      if (!migration) continue;
      if (run) {
        migration.migrate(data);
      } else if (migration.version === data.version) {
        run = true;
      }
    }
    if (!run) {
      throw new Error("Error migrating SessionRecord");
    }
  }

  static deserialize(data: SessionRecordData): SessionRecord {
    if (data.version !== SESSION_RECORD_VERSION) {
      this.migrate(data);
    }
    const obj = new this();
    if (data._sessions) {
      for (const [key, entry] of Object.entries(data._sessions)) {
        obj.sessions[key] = SessionEntry.deserialize(entry);
      }
    }
    return obj;
  }

  constructor() {
    this.sessions = {};
    this.version = SESSION_RECORD_VERSION;
  }

  serialize(): SessionRecordData {
    const _sessions: { [key: string]: SessionData } = {};
    for (const [key, entry] of Object.entries(this.sessions)) {
      _sessions[key] = entry.serialize();
    }
    return {
      _sessions,
      version: this.version
    };
  }

  haveOpenSession(): boolean {
    const openSession = this.getOpenSession();
    return (!!openSession && typeof openSession.registrationId === 'number');
  }

  getSession(key: Buffer): SessionEntry | undefined {
    const session = this.sessions[key.toString('base64')];
    if (session && session.indexInfo!.baseKeyType === BaseKeyType.OURS) {
      throw new Error("Tried to lookup a session using our basekey");
    }
    return session;
  }

  getOpenSession(): SessionEntry | undefined {
    for (const session of Object.values(this.sessions)) {
      if (!this.isClosed(session)) {
        return session;
      }
    }
    return undefined;
  }

  setSession(session: SessionEntry): void {
    this.sessions[session.indexInfo!.baseKey.toString('base64')] = session;
  }

  getSessions(): SessionEntry[] {
    // Return sessions ordered with most recently used first.
    return Array.from(Object.values(this.sessions)).sort((a, b) => {
      const aUsed = a.indexInfo!.used || 0;
      const bUsed = b.indexInfo!.used || 0;
      return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
    });
  }

  closeSession(session: SessionEntry): void {
    if (this.isClosed(session)) {
      console.warn("Session already closed", session);
      return;
    }
    console.info("Closing session:", session);
    session.indexInfo!.closed = Date.now();
  }

  openSession(session: SessionEntry): void {
    if (!this.isClosed(session)) {
      console.warn("Session already open");
    }
    console.info("Opening session:", session);
    session.indexInfo!.closed = -1;
  }

  isClosed(session: SessionEntry): boolean {
    return session.indexInfo!.closed !== -1;
  }

  removeOldSessions(): void {
    while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
      let oldestKey: string | undefined;
      let oldestSession: SessionEntry | undefined;
      for (const [key, session] of Object.entries(this.sessions)) {
        if (session.indexInfo!.closed !== -1 &&
          (!oldestSession || session.indexInfo!.closed < oldestSession.indexInfo!.closed)) {
          oldestKey = key;
          oldestSession = session;
        }
      }
      if (oldestKey) {
        console.info("Removing old closed session:", oldestSession);
        delete this.sessions[oldestKey];
      } else {
        throw new Error('Corrupt sessions object');
      }
    }
  }

  deleteAllSessions(): void {
    for (const key of Object.keys(this.sessions)) {
      delete this.sessions[key];
    }
  }
}

export default SessionRecord;