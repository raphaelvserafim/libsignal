export enum BaseKeyType {
  OURS = 1,
  THEIRS = 2
}

export enum ChainType {
  SENDING = 1,
  RECEIVING = 2
}

export interface QueueJob<T> {
  awaitable: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: any) => void;
}

export interface KeyPair {
  pubKey: Buffer;
  privKey: Buffer;
}

export interface PreKey {
  keyId: number;
  publicKey: Buffer;
}

export interface SignedPreKey {
  keyId: number;
  publicKey: Buffer;
  signature: Buffer;
}

export interface Device {
  identityKey: Buffer;
  registrationId: number;
  preKey?: PreKey;
  signedPreKey: SignedPreKey;
}

export interface ChainKey {
  counter: number;
  key?: Buffer;
}


export interface Storage {
  isTrustedIdentity(id: string, identityKey: Buffer): Promise<boolean>;
  loadSession(fqAddr: string): Promise<any>;
  storeSession(fqAddr: string, record: any): Promise<void>;
  loadPreKey(preKeyId: number): Promise<KeyPair | undefined>;
  loadSignedPreKey(signedPreKeyId: number): Promise<KeyPair | undefined>;
  getOurIdentity(): Promise<KeyPair>;
}

export interface IncomingMessage {
  identityKey: Buffer;
  baseKey: Buffer;
  preKeyId?: number;
  signedPreKeyId: number;
  registrationId: number;
}




export interface Chain {
  chainKey: ChainKey;
  chainType: number;
  messageKeys: { [index: string]: Buffer };
}

export interface IndexInfo {
  baseKey: Buffer;
  baseKeyType: number;
  closed: number;
  used: number;
  created: number;
  remoteIdentityKey: Buffer;
}

export interface CurrentRatchet {
  ephemeralKeyPair: KeyPair;
  lastRemoteEphemeralKey: Buffer;
  previousCounter: number;
  rootKey: Buffer;
}

export interface PendingPreKey {
  baseKey: Buffer;
  [key: string]: any;
}

export interface SessionData {
  registrationId: number;
  currentRatchet: any;
  indexInfo: any;
  _chains: any;
  pendingPreKey?: any;
}

export interface SessionRecordData {
  _sessions: { [key: string]: SessionData };
  version: string;
  registrationId?: number;
}

export interface Migration {
  version: string;
  migrate: (data: SessionRecordData) => void;
}





export interface ProtocolAddress {
  id: string;
  deviceId: number;
  toString(): string;
}

export interface SessionRatchet {
  rootKey: Buffer;
  ephemeralKeyPair: KeyPair;
  lastRemoteEphemeralKey: Uint8Array;
  previousCounter: number;
}

export interface SessionIndexInfo {
  created: number;
  used: number;
  remoteIdentityKey: Uint8Array;
  baseKey: Uint8Array;
  baseKeyType: BaseKeyType;
  closed: number;
}

export interface SessionChainKey {
  counter: number;
  key: Buffer;
}

export interface SessionChain {
  messageKeys: Record<number, Buffer>;
  chainKey: SessionChainKey;
  chainType: ChainType;
}

export interface Session {
  registrationId: number;
  currentRatchet: SessionRatchet;
  indexInfo: SessionIndexInfo;
  pendingPreKey?: {
    signedKeyId: number;
    baseKey: Uint8Array;
    preKeyId?: number;
  };
  addChain(key: Uint8Array, chain: SessionChain): void;
  getChain(key: Uint8Array): SessionChain | undefined;
  deleteChain(key: Uint8Array): void;
}

export interface SessionRecordInterface {
  getSession(baseKey: Uint8Array): Session | undefined;
  getOpenSession(): Session | undefined;
  closeSession(session: Session): void;
  setSession(session: Session): void;
  getSessions(): Session[];
  isClosed(session: Session): boolean;
}

export interface StorageInterface {
  isTrustedIdentity(id: string, identityKey: Uint8Array): Promise<boolean>;
  loadSession(address: string): Promise<SessionRecordInterface | undefined>;
  storeSession(address: string, record: SessionRecordInterface): Promise<void>;
  loadPreKey(keyId: number): Promise<KeyPair | undefined>;
  loadSignedPreKey(keyId: number): Promise<KeyPair | undefined>;
  getOurIdentity(): Promise<KeyPair>;
  removePreKey(keyId: number): Promise<void>;
}