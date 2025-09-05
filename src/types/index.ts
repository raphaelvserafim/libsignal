export const BaseKeyType = {
  OURS: 1,
  THEIRS: 2
} as const;

export const ChainType = {
  SENDING: 1,
  RECEIVING: 2
} as const;

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



