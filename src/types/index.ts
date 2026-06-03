export enum BaseKeyType {
  OURS = 1,
  THEIRS = 2,
}

export enum ChainType {
  SENDING = 1,
  RECEIVING = 2,
}

export interface KeyPair {
  pubKey: Buffer
  privKey: Buffer
}

export interface PreKey {
  keyId: number
  publicKey: Buffer
}

export interface SignedPreKey {
  keyId: number
  publicKey: Buffer
  signature: Buffer
}

export interface Device {
  identityKey: Buffer
  registrationId: number
  preKey?: PreKey
  signedPreKey: SignedPreKey
}

export interface ChainKey {
  counter: number
  key?: Buffer
}

export interface Chain {
  chainKey: ChainKey
  chainType: ChainType
  messageKeys: Record<number, Buffer>
}

export interface IndexInfo {
  baseKey: Buffer
  baseKeyType: BaseKeyType
  closed: number
  used: number
  created: number
  remoteIdentityKey: Buffer
}

export interface Ratchet {
  rootKey: Buffer
  ephemeralKeyPair: KeyPair
  lastRemoteEphemeralKey: Buffer
  previousCounter: number
}

export interface PendingPreKey {
  signedKeyId: number
  baseKey: Buffer
  preKeyId?: number
}

export interface IncomingMessage {
  identityKey: Buffer
  baseKey: Buffer
  preKeyId?: number
  signedPreKeyId: number
  registrationId: number
}

export interface SessionRecordInterface {
  getSession(key: Uint8Array): unknown
  getOpenSession(): unknown
  setSession(session: unknown): void
  closeSession(session: unknown): void
  getSessions(): unknown[]
  isClosed(session: unknown): boolean
  haveOpenSession(): boolean
  removeOldSessions(): void
  serialize(): SerializedSessionRecord
}

export interface StorageInterface {
  isTrustedIdentity(id: string, identityKey: Uint8Array): Promise<boolean>
  loadSession(address: string): Promise<SessionRecordInterface | undefined>
  storeSession(address: string, record: SessionRecordInterface): Promise<void>
  loadPreKey(keyId: number): Promise<KeyPair | undefined>
  loadSignedPreKey(keyId: number): Promise<KeyPair | undefined>
  getOurIdentity(): Promise<KeyPair>
  getOurRegistrationId?(): Promise<number>
  removePreKey?(keyId: number): Promise<void>
}

export interface SerializedChain {
  chainKey: {
    counter: number
    key: string | null
  }
  chainType: ChainType
  messageKeys: Record<string, string>
}

export interface SerializedSessionEntry {
  registrationId: number
  currentRatchet: {
    ephemeralKeyPair: {
      pubKey: string
      privKey: string
    }
    lastRemoteEphemeralKey: string
    previousCounter: number
    rootKey: string
  }
  indexInfo: {
    baseKey: string
    baseKeyType: BaseKeyType
    closed: number
    used: number
    created: number
    remoteIdentityKey: string
  }
  _chains: Record<string, SerializedChain>
  pendingPreKey?: {
    signedKeyId: number
    baseKey: string
    preKeyId?: number
  }
}

export interface SerializedSessionRecord {
  _sessions: Record<string, SerializedSessionEntry>
  version: string
}

export interface Migration {
  version: string
  migrate: (data: SerializedSessionRecord & { registrationId?: string }) => void
}

export type { SenderKeyStore } from '../group/group-cipher.js'
