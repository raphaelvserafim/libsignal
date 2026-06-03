import { describe, it, expect } from 'vitest'
import { SessionEntry } from '../../src/protocol/session-entry'
import { BaseKeyType, ChainType } from '../../src/types/index'
import curve from '../../src/crypto/curve'

function createTestSession(): SessionEntry {
  const entry = new SessionEntry()
  const ephemeralKeyPair = curve.generateKeyPair()
  const remoteKey = curve.generateKeyPair()

  entry.registrationId = 12345
  entry.currentRatchet = {
    rootKey: Buffer.alloc(32, 0x01),
    ephemeralKeyPair,
    lastRemoteEphemeralKey: remoteKey.pubKey,
    previousCounter: 0,
  }
  entry.indexInfo = {
    baseKey: ephemeralKeyPair.pubKey,
    baseKeyType: BaseKeyType.OURS,
    closed: -1,
    used: Date.now(),
    created: Date.now(),
    remoteIdentityKey: remoteKey.pubKey,
  }
  return entry
}

describe('SessionEntry', () => {
  describe('chains', () => {
    it('should add and get a chain', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      const chain = {
        messageKeys: {},
        chainKey: { counter: -1, key: Buffer.alloc(32, 0x02) },
        chainType: ChainType.SENDING,
      }
      entry.addChain(key, chain)
      const retrieved = entry.getChain(key)
      expect(retrieved).toBeDefined()
      expect(retrieved!.chainType).toBe(ChainType.SENDING)
    })

    it('should throw on overwrite attempt', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      const chain = {
        messageKeys: {},
        chainKey: { counter: -1, key: Buffer.alloc(32) },
        chainType: ChainType.SENDING,
      }
      entry.addChain(key, chain)
      expect(() => entry.addChain(key, chain)).toThrow('Overwrite attempt')
    })

    it('should return undefined for non-existent chain', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      expect(entry.getChain(key)).toBeUndefined()
    })

    it('should delete a chain', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      entry.addChain(key, {
        messageKeys: {},
        chainKey: { counter: 0, key: Buffer.alloc(32) },
        chainType: ChainType.RECEIVING,
      })
      entry.deleteChain(key)
      expect(entry.getChain(key)).toBeUndefined()
    })

    it('should throw when deleting non-existent chain', () => {
      const entry = createTestSession()
      expect(() => entry.deleteChain(Buffer.alloc(33, 0xff))).toThrow('Not Found')
    })

    it('should iterate chains', () => {
      const entry = createTestSession()
      const key1 = curve.generateKeyPair().pubKey
      const key2 = curve.generateKeyPair().pubKey
      entry.addChain(key1, {
        messageKeys: {},
        chainKey: { counter: 0, key: Buffer.alloc(32) },
        chainType: ChainType.SENDING,
      })
      entry.addChain(key2, {
        messageKeys: {},
        chainKey: { counter: 0, key: Buffer.alloc(32) },
        chainType: ChainType.RECEIVING,
      })
      const chains = Array.from(entry.chains())
      expect(chains).toHaveLength(2)
      expect(chains[0][0]).toBeInstanceOf(Buffer)
    })
  })

  describe('serialize / deserialize', () => {
    it('should roundtrip a session entry', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      entry.addChain(key, {
        messageKeys: { 0: Buffer.alloc(32, 0xaa), 1: Buffer.alloc(32, 0xbb) },
        chainKey: { counter: 1, key: Buffer.alloc(32, 0xcc) },
        chainType: ChainType.SENDING,
      })
      entry.pendingPreKey = {
        signedKeyId: 5,
        baseKey: curve.generateKeyPair().pubKey,
        preKeyId: 10,
      }

      const serialized = entry.serialize()
      const deserialized = SessionEntry.deserialize(serialized)

      expect(deserialized.registrationId).toBe(entry.registrationId)
      expect(deserialized.currentRatchet.rootKey.equals(entry.currentRatchet.rootKey)).toBe(true)
      expect(
        deserialized.currentRatchet.ephemeralKeyPair.pubKey.equals(entry.currentRatchet.ephemeralKeyPair.pubKey),
      ).toBe(true)
      expect(
        deserialized.currentRatchet.ephemeralKeyPair.privKey.equals(entry.currentRatchet.ephemeralKeyPair.privKey),
      ).toBe(true)
      expect(
        deserialized.currentRatchet.lastRemoteEphemeralKey.equals(entry.currentRatchet.lastRemoteEphemeralKey),
      ).toBe(true)
      expect(deserialized.currentRatchet.previousCounter).toBe(0)
      expect(deserialized.indexInfo.baseKeyType).toBe(BaseKeyType.OURS)
      expect(deserialized.indexInfo.closed).toBe(-1)
      expect(deserialized.pendingPreKey).toBeDefined()
      expect(deserialized.pendingPreKey!.signedKeyId).toBe(5)
      expect(deserialized.pendingPreKey!.preKeyId).toBe(10)

      const chain = deserialized.getChain(key)
      expect(chain).toBeDefined()
      expect(chain!.messageKeys[0].equals(Buffer.alloc(32, 0xaa))).toBe(true)
      expect(chain!.messageKeys[1].equals(Buffer.alloc(32, 0xbb))).toBe(true)
      expect(chain!.chainKey.counter).toBe(1)
    })

    it('should roundtrip without pendingPreKey', () => {
      const entry = createTestSession()
      const serialized = entry.serialize()
      const deserialized = SessionEntry.deserialize(serialized)
      expect(deserialized.pendingPreKey).toBeUndefined()
    })

    it('should roundtrip with closed chain key', () => {
      const entry = createTestSession()
      const key = curve.generateKeyPair().pubKey
      entry.addChain(key, {
        messageKeys: {},
        chainKey: { counter: 5, key: undefined },
        chainType: ChainType.RECEIVING,
      })
      const serialized = entry.serialize()
      const deserialized = SessionEntry.deserialize(serialized)
      const chain = deserialized.getChain(key)
      expect(chain!.chainKey.key).toBeUndefined()
      expect(chain!.chainKey.counter).toBe(5)
    })
  })

  describe('toString', () => {
    it('should include base key', () => {
      const entry = createTestSession()
      expect(entry.toString()).toMatch(/^<SessionEntry \[baseKey=.+\]>$/)
    })
  })
})
