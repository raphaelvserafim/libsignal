import { describe, it, expect } from 'vitest'
import { SessionRecord } from '../../src/protocol/session-record'
import { SessionEntry } from '../../src/protocol/session-entry'
import { BaseKeyType } from '../../src/types/index'
import curve from '../../src/crypto/curve'

function createTestEntry(closed = -1): SessionEntry {
  const entry = new SessionEntry()
  const kp = curve.generateKeyPair()
  const remote = curve.generateKeyPair()

  entry.registrationId = Math.floor(Math.random() * 16384)
  entry.currentRatchet = {
    rootKey: Buffer.alloc(32, 0x01),
    ephemeralKeyPair: kp,
    lastRemoteEphemeralKey: remote.pubKey,
    previousCounter: 0,
  }
  entry.indexInfo = {
    baseKey: kp.pubKey,
    baseKeyType: BaseKeyType.OURS,
    closed,
    used: Date.now(),
    created: Date.now(),
    remoteIdentityKey: remote.pubKey,
  }
  return entry
}

function createTheirsEntry(closed = -1): SessionEntry {
  const entry = createTestEntry(closed)
  entry.indexInfo.baseKeyType = BaseKeyType.THEIRS
  entry.indexInfo.baseKey = curve.generateKeyPair().pubKey
  return entry
}

describe('SessionRecord', () => {
  it('should create an empty record', () => {
    const record = new SessionRecord()
    expect(record.version).toBe('v1')
    expect(Object.keys(record.sessions)).toHaveLength(0)
  })

  describe('session management', () => {
    it('should set and get a session', () => {
      const record = new SessionRecord()
      const entry = createTheirsEntry()
      record.setSession(entry)
      const found = record.getSession(entry.indexInfo.baseKey)
      expect(found).toBeDefined()
      expect(found!.registrationId).toBe(entry.registrationId)
    })

    it('should throw when looking up our own basekey', () => {
      const record = new SessionRecord()
      const entry = createTestEntry() // OURS baseKeyType
      record.setSession(entry)
      expect(() => record.getSession(entry.indexInfo.baseKey)).toThrow('Tried to lookup a session using our basekey')
    })

    it('should return undefined for unknown key', () => {
      const record = new SessionRecord()
      expect(record.getSession(Buffer.alloc(33, 0xff))).toBeUndefined()
    })

    it('should accept Uint8Array for getSession', () => {
      const record = new SessionRecord()
      const entry = createTheirsEntry()
      record.setSession(entry)
      const uint8Key = new Uint8Array(entry.indexInfo.baseKey)
      const found = record.getSession(uint8Key)
      expect(found).toBeDefined()
    })
  })

  describe('open/close sessions', () => {
    it('should find open session', () => {
      const record = new SessionRecord()
      const entry = createTestEntry(-1)
      record.setSession(entry)
      expect(record.haveOpenSession()).toBe(true)
      expect(record.getOpenSession()).toBe(entry)
    })

    it('should close session', () => {
      const record = new SessionRecord()
      const entry = createTestEntry(-1)
      record.setSession(entry)
      record.closeSession(entry)
      expect(record.isClosed(entry)).toBe(true)
      expect(record.haveOpenSession()).toBe(false)
    })

    it('should reopen session', () => {
      const record = new SessionRecord()
      const entry = createTestEntry(-1)
      record.setSession(entry)
      record.closeSession(entry)
      record.openSession(entry)
      expect(record.isClosed(entry)).toBe(false)
    })

    it('should return false when no sessions exist', () => {
      const record = new SessionRecord()
      expect(record.haveOpenSession()).toBe(false)
    })
  })

  describe('getSessions', () => {
    it('should return sessions sorted by most recently used', () => {
      const record = new SessionRecord()
      const e1 = createTestEntry()
      e1.indexInfo.used = 100
      const e2 = createTestEntry()
      e2.indexInfo.used = 300
      const e3 = createTestEntry()
      e3.indexInfo.used = 200
      record.setSession(e1)
      record.setSession(e2)
      record.setSession(e3)
      const sessions = record.getSessions()
      expect(sessions[0].indexInfo.used).toBe(300)
      expect(sessions[1].indexInfo.used).toBe(200)
      expect(sessions[2].indexInfo.used).toBe(100)
    })
  })

  describe('removeOldSessions', () => {
    it('should remove oldest closed sessions beyond max', () => {
      const record = new SessionRecord()
      // Create 42 sessions (2 over the limit of 40)
      for (let i = 0; i < 42; i++) {
        const entry = createTestEntry(i + 1) // all closed with increasing timestamps
        record.setSession(entry)
      }
      record.removeOldSessions()
      expect(Object.keys(record.sessions).length).toBe(40)
    })

    it('should throw if all sessions are open and over limit', () => {
      const record = new SessionRecord()
      for (let i = 0; i < 41; i++) {
        const entry = createTestEntry(-1) // all open
        record.setSession(entry)
      }
      expect(() => record.removeOldSessions()).toThrow('Corrupt sessions object')
    })
  })

  describe('serialize / deserialize', () => {
    it('should roundtrip a session record', () => {
      const record = new SessionRecord()
      const entry = createTestEntry()
      record.setSession(entry)

      const serialized = record.serialize()
      const deserialized = SessionRecord.deserialize(serialized)

      expect(deserialized.version).toBe('v1')
      expect(Object.keys(deserialized.sessions)).toHaveLength(1)
      const session = Object.values(deserialized.sessions)[0]
      expect(session.registrationId).toBe(entry.registrationId)
    })

    it('should handle empty record', () => {
      const record = new SessionRecord()
      const serialized = record.serialize()
      const deserialized = SessionRecord.deserialize(serialized)
      expect(Object.keys(deserialized.sessions)).toHaveLength(0)
    })
  })

  describe('deleteAllSessions', () => {
    it('should remove all sessions', () => {
      const record = new SessionRecord()
      record.setSession(createTestEntry())
      record.setSession(createTestEntry())
      record.deleteAllSessions()
      expect(Object.keys(record.sessions)).toHaveLength(0)
    })
  })
})
