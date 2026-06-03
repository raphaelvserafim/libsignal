import { describe, it, expect } from 'vitest'
import { ProtocolAddress } from '../../src/protocol/protocol-address'

describe('ProtocolAddress', () => {
  it('should construct with id and deviceId', () => {
    const addr = new ProtocolAddress('user123', 1)
    expect(addr.id).toBe('user123')
    expect(addr.deviceId).toBe(1)
  })

  it('should produce string representation', () => {
    const addr = new ProtocolAddress('user123', 2)
    expect(addr.toString()).toBe('user123.2')
  })

  describe('from', () => {
    it('should parse encoded address', () => {
      const addr = ProtocolAddress.from('user123.2')
      expect(addr.id).toBe('user123')
      expect(addr.deviceId).toBe(2)
    })

    it('should throw on invalid format', () => {
      expect(() => ProtocolAddress.from('invalid')).toThrow('Invalid address encoding')
      expect(() => ProtocolAddress.from('')).toThrow('Invalid address encoding')
    })
  })

  describe('is', () => {
    it('should compare equal addresses', () => {
      const a = new ProtocolAddress('user', 1)
      const b = new ProtocolAddress('user', 1)
      expect(a.is(b)).toBe(true)
    })

    it('should compare different addresses', () => {
      const a = new ProtocolAddress('user1', 1)
      const b = new ProtocolAddress('user2', 1)
      expect(a.is(b)).toBe(false)
    })

    it('should compare different device IDs', () => {
      const a = new ProtocolAddress('user', 1)
      const b = new ProtocolAddress('user', 2)
      expect(a.is(b)).toBe(false)
    })
  })

  describe('validation', () => {
    it('should throw on non-string id', () => {
      expect(() => new ProtocolAddress(123 as any, 1)).toThrow('id required for addr')
    })

    it('should throw on encoded id', () => {
      expect(() => new ProtocolAddress('user.1', 1)).toThrow('encoded addr detected')
    })

    it('should throw on non-number deviceId', () => {
      expect(() => new ProtocolAddress('user', '1' as any)).toThrow('number required for deviceId')
    })
  })
})
