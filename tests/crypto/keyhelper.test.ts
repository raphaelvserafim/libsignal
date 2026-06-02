import { describe, it, expect } from 'vitest';
import * as keyhelper from '../../src/crypto/keyhelper';

describe('keyhelper', () => {
  describe('generateIdentityKeyPair', () => {
    it('should generate a valid key pair', () => {
      const kp = keyhelper.generateIdentityKeyPair();
      expect(kp.pubKey.byteLength).toBe(33);
      expect(kp.privKey.byteLength).toBe(32);
      expect(kp.pubKey[0]).toBe(5);
    });
  });

  describe('generateRegistrationId', () => {
    it('should generate a 14-bit number', () => {
      const id = keyhelper.generateRegistrationId();
      expect(typeof id).toBe('number');
      expect(id).toBeGreaterThanOrEqual(0);
      expect(id).toBeLessThan(16384); // 2^14
    });

    it('should generate different IDs', () => {
      const ids = new Set(Array.from({ length: 10 }, () => keyhelper.generateRegistrationId()));
      expect(ids.size).toBeGreaterThan(1);
    });
  });

  describe('generateSignedPreKey', () => {
    it('should generate a signed prekey with valid signature', () => {
      const identityKeyPair = keyhelper.generateIdentityKeyPair();
      const signedPreKey = keyhelper.generateSignedPreKey(identityKeyPair, 1);
      expect(signedPreKey.keyId).toBe(1);
      expect(signedPreKey.keyPair.pubKey.byteLength).toBe(33);
      expect(signedPreKey.keyPair.privKey.byteLength).toBe(32);
      expect(signedPreKey.signature.byteLength).toBe(64);
    });

    it('should throw on invalid identity key pair', () => {
      expect(() => keyhelper.generateSignedPreKey({ pubKey: Buffer.alloc(10), privKey: Buffer.alloc(10) }, 1))
        .toThrow('Invalid argument for identityKeyPair');
    });

    it('should throw on negative keyId', () => {
      const identityKeyPair = keyhelper.generateIdentityKeyPair();
      expect(() => keyhelper.generateSignedPreKey(identityKeyPair, -1))
        .toThrow('Invalid argument for signedKeyId');
    });
  });

  describe('generatePreKey', () => {
    it('should generate a prekey', () => {
      const preKey = keyhelper.generatePreKey(42);
      expect(preKey.keyId).toBe(42);
      expect(preKey.keyPair.pubKey.byteLength).toBe(33);
      expect(preKey.keyPair.privKey.byteLength).toBe(32);
    });

    it('should throw on invalid keyId', () => {
      expect(() => keyhelper.generatePreKey(-1)).toThrow('Invalid argument for keyId');
      expect(() => keyhelper.generatePreKey(1.5)).toThrow('Invalid argument for keyId');
    });
  });
});
