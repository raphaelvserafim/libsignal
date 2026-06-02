import { describe, it, expect } from 'vitest';
import crypto from '../../src/crypto/index';

describe('crypto', () => {
  describe('encrypt / decrypt', () => {
    it('should encrypt and decrypt data with AES-256-CBC', () => {
      const key = Buffer.alloc(32, 0xab);
      const iv = Buffer.alloc(16, 0xcd);
      const plaintext = Buffer.from('Hello, Signal Protocol!');
      const encrypted = crypto.encrypt(key, plaintext, iv);
      expect(encrypted).toBeInstanceOf(Buffer);
      expect(encrypted.equals(plaintext)).toBe(false);
      const decrypted = crypto.decrypt(key, encrypted, iv);
      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('should throw on wrong key length', () => {
      expect(() => crypto.encrypt(Buffer.alloc(16), Buffer.from('test'), Buffer.alloc(16))).toThrow('Key must be 32 bytes');
    });

    it('should throw on wrong IV length', () => {
      expect(() => crypto.encrypt(Buffer.alloc(32), Buffer.from('test'), Buffer.alloc(8))).toThrow('IV must be 16 bytes');
    });

    it('should fail decrypt with wrong key', () => {
      const key1 = Buffer.alloc(32, 0xab);
      const key2 = Buffer.alloc(32, 0xcd);
      const iv = Buffer.alloc(16, 0xef);
      const encrypted = crypto.encrypt(key1, Buffer.from('secret'), iv);
      expect(() => crypto.decrypt(key2, encrypted, iv)).toThrow();
    });
  });

  describe('calculateMAC / verifyMAC', () => {
    it('should calculate HMAC-SHA256', () => {
      const key = Buffer.alloc(32, 0x01);
      const data = Buffer.from('test data');
      const mac = crypto.calculateMAC(key, data);
      expect(mac).toBeInstanceOf(Buffer);
      expect(mac.byteLength).toBe(32);
    });

    it('should produce same MAC for same inputs', () => {
      const key = Buffer.alloc(32, 0x01);
      const data = Buffer.from('test data');
      const mac1 = crypto.calculateMAC(key, data);
      const mac2 = crypto.calculateMAC(key, data);
      expect(mac1.equals(mac2)).toBe(true);
    });

    it('should produce different MACs for different data', () => {
      const key = Buffer.alloc(32, 0x01);
      const mac1 = crypto.calculateMAC(key, Buffer.from('data1'));
      const mac2 = crypto.calculateMAC(key, Buffer.from('data2'));
      expect(mac1.equals(mac2)).toBe(false);
    });

    it('should verify a valid MAC', () => {
      const key = Buffer.alloc(32, 0x01);
      const data = Buffer.from('test');
      const mac = crypto.calculateMAC(key, data);
      expect(() => crypto.verifyMAC(data, key, mac.slice(0, 8), 8)).not.toThrow();
    });

    it('should throw on invalid MAC', () => {
      const key = Buffer.alloc(32, 0x01);
      const data = Buffer.from('test');
      const badMac = Buffer.alloc(8, 0xff);
      expect(() => crypto.verifyMAC(data, key, badMac, 8)).toThrow('Bad MAC');
    });

    it('should throw on wrong MAC length', () => {
      const key = Buffer.alloc(32, 0x01);
      const data = Buffer.from('test');
      const mac = Buffer.alloc(4);
      expect(() => crypto.verifyMAC(data, key, mac, 8)).toThrow('Bad MAC length');
    });
  });

  describe('hash', () => {
    it('should compute SHA-512 hash', () => {
      const data = Buffer.from('test');
      const h = crypto.hash(data);
      expect(h).toBeInstanceOf(Buffer);
      expect(h.byteLength).toBe(64);
    });

    it('should throw on empty data', () => {
      expect(() => crypto.hash(Buffer.alloc(0))).toThrow('Data cannot be empty');
    });

    it('should produce deterministic output', () => {
      const data = Buffer.from('deterministic');
      expect(crypto.hash(data).equals(crypto.hash(data))).toBe(true);
    });
  });

  describe('deriveSecrets', () => {
    it('should derive 3 secrets by default', () => {
      const input = Buffer.alloc(32, 0x01);
      const salt = Buffer.alloc(32, 0x02);
      const info = Buffer.from('info');
      const secrets = crypto.deriveSecrets(input, salt, info);
      expect(secrets).toHaveLength(3);
      for (const s of secrets) {
        expect(s).toBeInstanceOf(Buffer);
        expect(s.byteLength).toBe(32);
      }
    });

    it('should derive 1 or 2 secrets when requested', () => {
      const input = Buffer.alloc(32, 0x01);
      const salt = Buffer.alloc(32, 0x02);
      const info = Buffer.from('info');
      expect(crypto.deriveSecrets(input, salt, info, 1)).toHaveLength(1);
      expect(crypto.deriveSecrets(input, salt, info, 2)).toHaveLength(2);
    });

    it('should throw on wrong salt length', () => {
      expect(() => crypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(16), Buffer.from('info'))).toThrow('salt of incorrect length');
    });

    it('should throw on invalid chunks', () => {
      expect(() => crypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('info'), 4)).toThrow('Chunks must be between 1 and 3');
    });

    it('should default to 3 chunks when 0 is passed', () => {
      // chunks=0 is falsy, so it defaults to 3
      const result = crypto.deriveSecrets(Buffer.alloc(32), Buffer.alloc(32), Buffer.from('info'), 0);
      expect(result).toHaveLength(3);
    });
  });
});
