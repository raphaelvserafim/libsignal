import { describe, it, expect } from 'vitest';
import curve from '../../src/crypto/curve';

describe('curve', () => {
  describe('generateKeyPair', () => {
    it('should generate a key pair with 33-byte pubKey and 32-byte privKey', () => {
      const keyPair = curve.generateKeyPair();
      expect(keyPair.pubKey).toBeInstanceOf(Buffer);
      expect(keyPair.privKey).toBeInstanceOf(Buffer);
      expect(keyPair.pubKey.byteLength).toBe(33);
      expect(keyPair.privKey.byteLength).toBe(32);
    });

    it('should prefix pubKey with 0x05', () => {
      const keyPair = curve.generateKeyPair();
      expect(keyPair.pubKey[0]).toBe(5);
    });

    it('should generate unique key pairs', () => {
      const kp1 = curve.generateKeyPair();
      const kp2 = curve.generateKeyPair();
      expect(kp1.pubKey.equals(kp2.pubKey)).toBe(false);
      expect(kp1.privKey.equals(kp2.privKey)).toBe(false);
    });
  });

  describe('getPublicFromPrivateKey', () => {
    it('should derive public key from private key', () => {
      const keyPair = curve.generateKeyPair();
      const derivedPub = curve.getPublicFromPrivateKey(keyPair.privKey);
      expect(derivedPub).toBeInstanceOf(Buffer);
      expect(derivedPub.byteLength).toBe(33);
      expect(derivedPub[0]).toBe(5);
    });
  });

  describe('calculateAgreement', () => {
    it('should compute shared secret between two key pairs', () => {
      const alice = curve.generateKeyPair();
      const bob = curve.generateKeyPair();
      const sharedAlice = curve.calculateAgreement(bob.pubKey, alice.privKey);
      const sharedBob = curve.calculateAgreement(alice.pubKey, bob.privKey);
      expect(sharedAlice).toBeInstanceOf(Buffer);
      expect(sharedAlice.byteLength).toBe(32);
      expect(sharedAlice.equals(sharedBob)).toBe(true);
    });

    it('should throw on invalid private key', () => {
      const bob = curve.generateKeyPair();
      expect(() => curve.calculateAgreement(bob.pubKey, Buffer.alloc(16))).toThrow('Incorrect private key length');
    });

    it('should throw on invalid public key', () => {
      const alice = curve.generateKeyPair();
      expect(() => curve.calculateAgreement(Buffer.alloc(10), alice.privKey)).toThrow('Invalid public key');
    });

    it('should throw on null private key', () => {
      const bob = curve.generateKeyPair();
      expect(() => curve.calculateAgreement(bob.pubKey, null as any)).toThrow();
    });
  });

  describe('calculateSignature / verifySignature', () => {
    it('should sign and verify a message', () => {
      const keyPair = curve.generateKeyPair();
      const message = Buffer.from('test message');
      const signature = curve.calculateSignature(keyPair.privKey, message);
      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.byteLength).toBe(64);
      const verified = curve.verifySignature(keyPair.pubKey, message, signature);
      expect(verified).toBe(true);
    });

    it('should fail verification with wrong key', () => {
      const keyPair1 = curve.generateKeyPair();
      const keyPair2 = curve.generateKeyPair();
      const message = Buffer.from('test message');
      const signature = curve.calculateSignature(keyPair1.privKey, message);
      const verified = curve.verifySignature(keyPair2.pubKey, message, signature);
      expect(verified).toBe(false);
    });

    it('should fail verification with wrong message', () => {
      const keyPair = curve.generateKeyPair();
      const signature = curve.calculateSignature(keyPair.privKey, Buffer.from('original'));
      const verified = curve.verifySignature(keyPair.pubKey, Buffer.from('tampered'), signature);
      expect(verified).toBe(false);
    });

    it('should throw on empty message for signing', () => {
      const keyPair = curve.generateKeyPair();
      expect(() => curve.calculateSignature(keyPair.privKey, Buffer.alloc(0))).toThrow('Invalid message');
    });

    it('should throw on invalid signature length for verify', () => {
      const keyPair = curve.generateKeyPair();
      expect(() => curve.verifySignature(keyPair.pubKey, Buffer.from('msg'), Buffer.alloc(32))).toThrow('Invalid signature');
    });

    it('should not have isInit bypass', () => {
      const keyPair = curve.generateKeyPair();
      const message = Buffer.from('test');
      // verifySignature should only accept 3 args (no isInit)
      expect(curve.verifySignature.length).toBe(3);
    });
  });
});
