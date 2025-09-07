import nodeCrypto from 'crypto';
import curve from "./curve.js";

interface KeyPair {
  privKey: Buffer;
  pubKey: Buffer;
}

interface SignedPreKey {
  keyId: number;
  keyPair: KeyPair;
  signature: Buffer;
}

interface PreKey {
  keyId: number;
  keyPair: KeyPair;
}

function isNonNegativeInteger(n: unknown): n is number {
  return (typeof n === 'number' && (n % 1) === 0 && n >= 0);
}

export const generateIdentityKeyPair = curve.generateKeyPair;

export function generateRegistrationId(): number {
  var registrationId = Uint16Array.from(nodeCrypto.randomBytes(2))[0];
  if (registrationId === undefined) {
    throw new Error('Failed to generate registration ID');
  }
  return registrationId & 0x3fff;
}

export function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey {
  if (!(identityKeyPair.privKey instanceof Buffer) ||
    identityKeyPair.privKey.byteLength != 32 ||
    !(identityKeyPair.pubKey instanceof Buffer) ||
    identityKeyPair.pubKey.byteLength != 33) {
    throw new TypeError('Invalid argument for identityKeyPair');
  }
  if (!isNonNegativeInteger(signedKeyId)) {
    throw new TypeError('Invalid argument for signedKeyId: ' + signedKeyId);
  }
  const keyPair = curve.generateKeyPair();
  const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);
  return {
    keyId: signedKeyId,
    keyPair: keyPair,
    signature: sig
  };
}

export function generatePreKey(keyId: number): PreKey {
  if (!isNonNegativeInteger(keyId)) {
    throw new TypeError('Invalid argument for keyId: ' + keyId);
  }
  const keyPair = curve.generateKeyPair();
  return {
    keyId,
    keyPair
  };
}