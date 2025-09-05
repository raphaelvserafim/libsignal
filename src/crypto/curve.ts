import * as curveJs from 'curve25519-js';
import { generateKeyPairSync, randomBytes } from 'crypto';
import * as nodeCrypto from 'crypto';

// from: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/lib/crypto.js
const PUBLIC_KEY_DER_PREFIX = Buffer.from([
  48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);

const PRIVATE_KEY_DER_PREFIX = Buffer.from([
  48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

const KEY_BUNDLE_TYPE = Buffer.from([5]);

const prefixKeyInPublicKey = function (pubKey: Buffer): Buffer {
  return Buffer.from(Buffer.concat([new Uint8Array(KEY_BUNDLE_TYPE), new Uint8Array(pubKey)]));
};

function validatePrivKey(privKey: Buffer): void {
  if (privKey === undefined) {
    throw new Error("Undefined private key");
  }
  if (!(privKey instanceof Buffer)) {
    throw new Error(`Invalid private key type: ${privKey && typeof privKey === 'object' ? (privKey as any).constructor?.name : typeof privKey}`);
  }
  if (privKey.byteLength != 32) {
    throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
  }
}

function scrubPubKeyFormat(pubKey: Buffer): Buffer {
  if (!(pubKey instanceof Buffer)) {
    throw new Error(`Invalid public key type: ${pubKey && typeof pubKey === 'object' ? (pubKey as any).constructor?.name : typeof pubKey}`);
  }
  if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
    throw new Error("Invalid public key");
  }
  if (pubKey.byteLength == 33) {
    return pubKey.slice(1);
  } else {
    console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
    return pubKey;
  }
}

function unclampEd25519PrivateKey(clampedSk: Buffer): Uint8Array {
  const unclampedSk = new Uint8Array(clampedSk);

  if (!unclampedSk || unclampedSk.length < 32) {
    throw new Error("Invalid private key for unclamping");
  }

  // Fix the first byte
  unclampedSk[0]! |= 6; // Ensure last 3 bits match expected `110` pattern

  // Fix the last byte
  unclampedSk[31]! |= 128; // Restore the highest bit
  unclampedSk[31]! &= ~64; // Clear the second-highest bit

  return unclampedSk;
}

export function getPublicFromPrivateKey(privKey: Buffer): Buffer {
  const unclampedPK = unclampEd25519PrivateKey(privKey);
  const keyPair = curveJs.generateKeyPair(unclampedPK);
  return prefixKeyInPublicKey(Buffer.from(keyPair.public));
}

export function generateKeyPair(): { pubKey: Buffer; privKey: Buffer } {
  try {
    // Try to use Node.js native crypto if x25519 is supported
    const { publicKey: publicDerBytes, privateKey: privateDerBytes } = generateKeyPairSync(
      'x25519' as any,
      {
        publicKeyEncoding: { format: 'der', type: 'spki' },
        privateKeyEncoding: { format: 'der', type: 'pkcs8' }
      } as any
    );
    const pubKey = Buffer.from(publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32));

    const privKey = Buffer.from(privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32));

    return {
      pubKey: prefixKeyInPublicKey(pubKey),
      privKey
    };
  } catch (e) {
    const keyPair = curveJs.generateKeyPair(randomBytes(32));
    return {
      privKey: Buffer.from(keyPair.private),
      pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public)),
    };
  }
}

export function calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer {
  pubKey = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);
  if (!pubKey || pubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }
  if (typeof nodeCrypto.diffieHellman === 'function') {
    const nodePrivateKey = nodeCrypto.createPrivateKey({
      key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
      format: 'der',
      type: 'pkcs8'
    });
    const nodePublicKey = nodeCrypto.createPublicKey({
      key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
      format: 'der',
      type: 'spki'
    });

    return nodeCrypto.diffieHellman({
      privateKey: nodePrivateKey,
      publicKey: nodePublicKey,
    });
  } else {
    const secret = curveJs.sharedKey(privKey, pubKey);
    return Buffer.from(secret);
  }
}

export function calculateSignature(privKey: Buffer, message: Buffer): Buffer {
  validatePrivKey(privKey);
  if (!message) {
    throw new Error("Invalid message");
  }
  return Buffer.from(curveJs.sign(privKey, message, randomBytes(64)));
}

export function verifySignature(pubKey: Buffer, msg: Buffer, sig: Buffer, isInit?: boolean): boolean {
  pubKey = scrubPubKeyFormat(pubKey);
  if (!pubKey || pubKey.byteLength != 32) {
    throw new Error("Invalid public key");
  }
  if (!msg) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength != 64) {
    throw new Error("Invalid signature");
  }
  return isInit ? true : curveJs.verify(pubKey, msg, sig);
}

const curve = {
  getPublicFromPrivateKey,
  generateKeyPair,
  calculateAgreement,
  calculateSignature,
  verifySignature
};

export default curve;