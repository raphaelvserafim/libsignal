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

const prefixKeyInPublicKey = (pubKey: Uint8Array): Buffer => {
  if (pubKey.length === 0) {
    throw new Error('Public key cannot be empty');
  }

  return Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
};

function validatePrivKey(privKey: Uint8Array): void {
  if (privKey === undefined || privKey === null) {
    throw new Error("Private key cannot be undefined or null");
  }
  if (!(privKey instanceof Uint8Array)) {
    throw new Error(`Invalid private key type: ${privKey && typeof privKey === 'object' ? (privKey as any).constructor?.name : typeof privKey}`);
  }
  if (privKey.byteLength !== 32) {
    throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
  }
}


function scrubPubKeyFormat(pubKey: Uint8Array): Buffer {
  if (!(pubKey instanceof Uint8Array)) {
    throw new Error(`Invalid public key type: ${pubKey && typeof pubKey === 'object' ? (pubKey as any).constructor?.name : typeof pubKey}`);
  }

  if (!pubKey || ((pubKey.byteLength !== 33 || pubKey[0] !== 5) && pubKey.byteLength !== 32)) {
    throw new Error("Invalid public key");
  }

  if (pubKey.byteLength === 33) {
    return Buffer.from(pubKey.slice(1));
  } else {
    console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
    return Buffer.from(pubKey);
  }
}


function unclampEd25519PrivateKey(clampedSk: Uint8Array): Uint8Array {
  if (!clampedSk || clampedSk.length !== 32) {
    throw new Error("Invalid private key for unclamping");
  }

  const unclampedSk = new Uint8Array(clampedSk);

  unclampedSk[0] |= 6;    // Set last 3 bits to `110` pattern
  unclampedSk[31] |= 128; // Set highest bit
  unclampedSk[31] &= ~64; // Clear second-highest bit

  return unclampedSk;
}

export function getPublicFromPrivateKey(privKey: Uint8Array): Buffer {
  const unclampedPK = unclampEd25519PrivateKey(privKey);
  const keyPair = curveJs.generateKeyPair(unclampedPK);
  return prefixKeyInPublicKey(keyPair.public);
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


export function calculateAgreement(pubKey: Uint8Array, privKey: Uint8Array): Buffer {
  const scrubbed = scrubPubKeyFormat(pubKey);
  validatePrivKey(privKey);

  if (scrubbed.byteLength !== 32) {
    throw new Error("Invalid public key");
  }

  if (typeof nodeCrypto.diffieHellman === 'function') {
    const nodePrivateKey = nodeCrypto.createPrivateKey({
      key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
      format: 'der',
      type: 'pkcs8'
    });
    const nodePublicKey = nodeCrypto.createPublicKey({
      key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, scrubbed]),
      format: 'der',
      type: 'spki'
    });

    return nodeCrypto.diffieHellman({
      privateKey: nodePrivateKey,
      publicKey: nodePublicKey,
    });
  } else {
    const secret = curveJs.sharedKey(privKey, scrubbed);
    return Buffer.from(secret);
  }
}

export function calculateSignature(privKey: Uint8Array, message: Uint8Array): Buffer {
  validatePrivKey(privKey);
  if (!message || message.byteLength === 0) {
    throw new Error("Invalid message");
  }
  return Buffer.from(curveJs.sign(privKey, message, randomBytes(64)));
}

export function verifySignature(pubKey: Uint8Array, msg: Uint8Array, sig: Uint8Array, isInit?: boolean): boolean {
  const scrubbed = scrubPubKeyFormat(pubKey);

  if (scrubbed.byteLength !== 32) {
    throw new Error("Invalid public key");
  }
  if (!msg || msg.byteLength === 0) {
    throw new Error("Invalid message");
  }
  if (!sig || sig.byteLength !== 64) {
    throw new Error("Invalid signature");
  }

  return isInit ? true : curveJs.verify(scrubbed, msg, sig);
}

const curve = {
  getPublicFromPrivateKey,
  generateKeyPair,
  calculateAgreement,
  calculateSignature,
  verifySignature
};

export default curve;