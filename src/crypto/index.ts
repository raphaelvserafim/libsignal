import { createCipheriv, createDecipheriv, createHmac, createHash, timingSafeEqual } from 'crypto';


export function encrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Buffer {
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes for AES-256');
  }
  if (iv.length !== 16) {
    throw new Error('IV must be 16 bytes for AES-256-CBC');
  }

  const cipher = createCipheriv('aes-256-cbc', key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

  return encrypted;
}

export function decrypt(
  key: Uint8Array,
  data: Uint8Array,
  iv: Uint8Array
): Buffer {
  if (key.length !== 32) {
    throw new Error('Key must be 32 bytes for AES-256');
  }
  if (iv.length !== 16) {
    throw new Error('IV must be 16 bytes for AES-256-CBC');
  }

  const decipher = createDecipheriv('aes-256-cbc', key, iv);

  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

  return decrypted;
}

export function calculateMAC(
  key: Uint8Array,
  data: Uint8Array
): Buffer {
  const hmac = createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest();
}


export function hash(data: Uint8Array): Buffer {
  if (data.length === 0) {
    throw new Error('Data cannot be empty');
  }

  const sha512 = createHash('sha512');
  sha512.update(data);
  return sha512.digest();
}



export function deriveSecrets(
  input: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  chunks?: number
): Buffer[] {
  if (salt.byteLength !== 32) {
    throw new Error("Got salt of incorrect length");
  }

  chunks = chunks || 3;

  if (chunks < 1 || chunks > 3) {
    throw new Error("Chunks must be between 1 and 3");
  }

  const PRK = calculateMAC(salt, input);
  const infoArray = new Uint8Array(info.byteLength + 1 + 32);
  infoArray.set(info, 32);
  infoArray[infoArray.length - 1] = 1;

  const signed = [calculateMAC(PRK, infoArray.slice(32))];

  if (chunks > 1) {
    infoArray.set(signed[signed.length - 1]!, 0);
    infoArray[infoArray.length - 1] = 2;
    signed.push(calculateMAC(PRK, infoArray));
  }

  if (chunks > 2) {
    infoArray.set(signed[signed.length - 1]!, 0);
    infoArray[infoArray.length - 1] = 3;
    signed.push(calculateMAC(PRK, infoArray));
  }

  return signed;
}

export function verifyMAC(
  data: Uint8Array,
  key: Uint8Array,
  mac: Uint8Array,
  length: number
): void {
  const calculatedMac = calculateMAC(key, data).slice(0, length);

  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error("Bad MAC length");
  }

  if (!timingSafeEqual(mac, calculatedMac)) {
    throw new Error("Bad MAC");
  }
}

const crypto = {
  deriveSecrets,
  decrypt,
  encrypt,
  hash,
  calculateMAC,
  verifyMAC
};

export default crypto;