import { createCipheriv, createDecipheriv, createHmac, createHash } from 'crypto';

export function encrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-cbc', new Uint8Array(key), new Uint8Array(iv))
  return Buffer.concat([new Uint8Array(cipher.update(new Uint8Array(data))), new Uint8Array(cipher.final())])
}


export function decrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([new Uint8Array(decipher.update(data) as Buffer), new Uint8Array(decipher.final() as Buffer)]);
}

export function calculateMAC(key: Buffer, data: Buffer): Buffer {

  const hmac = createHmac('sha256', key);
  hmac.update(data);
  return Buffer.from(hmac.digest());
}

export function hash(data: Buffer): Buffer {

  const sha512 = createHash('sha512');
  sha512.update(data);
  return sha512.digest();
}

export function deriveSecrets(input: Buffer, salt: Buffer, info: Buffer, chunks?: number): Buffer[] {

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
  const signed = [calculateMAC(PRK, Buffer.from(infoArray.slice(32)))];

  if (chunks > 1) {
    infoArray.set(signed[signed.length - 1]!, 0);
    infoArray[infoArray.length - 1] = 2;
    signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
  }

  if (chunks > 2) {
    infoArray.set(signed[signed.length - 1]!, 0);
    infoArray[infoArray.length - 1] = 3;
    signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
  }

  return signed;
}

export function verifyMAC(data: Buffer, key: Buffer, mac: Buffer, length: number): void {
  const calculatedMac = calculateMAC(key, data).slice(0, length);

  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error("Bad MAC length");
  }

  if (!mac.equals(Uint8Array.from(calculatedMac))) {
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