/**
 * SessionCipher is a high-level interface for encrypting and decrypting messages.
 * It manages the session state and handles the details of the Double Ratchet algorithm.
 * @raphaelvserafim
 */

'use strict';
import crypto from "../crypto/index.js";
import curve from "../crypto/curve.js";
import { ChainType } from "../types/index.js";
import { MessageCounterError, SessionError, UntrustedIdentityKeyError } from "../utils/errors.js";
import { PreKeyWhisperMessage, WhisperMessage } from "../utils/protobufs.js";
import queueJob from "../utils/queue-job.js";
import { ProtocolAddress } from "./protocol-address.js";
import { SessionBuilder } from "./session-builder.js";
import { SessionRecord } from "./session-record.js";
import { MAX_MESSAGE_KEYS_GAP, MIN_PREKEY_MESSAGE_SIZE, MIN_WHISPER_MESSAGE_SIZE, VERSION } from "../constants/index.js";


function secureZeroMemory(buffer: Buffer | Uint8Array | ArrayBuffer | null | undefined): void {
  if (!buffer) return;
  try {
    if (buffer instanceof Buffer) {
      buffer.fill(0);
    } else if (buffer instanceof Uint8Array) {
      buffer.fill(0);
    } else if (buffer instanceof ArrayBuffer) {
      new Uint8Array(buffer).fill(0);
    }
  } catch (e) {
  }
}

export class SessionCipher {
  addr: ProtocolAddress;
  storage: any;

  constructor(storage: any, protocolAddress: ProtocolAddress) {
    if (!storage) {
      throw new TypeError("storage is required");
    }
    if (!(protocolAddress instanceof ProtocolAddress)) {
      throw new TypeError("protocolAddress must be a ProtocolAddress");
    }

    const requiredMethods = ['loadSession', 'storeSession', 'getOurIdentity', 'isTrustedIdentity', 'getOurRegistrationId'];

    for (const method of requiredMethods) {
      if (typeof storage[method] !== 'function') {
        throw new TypeError(`storage must implement ${method}() method`);
      }
    }

    this.addr = protocolAddress;
    this.storage = storage;
  }

  _encodeTupleByte(number1: number, number2: number): number {
    if (!Number.isInteger(number1) || !Number.isInteger(number2)) {
      throw new TypeError("Numbers must be integers");
    }
    if (number1 < 0 || number1 > 15 || number2 < 0 || number2 > 15) {
      throw new TypeError("Numbers must be between 0 and 15 (4 bits)");
    }
    return (number1 << 4) | number2;
  }

  _decodeTupleByte(byte: number): [number, number] {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new TypeError("Byte must be an integer between 0 and 255");
    }
    return [byte >> 4, byte & 0xf];
  }

  toString(): string {
    return `<SessionCipher(${this.addr.toString()})>`;
  }

  async getRecord(): Promise<SessionRecord | null> {
    const record = await this.storage.loadSession(this.addr.toString());
    if (record && !(record instanceof SessionRecord)) {
      throw new TypeError('SessionRecord type expected from loadSession');
    }
    return record;
  }

  async storeRecord(record: SessionRecord): Promise<void> {
    if (!record || !(record instanceof SessionRecord)) {
      throw new TypeError('SessionRecord required');
    }
    record.removeOldSessions();
    await this.storage.storeSession(this.addr.toString(), record);
  }

  async queueJob<T>(awaitable: () => Promise<T>): Promise<T> {
    if (typeof awaitable !== 'function') {
      throw new TypeError('awaitable must be a function');
    }
    return await queueJob(this.addr.toString(), awaitable);
  }

  async encrypt(data: Buffer): Promise<{ type: number, body: Buffer, registrationId: number }> {
    if (!Buffer.isBuffer(data)) {
      throw new TypeError('data must be a Buffer');
    }
    if (data.length === 0) {
      throw new Error('data cannot be empty');
    }


    const ourIdentityKey = await this.storage.getOurIdentity();
    if (!ourIdentityKey || !ourIdentityKey.pubKey) {
      throw new SessionError("Missing our identity key");
    }

    let keys: any | null = null;
    let macInput: Buffer | null = null;

    try {
      return await this.queueJob(async () => {
        const record = await this.getRecord();
        if (!record) {
          throw new SessionError("No sessions");
        }
        const session = record.getOpenSession();
        if (!session) {
          throw new SessionError("No open session");
        }

        const remoteIdentityKey = session.indexInfo.remoteIdentityKey;
        if (!remoteIdentityKey) {
          throw new SessionError("Missing remote identity key");
        }

        if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
          throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
        }

        const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey);
        if (!chain) {
          throw new SessionError("No sending chain available");
        }
        if (chain.chainType === ChainType.RECEIVING) {
          throw new Error("Tried to encrypt on a receiving chain");
        }

        this.fillMessageKeys(chain, chain.chainKey.counter + 1);

        keys = crypto.deriveSecrets(chain.messageKeys[chain.chainKey.counter], Buffer.alloc(32), Buffer.from("WhisperMessageKeys"));

        delete chain.messageKeys[chain.chainKey.counter];

        const msg = WhisperMessage.create();
        msg.ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey;
        msg.counter = chain.chainKey.counter;
        msg.previousCounter = session.currentRatchet.previousCounter;
        msg.ciphertext = crypto.encrypt(keys[0], data, keys[2].slice(0, 16));

        const msgBuf = WhisperMessage.encode(msg).finish();


        macInput = Buffer.alloc(msgBuf.byteLength + (33 * 2) + 1);
        macInput.set(ourIdentityKey.pubKey);
        macInput.set(remoteIdentityKey, 33);
        macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
        macInput.set(msgBuf, (33 * 2) + 1);

        const mac = crypto.calculateMAC(keys[1], macInput);
        const result = Buffer.alloc(msgBuf.byteLength + 9);
        result[0] = this._encodeTupleByte(VERSION, VERSION);
        result.set(msgBuf, 1);
        result.set(mac.slice(0, 8), msgBuf.byteLength + 1);

        await this.storeRecord(record);

        let type: number, body: Buffer;
        if (session.pendingPreKey) {
          type = 3;  // prekey bundle
          const preKeyMsg = PreKeyWhisperMessage.create({
            identityKey: ourIdentityKey.pubKey,
            registrationId: await this.storage.getOurRegistrationId(),
            baseKey: session.pendingPreKey.baseKey,
            signedPreKeyId: session.pendingPreKey.signedKeyId,
            message: result
          });
          if (session.pendingPreKey.preKeyId !== undefined) {
            preKeyMsg.preKeyId = session.pendingPreKey.preKeyId;
          }
          body = Buffer.concat([
            Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
            Buffer.from(PreKeyWhisperMessage.encode(preKeyMsg).finish())
          ]);
        } else {
          type = 1;  // normal
          body = result;
        }

        return {
          type,
          body,
          registrationId: session.registrationId
        };
      });
    } finally {
      if (keys && Array.isArray(keys)) {
        for (const key of keys) {
          secureZeroMemory(key);
        }
      }
      secureZeroMemory(macInput);
    }
  }

  async decryptWithSessions(data: Buffer, sessions: any[]): Promise<{ session: any, plaintext: Buffer }> {
    if (!sessions || !Array.isArray(sessions) || sessions.length === 0) {
      throw new SessionError("No sessions available");
    }

    const errs: Error[] = [];
    for (const session of sessions) {
      if (!session) {
        continue;
      }

      try {
        const plaintext = await this.doDecryptWhisperMessage(data, session);
        session.indexInfo.used = Date.now();
        return {
          session,
          plaintext
        };
      } catch (e) {
        errs.push(e as Error);
      }
    }

    console.error(`Failed to decrypt message with ${sessions.length} known session(s)`);
    throw new SessionError("No matching sessions found for message");
  }

  async decryptWhisperMessage(data: Buffer): Promise<Buffer> {
    // Validação de entrada
    if (!Buffer.isBuffer(data)) {
      throw new TypeError('data must be a Buffer');
    }
    if (data.length < MIN_WHISPER_MESSAGE_SIZE) {
      throw new Error(`Message too short (min ${MIN_WHISPER_MESSAGE_SIZE} bytes)`);
    }

    return await this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        throw new SessionError("No session record");
      }

      const result = await this.decryptWithSessions(data, record.getSessions());
      const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey;

      if (!await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey)) {
        throw new UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey);
      }

      if (record.isClosed(result.session)) {
        console.warn("Decrypted message with closed session");
      }

      await this.storeRecord(record);
      return result.plaintext;
    });
  }

  async decryptPreKeyWhisperMessage(data: Buffer): Promise<Buffer> {
    // Validação de entrada
    if (!Buffer.isBuffer(data)) {
      throw new TypeError('data must be a Buffer');
    }

    if (data.length < MIN_PREKEY_MESSAGE_SIZE) {
      throw new Error(`PreKey message too short (min ${MIN_PREKEY_MESSAGE_SIZE} bytes)`);
    }

    const versions = this._decodeTupleByte(data[0]);

    if (versions[1] > 3 || versions[0] < 3) {
      throw new Error("Incompatible version number on PreKeyWhisperMessage");
    }

    return await this.queueJob(async () => {
      let record = await this.getRecord();
      const preKeyProto = PreKeyWhisperMessage.decode(data.slice(1));

      if (!preKeyProto.baseKey) {
        throw new Error("Missing baseKey in PreKeyWhisperMessage");
      }

      if (!preKeyProto.identityKey) {
        throw new Error("Missing identityKey in PreKeyWhisperMessage");
      }

      if (!preKeyProto.message) {
        throw new Error("Missing message in PreKeyWhisperMessage");
      }

      if (!record) {
        if (preKeyProto.registrationId == null) {
          throw new Error("No registrationId");
        }
        record = new SessionRecord();
      }

      const builder = new SessionBuilder(this.storage, this.addr);
      const preKeyId = await builder.initIncoming(record, preKeyProto);
      const session = record.getSession(preKeyProto.baseKey);

      if (!session) {
        throw new SessionError("Failed to create session from PreKey message");
      }

      const plaintext = await this.doDecryptWhisperMessage(preKeyProto.message, session);
      await this.storeRecord(record);

      if (preKeyId !== undefined && preKeyId !== null) {
        await this.storage.removePreKey(preKeyId);
      }

      return plaintext;
    });
  }

  async doDecryptWhisperMessage(messageBuffer: Buffer, session: any): Promise<Buffer> {
    if (!session) {
      throw new TypeError("session required");
    }
    if (!Buffer.isBuffer(messageBuffer)) {
      throw new TypeError("messageBuffer must be a Buffer");
    }
    if (messageBuffer.length < MIN_WHISPER_MESSAGE_SIZE) {
      throw new Error("Message buffer too short");
    }

    let keys: Buffer[] | null = null;
    let macInput: Buffer | null = null;
    let messageKey: Buffer | null = null;

    try {
      const versions = this._decodeTupleByte(messageBuffer[0]);
      if (versions[1] > 3 || versions[0] < 3) {
        throw new Error("Incompatible version number on WhisperMessage");
      }

      const messageProto = messageBuffer.slice(1, -8);
      const message = WhisperMessage.decode(messageProto);

      if (!message.ephemeralKey) {
        throw new Error("Missing ephemeralKey in message");
      }
      if (message.counter === undefined || message.counter === null) {
        throw new Error("Missing counter in message");
      }
      if (message.previousCounter === undefined || message.previousCounter === null) {
        throw new Error("Missing previousCounter in message");
      }

      this.maybeStepRatchet(session, message.ephemeralKey, message.previousCounter);

      const chain = session.getChain(message.ephemeralKey);
      if (!chain) {
        throw new SessionError("No chain available for message");
      }
      if (chain.chainType === ChainType.SENDING) {
        throw new Error("Tried to decrypt on a sending chain");
      }

      this.fillMessageKeys(chain, message.counter);

      if (!chain.messageKeys.hasOwnProperty(message.counter)) {
        throw new MessageCounterError('Key used already or never filled');
      }

      messageKey = chain.messageKeys[message.counter];
      if (!messageKey) {
        throw new SessionError('Missing message key');
      }
      delete chain.messageKeys[message.counter];

      keys = crypto.deriveSecrets(messageKey, Buffer.alloc(32), Buffer.from("WhisperMessageKeys"));

      const ourIdentityKey = await this.storage.getOurIdentity();
      if (!ourIdentityKey || !ourIdentityKey.pubKey) {
        throw new SessionError("Missing our identity key");
      }

      macInput = Buffer.alloc(messageProto.byteLength + (33 * 2) + 1);
      macInput.set(session.indexInfo.remoteIdentityKey);
      macInput.set(ourIdentityKey.pubKey, 33);
      macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION);
      macInput.set(messageProto, (33 * 2) + 1);

      crypto.verifyMAC(macInput, keys[1], messageBuffer.slice(-8), 8);

      const plaintext = crypto.decrypt(keys[0], message.ciphertext, keys[2].slice(0, 16));
      delete session.pendingPreKey;

      return plaintext;
    } finally {
      secureZeroMemory(messageKey);
      if (keys) {
        keys.forEach(key => secureZeroMemory(key));
      }
      secureZeroMemory(macInput);
    }
  }

  fillMessageKeys(chain: any, counter: number): void {
    if (!chain) {
      throw new TypeError("chain required");
    }
    if (!Number.isInteger(counter) || counter < 0) {
      throw new TypeError("counter must be a non-negative integer");
    }

    while (chain.chainKey.counter < counter) {
      const gap = counter - chain.chainKey.counter;

      if (gap > MAX_MESSAGE_KEYS_GAP) {
        throw new SessionError(`Over ${MAX_MESSAGE_KEYS_GAP} messages into the future!`);
      }

      if (chain.chainKey.key === undefined) {
        throw new SessionError('Chain closed');
      }

      const key = chain.chainKey.key;
      chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, Buffer.from([1]));
      chain.chainKey.key = crypto.calculateMAC(key, Buffer.from([2]));
      chain.chainKey.counter += 1;
    }
  }

  maybeStepRatchet(session: any, remoteKey: any, previousCounter: number): void {
    if (!session) {
      throw new TypeError("session required");
    }
    if (!remoteKey) {
      throw new TypeError("remoteKey required");
    }
    if (!Number.isInteger(previousCounter) || previousCounter < 0) {
      throw new TypeError("previousCounter must be a non-negative integer");
    }

    if (session.getChain(remoteKey)) {
      return;
    }

    const ratchet = session.currentRatchet;
    if (!ratchet) {
      throw new SessionError("Missing currentRatchet");
    }

    let previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey);
    if (previousRatchet) {
      this.fillMessageKeys(previousRatchet, previousCounter);
      delete previousRatchet.chainKey.key;  // Close
    }

    this.calculateRatchet(session, remoteKey, false);

    const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey);
    if (prevCounter) {
      ratchet.previousCounter = prevCounter.chainKey.counter;
      session.deleteChain(ratchet.ephemeralKeyPair.pubKey);
    }

    ratchet.ephemeralKeyPair = curve.generateKeyPair();
    this.calculateRatchet(session, remoteKey, true);
    ratchet.lastRemoteEphemeralKey = remoteKey;
  }

  calculateRatchet(session: any, remoteKey: any, sending: boolean): void {
    if (!session || !session.currentRatchet) {
      throw new TypeError("session with currentRatchet required");
    }
    if (!remoteKey) {
      throw new TypeError("remoteKey required");
    }

    let sharedSecret: Buffer | null = null;

    try {
      const ratchet = session.currentRatchet;
      sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
      const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey,
        Buffer.from("WhisperRatchet"), /*chunks*/ 2);

      const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey;
      session.addChain(chainKey, {
        messageKeys: {},
        chainKey: {
          counter: -1,
          key: masterKey[1]
        },
        chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
      });
      ratchet.rootKey = masterKey[0];
    } finally {
      secureZeroMemory(sharedSecret);
    }
  }

  async hasOpenSession(): Promise<boolean> {
    return await this.queueJob(async () => {
      const record = await this.getRecord();
      if (!record) {
        return false;
      }
      return record.haveOpenSession();
    });
  }

  async closeOpenSession(): Promise<void> {
    return await this.queueJob(async () => {
      const record = await this.getRecord();
      if (record) {
        const openSession = record.getOpenSession();
        if (openSession) {
          record.closeSession(openSession);
          await this.storeRecord(record);
        }
      }
    });
  }
}