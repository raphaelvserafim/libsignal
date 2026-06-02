import { describe, it, expect, beforeEach } from 'vitest';
import { SessionBuilder } from '../../src/protocol/session-builder';
import { SessionCipher } from '../../src/protocol/session-cipher';
import { SessionRecord } from '../../src/protocol/session-record';
import { ProtocolAddress } from '../../src/protocol/protocol-address';
import * as keyhelper from '../../src/crypto/keyhelper';
import curve from '../../src/crypto/curve';
import { Device, KeyPair, StorageInterface } from '../../src/types/index';

class MockStorage implements StorageInterface {
  private identity: KeyPair;
  private registrationId: number;
  private sessions = new Map<string, SessionRecord>();
  private preKeys = new Map<number, KeyPair>();
  private signedPreKeys = new Map<number, KeyPair>();
  private trustedIdentities = new Map<string, Buffer>();

  constructor(identity: KeyPair, registrationId: number) {
    this.identity = identity;
    this.registrationId = registrationId;
  }

  async getOurIdentity(): Promise<KeyPair> {
    return this.identity;
  }

  async getOurRegistrationId(): Promise<number> {
    return this.registrationId;
  }

  async isTrustedIdentity(_id: string, _identityKey: Uint8Array): Promise<boolean> {
    return true;
  }

  async loadSession(address: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(address);
  }

  async storeSession(address: string, record: SessionRecord): Promise<void> {
    this.sessions.set(address, record);
  }

  async loadPreKey(keyId: number): Promise<KeyPair | undefined> {
    return this.preKeys.get(keyId);
  }

  async loadSignedPreKey(keyId: number): Promise<KeyPair | undefined> {
    return this.signedPreKeys.get(keyId);
  }

  async removePreKey(keyId: number): Promise<void> {
    this.preKeys.delete(keyId);
  }

  storePreKey(keyId: number, keyPair: KeyPair) {
    this.preKeys.set(keyId, keyPair);
  }

  storeSignedPreKey(keyId: number, keyPair: KeyPair) {
    this.signedPreKeys.set(keyId, keyPair);
  }

  saveTrustedIdentity(id: string, key: Buffer) {
    this.trustedIdentities.set(id, key);
  }
}

function createUser() {
  const identity = keyhelper.generateIdentityKeyPair();
  const registrationId = keyhelper.generateRegistrationId();
  const storage = new MockStorage(identity, registrationId);

  const signedPreKey = keyhelper.generateSignedPreKey(identity, 1);
  storage.storeSignedPreKey(signedPreKey.keyId, signedPreKey.keyPair);

  const preKey = keyhelper.generatePreKey(1);
  storage.storePreKey(preKey.keyId, preKey.keyPair);

  return {
    identity,
    registrationId,
    storage,
    signedPreKey,
    preKey,
    getDevice(): Device {
      return {
        identityKey: identity.pubKey,
        registrationId,
        preKey: {
          keyId: preKey.keyId,
          publicKey: preKey.keyPair.pubKey,
        },
        signedPreKey: {
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.keyPair.pubKey,
          signature: signedPreKey.signature,
        },
      };
    },
  };
}

describe('Signal Protocol Integration', () => {
  let alice: ReturnType<typeof createUser>;
  let bob: ReturnType<typeof createUser>;
  let aliceAddr: ProtocolAddress;
  let bobAddr: ProtocolAddress;

  beforeEach(() => {
    alice = createUser();
    bob = createUser();
    aliceAddr = new ProtocolAddress('alice', 1);
    bobAddr = new ProtocolAddress('bob', 1);
  });

  it('Alice sends a message to Bob (happy path)', async () => {
    // Alice builds session with Bob's device info
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    // Alice encrypts
    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const plaintext = Buffer.from('Hello Bob!');
    const encrypted = await aliceCipher.encrypt(plaintext);

    expect(encrypted.type).toBe(3); // PreKeyWhisperMessage
    expect(encrypted.body).toBeInstanceOf(Buffer);

    // Bob decrypts
    const bobCipher = new SessionCipher(bob.storage, aliceAddr);
    const decrypted = await bobCipher.decryptPreKeyWhisperMessage(encrypted.body);

    expect(decrypted.toString()).toBe('Hello Bob!');
  });

  it('Bob replies to Alice (bidirectional)', async () => {
    // Setup: Alice -> Bob
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const bobCipher = new SessionCipher(bob.storage, aliceAddr);

    const encrypted1 = await aliceCipher.encrypt(Buffer.from('Hello Bob!'));
    await bobCipher.decryptPreKeyWhisperMessage(encrypted1.body);

    // Bob replies
    const encrypted2 = await bobCipher.encrypt(Buffer.from('Hello Alice!'));
    expect(encrypted2.type).toBe(1); // Normal WhisperMessage (session established)

    const decrypted = await aliceCipher.decryptWhisperMessage(encrypted2.body);
    expect(decrypted.toString()).toBe('Hello Alice!');
  });

  it('Multiple messages with ratchet advancement', async () => {
    // Setup session
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const bobCipher = new SessionCipher(bob.storage, aliceAddr);

    // First message (PreKey)
    const enc1 = await aliceCipher.encrypt(Buffer.from('Message 1'));
    expect(enc1.type).toBe(3); // PreKeyWhisperMessage
    const dec1 = await bobCipher.decryptPreKeyWhisperMessage(enc1.body);
    expect(dec1.toString()).toBe('Message 1');

    // Second message — still PreKey until Bob replies and clears pendingPreKey
    const enc2 = await aliceCipher.encrypt(Buffer.from('Message 2'));
    expect(enc2.type).toBe(3); // pendingPreKey still set on Alice's side
    const dec2 = await bobCipher.decryptPreKeyWhisperMessage(enc2.body);
    expect(dec2.toString()).toBe('Message 2');

    // Bob replies — this is a normal WhisperMessage
    const enc3 = await bobCipher.encrypt(Buffer.from('Reply 1'));
    expect(enc3.type).toBe(1);
    const dec3 = await aliceCipher.decryptWhisperMessage(enc3.body);
    expect(dec3.toString()).toBe('Reply 1');

    // Alice again — now normal since Bob's reply cleared pendingPreKey
    const enc4 = await aliceCipher.encrypt(Buffer.from('Message 3'));
    expect(enc4.type).toBe(1);
    const dec4 = await bobCipher.decryptWhisperMessage(enc4.body);
    expect(dec4.toString()).toBe('Message 3');

    // More back-and-forth
    const enc5 = await bobCipher.encrypt(Buffer.from('Reply 2'));
    const dec5 = await aliceCipher.decryptWhisperMessage(enc5.body);
    expect(dec5.toString()).toBe('Reply 2');

    const enc6 = await aliceCipher.encrypt(Buffer.from('Message 4'));
    const dec6 = await bobCipher.decryptWhisperMessage(enc6.body);
    expect(dec6.toString()).toBe('Message 4');
  });

  it('Session without preKey (signed prekey only)', async () => {
    const deviceNoPreKey: Device = {
      identityKey: bob.identity.pubKey,
      registrationId: bob.registrationId,
      signedPreKey: {
        keyId: bob.signedPreKey.keyId,
        publicKey: bob.signedPreKey.keyPair.pubKey,
        signature: bob.signedPreKey.signature,
      },
      // No preKey
    };

    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(deviceNoPreKey);

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const encrypted = await aliceCipher.encrypt(Buffer.from('No prekey message'));
    expect(encrypted.type).toBe(3);

    const bobCipher = new SessionCipher(bob.storage, aliceAddr);
    const decrypted = await bobCipher.decryptPreKeyWhisperMessage(encrypted.body);
    expect(decrypted.toString()).toBe('No prekey message');
  });

  it('New session replaces existing (rekey)', async () => {
    // First session
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const bobCipher = new SessionCipher(bob.storage, aliceAddr);

    const enc1 = await aliceCipher.encrypt(Buffer.from('Old session'));
    await bobCipher.decryptPreKeyWhisperMessage(enc1.body);

    // Bob generates new prekeys
    const newPreKey = keyhelper.generatePreKey(2);
    bob.storage.storePreKey(newPreKey.keyId, newPreKey.keyPair);
    const newSignedPreKey = keyhelper.generateSignedPreKey(bob.identity, 2);
    bob.storage.storeSignedPreKey(newSignedPreKey.keyId, newSignedPreKey.keyPair);

    const newDevice: Device = {
      identityKey: bob.identity.pubKey,
      registrationId: bob.registrationId,
      preKey: { keyId: newPreKey.keyId, publicKey: newPreKey.keyPair.pubKey },
      signedPreKey: {
        keyId: newSignedPreKey.keyId,
        publicKey: newSignedPreKey.keyPair.pubKey,
        signature: newSignedPreKey.signature,
      },
    };

    // Alice re-establishes session
    await aliceBuilder.initOutgoing(newDevice);

    const enc2 = await aliceCipher.encrypt(Buffer.from('New session'));
    const dec2 = await bobCipher.decryptPreKeyWhisperMessage(enc2.body);
    expect(dec2.toString()).toBe('New session');
  });

  it('Untrusted identity throws error', async () => {
    const untrustedStorage: StorageInterface = {
      ...alice.storage,
      isTrustedIdentity: async () => false,
      getOurIdentity: () => alice.storage.getOurIdentity(),
      loadSession: (addr) => alice.storage.loadSession(addr),
      storeSession: (addr, rec) => alice.storage.storeSession(addr, rec),
      loadPreKey: (id) => alice.storage.loadPreKey(id),
      loadSignedPreKey: (id) => alice.storage.loadSignedPreKey(id),
    };

    const builder = new SessionBuilder(untrustedStorage, bobAddr);
    await expect(builder.initOutgoing(bob.getDevice())).rejects.toThrow();
  });

  it('Duplicate message counter throws MessageCounterError', async () => {
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);
    const bobCipher = new SessionCipher(bob.storage, aliceAddr);

    const encrypted = await aliceCipher.encrypt(Buffer.from('once'));

    // First decrypt succeeds
    await bobCipher.decryptPreKeyWhisperMessage(encrypted.body);

    // Second decrypt with same message should fail
    await expect(bobCipher.decryptPreKeyWhisperMessage(encrypted.body))
      .rejects.toThrow();
  });

  it('Invalid signed prekey signature throws error', async () => {
    const badDevice: Device = {
      identityKey: bob.identity.pubKey,
      registrationId: bob.registrationId,
      signedPreKey: {
        keyId: 1,
        publicKey: bob.signedPreKey.keyPair.pubKey,
        signature: Buffer.alloc(64, 0xff), // Invalid signature
      },
    };

    const builder = new SessionBuilder(alice.storage, bobAddr);
    await expect(builder.initOutgoing(badDevice)).rejects.toThrow('Invalid signature');
  });

  it('hasOpenSession and closeOpenSession work correctly', async () => {
    const aliceBuilder = new SessionBuilder(alice.storage, bobAddr);
    await aliceBuilder.initOutgoing(bob.getDevice());

    const aliceCipher = new SessionCipher(alice.storage, bobAddr);

    expect(await aliceCipher.hasOpenSession()).toBe(true);

    await aliceCipher.closeOpenSession();

    expect(await aliceCipher.hasOpenSession()).toBe(false);

    // Encrypt should fail after close
    await expect(aliceCipher.encrypt(Buffer.from('fail'))).rejects.toThrow('No open session');
  });
});
