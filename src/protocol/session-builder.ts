/**
 * SessionBuilder is responsible for establishing new sessions.
 * @raphaelvserafim
 */
'use strict';
import crypto from "../crypto";
import curve from "../crypto/curve";
import { BaseKeyType, ChainType } from "../types";
import { PreKeyError, UntrustedIdentityKeyError } from "../utils/errors";
import queueJob from "../utils/queue-job";
import { ProtocolAddress } from "./protocol-address";
import { SessionRecord } from "./session-record";


export class SessionBuilder {
  addr: ProtocolAddress;
  storage: any;

  constructor(storage: any, protocolAddress: ProtocolAddress) {
    this.addr = protocolAddress;
    this.storage = storage;
  }

  async initOutgoing(device: any) {
    const fqAddr = this.addr.toString();
    return await queueJob(fqAddr, async () => {
      if (!await this.storage.isTrustedIdentity(this.addr.id, device.identityKey)) {
        throw new UntrustedIdentityKeyError(this.addr.id, device.identityKey);
      }
      curve.verifySignature(device.identityKey, device.signedPreKey.publicKey,
        device.signedPreKey.signature, true);
      const baseKey = curve.generateKeyPair();
      const devicePreKey = device.preKey && device.preKey.publicKey;
      const session = await this.initSession(true, baseKey, undefined, device.identityKey,
        devicePreKey, device.signedPreKey.publicKey,
        device.registrationId);
      session.pendingPreKey = {
        signedKeyId: device.signedPreKey.keyId,
        baseKey: baseKey.pubKey
      };
      if (device.preKey) {
        session.pendingPreKey.preKeyId = device.preKey.keyId;
      }
      let record = await this.storage.loadSession(fqAddr);
      if (!record) {
        record = new SessionRecord();
      } else {
        const openSession = record.getOpenSession();
        if (openSession) {
          console.warn("Closing stale open session for new outgoing prekey bundle");
          record.closeSession(openSession);
        }
      }
      record.setSession(session);
      await this.storage.storeSession(fqAddr, record);
    });
  }

  async initIncoming(record: any, message: any) {
    const fqAddr = this.addr.toString();
    if (!await this.storage.isTrustedIdentity(fqAddr, message.identityKey)) {
      throw new UntrustedIdentityKeyError(this.addr.id, message.identityKey);
    }
    if (record.getSession(message.baseKey)) {
      // This just means we haven't replied.
      return;
    }
    const preKeyPair = await this.storage.loadPreKey(message.preKeyId);
    if (message.preKeyId && !preKeyPair) {
      throw new PreKeyError('Invalid PreKey ID');
    }
    const signedPreKeyPair = await this.storage.loadSignedPreKey(message.signedPreKeyId);
    if (!signedPreKeyPair) {
      throw new PreKeyError("Missing SignedPreKey");
    }
    const existingOpenSession = record.getOpenSession();
    if (existingOpenSession) {
      console.warn("Closing open session in favor of incoming prekey bundle");
      record.closeSession(existingOpenSession);
    }
    record.setSession(await this.initSession(false, preKeyPair, signedPreKeyPair,
      message.identityKey, message.baseKey,
      undefined, message.registrationId));
    return message.preKeyId;
  }

  async initSession(
    isInitiator: boolean,
    ourEphemeralKey: any,
    ourSignedKey: any,
    theirIdentityPubKey: any,
    theirEphemeralPubKey: any,
    theirSignedPubKey: any,
    registrationId: any
  ) {
    if (isInitiator) {
      if (ourSignedKey) {
        throw new Error("Invalid call to initSession");
      }
      ourSignedKey = ourEphemeralKey;
    } else {
      if (theirSignedPubKey) {
        throw new Error("Invalid call to initSession");
      }
      theirSignedPubKey = theirEphemeralPubKey;
    }
    let sharedSecret;
    if (!ourEphemeralKey || !theirEphemeralPubKey) {
      sharedSecret = new Uint8Array(32 * 4);
    } else {
      sharedSecret = new Uint8Array(32 * 5);
    }
    for (var i = 0; i < 32; i++) {
      sharedSecret[i] = 0xff;
    }
    const ourIdentityKey = await this.storage.getOurIdentity();
    const a1 = curve.calculateAgreement(theirSignedPubKey, ourIdentityKey.privKey);
    const a2 = curve.calculateAgreement(theirIdentityPubKey, ourSignedKey.privKey);
    const a3 = curve.calculateAgreement(theirSignedPubKey, ourSignedKey.privKey);
    if (isInitiator) {
      sharedSecret.set(new Uint8Array(a1), 32);
      sharedSecret.set(new Uint8Array(a2), 32 * 2);
    } else {
      sharedSecret.set(new Uint8Array(a1), 32 * 2);
      sharedSecret.set(new Uint8Array(a2), 32);
    }
    sharedSecret.set(new Uint8Array(a3), 32 * 3);
    if (ourEphemeralKey && theirEphemeralPubKey) {
      const a4 = curve.calculateAgreement(theirEphemeralPubKey, ourEphemeralKey.privKey);
      sharedSecret.set(new Uint8Array(a4), 32 * 4);
    }
    const masterKey = crypto.deriveSecrets(Buffer.from(sharedSecret), Buffer.alloc(32),
      Buffer.from("WhisperText"));
    const session = SessionRecord.createEntry();
    session.registrationId = registrationId;
    session.currentRatchet = {
      rootKey: masterKey[0],
      ephemeralKeyPair: isInitiator ? curve.generateKeyPair() : ourSignedKey,
      lastRemoteEphemeralKey: theirSignedPubKey,
      previousCounter: 0
    };
    session.indexInfo = {
      created: Date.now(),
      used: Date.now(),
      remoteIdentityKey: theirIdentityPubKey,
      baseKey: isInitiator ? ourEphemeralKey.pubKey : theirEphemeralPubKey,
      baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
      closed: -1
    };
    if (isInitiator) {
      // If we're initiating we go ahead and set our first sending ephemeral key now,
      // otherwise we figure it out when we first maybeStepRatchet with the remote's
      // ephemeral key
      this.calculateSendingRatchet(session, theirSignedPubKey);
    }
    return session;
  }

  calculateSendingRatchet(session: any, remoteKey: any) {
    const ratchet = session.currentRatchet;
    const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey);
    const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from("WhisperRatchet"));
    session.addChain(ratchet.ephemeralKeyPair.pubKey, {
      messageKeys: {},
      chainKey: {
        counter: -1,
        key: masterKey[1]
      },
      chainType: ChainType.SENDING
    });
    ratchet.rootKey = masterKey[0];
  }
}

