/**
 * Test verifySignature with WhatsApp key format.
 *
 * WhatsApp stores public keys as 32 bytes (without 0x05 prefix), but
 * signatures are computed over the 33-byte prefixed version.
 * Our verifySignature handles the identity key format via scrubPubKeyFormat,
 * and the message (signed prekey pubKey) should include the prefix.
 *
 * Validated with real WhatsApp session data — verification passes.
 * The isInit=true bypass was a bug, not a WhatsApp requirement.
 */
import { describe, it, expect } from 'vitest'
import curve from '../../src/crypto/curve'
import * as keyhelper from '../../src/crypto/keyhelper'

describe('WhatsApp key format compatibility', () => {
  it('should verify with 32-byte identity key (WhatsApp storage format)', () => {
    // WhatsApp stores identity pubKey as 32 bytes (no 0x05 prefix)
    // Our verifySignature strips the prefix via scrubPubKeyFormat, so both work
    const identity = keyhelper.generateIdentityKeyPair()
    const signedPreKey = keyhelper.generateSignedPreKey(identity, 1)

    // Simulate WhatsApp format: 32-byte raw identity key
    const rawIdentityPub = identity.pubKey.slice(1)
    expect(rawIdentityPub.length).toBe(32)

    // Message (signed prekey pubKey) keeps its 33-byte format (signature was over this)
    const isValid = curve.verifySignature(rawIdentityPub, signedPreKey.keyPair.pubKey, signedPreKey.signature)
    expect(isValid).toBe(true)
  })

  it('should verify with 33-byte prefixed keys (standard format)', () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const signedPreKey = keyhelper.generateSignedPreKey(identity, 1)

    expect(identity.pubKey.length).toBe(33)
    expect(identity.pubKey[0]).toBe(5)

    const isValid = curve.verifySignature(identity.pubKey, signedPreKey.keyPair.pubKey, signedPreKey.signature)
    expect(isValid).toBe(true)
  })

  it('should verify when WhatsApp provides 32-byte signed prekey with prefix added', () => {
    // WhatsApp stores signedPreKey.public as 32 bytes
    // When building the device bundle, the prefix must be added back
    // because the signature was computed over the 33-byte version
    const identity = keyhelper.generateIdentityKeyPair()
    const signedPreKey = keyhelper.generateSignedPreKey(identity, 1)

    // Simulate: strip prefix (WhatsApp storage), then add back (device bundle)
    const rawSignedPK = signedPreKey.keyPair.pubKey.slice(1) // 32 bytes
    const restoredSignedPK = Buffer.concat([Buffer.from([5]), rawSignedPK]) // 33 bytes

    const isValid = curve.verifySignature(identity.pubKey, restoredSignedPK, signedPreKey.signature)
    expect(isValid).toBe(true)
  })

  it('should reject verification when message is tampered', () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const signedPreKey = keyhelper.generateSignedPreKey(identity, 1)

    const tampered = Buffer.from(signedPreKey.keyPair.pubKey)
    tampered[15] ^= 0xff

    const isValid = curve.verifySignature(identity.pubKey, tampered, signedPreKey.signature)
    expect(isValid).toBe(false)
  })
})
