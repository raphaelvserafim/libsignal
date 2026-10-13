import { describe, it, expect, beforeEach } from 'vitest'
import { SessionBuilder } from '../../src/protocol/session-builder'
import { SessionCipher } from '../../src/protocol/session-cipher'
import { SessionRecord } from '../../src/protocol/session-record'
import { ProtocolAddress } from '../../src/protocol/protocol-address'
import * as keyhelper from '../../src/crypto/keyhelper'
import curve from '../../src/crypto/curve'
import { generateKemKeyPair } from '../../src/crypto/kem'
import type { Device, KeyPair, StorageInterface } from '../../src/types/index'

type Kem = { publicKey: Uint8Array; privateKey: Uint8Array }

class Storage implements StorageInterface {
  sessions = new Map<string, SessionRecord>()
  preKeys = new Map<number, KeyPair>()
  signedPreKeys = new Map<number, KeyPair>()
  kyberPreKeys = new Map<number, Kem>()
  constructor(
    private identity: KeyPair,
    private regId: number,
  ) {}
  async getOurIdentity() { return this.identity }
  async getOurRegistrationId() { return this.regId }
  async isTrustedIdentity() { return true }
  async loadSession(a: string) { return this.sessions.get(a) }
  async storeSession(a: string, r: SessionRecord) { this.sessions.set(a, r) }
  async loadPreKey(id: number) { return this.preKeys.get(id) }
  async loadSignedPreKey(id: number) { return this.signedPreKeys.get(id) }
  async loadKyberPreKey(id: number) { return this.kyberPreKeys.get(id) }
  async removePreKey(id: number) { this.preKeys.delete(id) }
}

/** `comPq: false` simula contato que ainda não publica chave pós-quântica. */
function criarUsuario(comPq: boolean) {
  const identity = keyhelper.generateIdentityKeyPair()
  const regId = keyhelper.generateRegistrationId()
  const storage = new Storage(identity, regId)

  const spk = keyhelper.generateSignedPreKey(identity, 1)
  storage.signedPreKeys.set(spk.keyId, spk.keyPair)
  const pk = keyhelper.generatePreKey(1)
  storage.preKeys.set(pk.keyId, pk.keyPair)

  const kyber = generateKemKeyPair()
  const kyberId = 7
  if (comPq) storage.kyberPreKeys.set(kyberId, kyber)

  return {
    storage,
    device(): Device {
      const base: Device = {
        identityKey: identity.pubKey,
        registrationId: regId,
        preKey: { keyId: pk.keyId, publicKey: pk.keyPair.pubKey },
        signedPreKey: { keyId: spk.keyId, publicKey: spk.keyPair.pubKey, signature: spk.signature },
      }
      if (!comPq) return base
      return {
        ...base,
        pqPreKey: {
          keyId: kyberId,
          publicKey: kyber.publicKey,
          // Assinada pela identidade, como a signed prekey — é o que o initOutgoing confere.
          signature: curve.calculateSignature(identity.privKey, Buffer.from(kyber.publicKey)),
        },
      }
    },
    kyber,
    kyberId,
    identity,
  }
}

describe('PQXDH ponta a ponta', () => {
  let alice: ReturnType<typeof criarUsuario>
  let bob: ReturnType<typeof criarUsuario>
  const aliceAddr = new ProtocolAddress('alice', 1)
  const bobAddr = new ProtocolAddress('bob', 1)

  beforeEach(() => {
    alice = criarUsuario(true)
    bob = criarUsuario(true)
  })

  it('Alice manda para Bob com PQXDH e Bob decifra', async () => {
    await new SessionBuilder(alice.storage, bobAddr).initOutgoing(bob.device())
    const enc = await new SessionCipher(alice.storage, bobAddr).encrypt(Buffer.from('oi pós-quântico'))
    expect(enc.type).toBe(3)

    const texto = await new SessionCipher(bob.storage, aliceAddr).decryptPreKeyWhisperMessage(enc.body)
    expect(texto.toString()).toBe('oi pós-quântico')
  })

  it('a conversa segue nos dois sentidos depois da sessão PQ aberta', async () => {
    await new SessionBuilder(alice.storage, bobAddr).initOutgoing(bob.device())
    const cipherA = new SessionCipher(alice.storage, bobAddr)
    const cipherB = new SessionCipher(bob.storage, aliceAddr)

    await cipherB.decryptPreKeyWhisperMessage((await cipherA.encrypt(Buffer.from('um'))).body)
    const resposta = await cipherB.encrypt(Buffer.from('dois'))
    expect(resposta.type).toBe(1)
    expect((await cipherA.decryptWhisperMessage(resposta.body)).toString()).toBe('dois')
  })

  it('contato SEM chave PQ continua funcionando em sessão clássica', async () => {
    const semPq = criarUsuario(false)
    await new SessionBuilder(alice.storage, bobAddr).initOutgoing(semPq.device())
    const enc = await new SessionCipher(alice.storage, bobAddr).encrypt(Buffer.from('clássico'))
    const texto = await new SessionCipher(semPq.storage, aliceAddr).decryptPreKeyWhisperMessage(enc.body)
    expect(texto.toString()).toBe('clássico')
  })

  it('REJEITA bundle com pqkey de assinatura inválida', async () => {
    const d = bob.device()
    d.pqPreKey!.signature = Buffer.alloc(64, 1) // assinada por ninguém
    await expect(new SessionBuilder(alice.storage, bobAddr).initOutgoing(d)).rejects.toThrow(/pq prekey/)
  })

  it('REJEITA bundle cuja pqkey foi trocada por outra', async () => {
    const d = bob.device()
    d.pqPreKey!.publicKey = generateKemKeyPair().publicKey // chave do atacante, assinatura antiga
    await expect(new SessionBuilder(alice.storage, bobAddr).initOutgoing(d)).rejects.toThrow(/pq prekey/)
  })
})
