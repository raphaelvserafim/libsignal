import { describe, it, expect } from 'vitest'
import { SessionBuilder } from '../../src/protocol/session-builder'
import { SessionRecord } from '../../src/protocol/session-record'
import { ProtocolAddress } from '../../src/protocol/protocol-address'
import curve from '../../src/crypto/curve'
import { generateKemKeyPair, encapsulate } from '../../src/crypto/kem'
import type { StorageInterface } from '../../src/types/index'

const idB = curve.generateKeyPair()
const spkB = curve.generateKeyPair()
const otkB = curve.generateKeyPair()
const idA = curve.generateKeyPair()
const baseA = curve.generateKeyPair()
const addr = new ProtocolAddress('bob', 1)

function store(kyber?: { publicKey: Uint8Array; privateKey: Uint8Array } | null): StorageInterface {
  const base = {
    getOurIdentity: async () => idB,
    getOurRegistrationId: async () => 1,
    isTrustedIdentity: async () => true,
    loadSession: async () => undefined,
    storeSession: async () => {},
    loadPreKey: async () => otkB,
    loadSignedPreKey: async () => spkB,
    removePreKey: async () => {},
  }
  // `kyber === undefined` = store ANTIGO, sem o método. `null` = tem o método mas não acha a chave.
  return (kyber === undefined ? base : { ...base, loadKyberPreKey: async () => kyber ?? undefined }) as unknown as StorageInterface
}

const msgBase = {
  identityKey: idA.pubKey,
  baseKey: baseA.pubKey,
  preKeyId: 1,
  signedPreKeyId: 1,
  registrationId: 1,
}

const comCiphertext = () => {
  const kp = generateKemKeyPair()
  return { kp, ...encapsulate(kp.publicKey) }
}

describe('initIncoming com PQXDH', () => {
  it('estabelece a sessão quando consegue decapsular', async () => {
    const { kp, ciphertext } = comCiphertext()
    const rec = new SessionRecord()
    await new SessionBuilder(store(kp), addr).initIncoming(rec, {
      ...msgBase,
      kyberPreKeyId: 7,
      kyberCiphertext: ciphertext,
    })
    expect(rec.getSession(baseA.pubKey)).toBeTruthy()
  })

  it('a sessão PQ difere da clássica — prova que o segredo entrou no KDF', async () => {
    const { kp, ciphertext } = comCiphertext()
    const pq = new SessionRecord()
    await new SessionBuilder(store(kp), addr).initIncoming(pq, {
      ...msgBase,
      kyberPreKeyId: 7,
      kyberCiphertext: ciphertext,
    })
    const classica = new SessionRecord()
    await new SessionBuilder(store(kp), addr).initIncoming(classica, { ...msgBase })

    const rk = (r: SessionRecord) => Buffer.from((r.getSession(baseA.pubKey) as never as { currentRatchet: { rootKey: Uint8Array } }).currentRatchet.rootKey)
    expect(rk(pq).equals(rk(classica))).toBe(false)
  })

  it('REJEITA se o store não suporta kyber — não cria sessão morta', async () => {
    const { ciphertext } = comCiphertext()
    await expect(
      new SessionBuilder(store(undefined), addr).initIncoming(new SessionRecord(), {
        ...msgBase,
        kyberPreKeyId: 7,
        kyberCiphertext: ciphertext,
      }),
    ).rejects.toThrow(/não suporta kyber/)
  })

  it('REJEITA se a kyber prekey não existe', async () => {
    const { ciphertext } = comCiphertext()
    await expect(
      new SessionBuilder(store(null), addr).initIncoming(new SessionRecord(), {
        ...msgBase,
        kyberPreKeyId: 99,
        kyberCiphertext: ciphertext,
      }),
    ).rejects.toThrow(/99 não encontrada/)
  })

  it('REJEITA ciphertext sem kyberPreKeyId', async () => {
    const { kp, ciphertext } = comCiphertext()
    await expect(
      new SessionBuilder(store(kp), addr).initIncoming(new SessionRecord(), {
        ...msgBase,
        kyberCiphertext: ciphertext,
      }),
    ).rejects.toThrow(/sem kyberPreKeyId/)
  })

  it('mensagem clássica continua funcionando em store sem suporte a kyber', async () => {
    const rec = new SessionRecord()
    await new SessionBuilder(store(undefined), addr).initIncoming(rec, { ...msgBase })
    expect(rec.getSession(baseA.pubKey)).toBeTruthy()
  })
})
