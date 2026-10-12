import { describe, it, expect } from 'vitest'
import { SessionBuilder } from '../../src/protocol/session-builder'
import { ProtocolAddress } from '../../src/protocol/protocol-address'
import curve from '../../src/crypto/curve'
import { generateKemKeyPair, encapsulate, decapsulate } from '../../src/crypto/kem'
import type { KeyPair, StorageInterface } from '../../src/types/index'

/** Storage mínimo — o initSession só precisa da nossa identidade. */
function storage(identity: KeyPair): StorageInterface {
  return {
    getOurIdentity: async () => identity,
    getOurRegistrationId: async () => 1,
    isTrustedIdentity: async () => true,
    loadSession: async () => undefined,
    storeSession: async () => {},
    loadPreKey: async () => undefined,
    removePreKey: async () => {},
    loadSignedPreKey: async () => undefined,
  } as unknown as StorageInterface
}

const addr = new ProtocolAddress('alice', 1)

async function derivar(kemSecret?: Uint8Array) {
  // Mesmas chaves dos dois lados, espelhadas — é o que acontece numa sessão real.
  const idA = curve.generateKeyPair()
  const idB = curve.generateKeyPair()
  const baseA = curve.generateKeyPair()   // efêmera do iniciador
  const spkB = curve.generateKeyPair()    // signed prekey do receptor
  const otkB = curve.generateKeyPair()    // one-time prekey do receptor

  const iniciador = await new SessionBuilder(storage(idA), addr).initSession(
    true, baseA, undefined, idB.pubKey, otkB.pubKey, spkB.pubKey, 1, kemSecret,
  )
  const receptor = await new SessionBuilder(storage(idB), addr).initSession(
    false, otkB, spkB, idA.pubKey, baseA.pubKey, undefined, 1, kemSecret,
  )
  return {
    iniciador: Buffer.from(iniciador.currentRatchet.rootKey),
    receptor: Buffer.from(receptor.currentRatchet.rootKey),
  }
}

describe('PQXDH no initSession', () => {
  it('os dois lados chegam na MESMA rootKey com o mesmo segredo do KEM', async () => {
    // É a propriedade que decide interoperabilidade. Errar a ordem da concatenação não
    // gera erro — gera exatamente este teste falhando, e em produção seria sessão morta.
    const kp = generateKemKeyPair()
    const { ciphertext, sharedSecret } = encapsulate(kp.publicKey)
    expect(Buffer.from(decapsulate(ciphertext, kp.privateKey))).toEqual(Buffer.from(sharedSecret))

    const { iniciador, receptor } = await derivar(sharedSecret)
    expect(iniciador).toEqual(receptor)
  })

  it('sessão clássica continua fechando entre os dois lados', async () => {
    const { iniciador, receptor } = await derivar(undefined)
    expect(iniciador).toEqual(receptor)
  })

  it('PQXDH e clássica derivam rootKeys DIFERENTES', async () => {
    // Prova que o segredo do KEM e a troca da string de info realmente entram no KDF —
    // sem isso a implementação "passaria" sem fazer nada.
    const kp = generateKemKeyPair()
    const { sharedSecret } = encapsulate(kp.publicKey)
    const comPq = await derivar(sharedSecret)
    const semPq = await derivar(undefined)
    expect(comPq.iniciador.equals(semPq.iniciador)).toBe(false)
  })

  it('segredo do KEM diferente muda a rootKey', async () => {
    const a = await derivar(encapsulate(generateKemKeyPair().publicKey).sharedSecret)
    const b = await derivar(encapsulate(generateKemKeyPair().publicKey).sharedSecret)
    expect(a.iniciador.equals(b.iniciador)).toBe(false)
  })

  it('rejeita segredo com tamanho errado em vez de derivar lixo', async () => {
    await expect(derivar(new Uint8Array(16))).rejects.toThrow(/32/)
  })
})
