import { describe, it, expect } from 'vitest'
import { buildSharedSecret } from '../../src/protocol/session-builder'
import curve from '../../src/crypto/curve'
import { generateKemKeyPair, encapsulate, decapsulate } from '../../src/crypto/kem'

/**
 * Monta os dois lados de uma sessão com as chaves espelhadas, exatamente como
 * `initOutgoing` e `initIncoming` chamam.
 *
 * Testar aqui em vez de na `rootKey` é deliberado: o iniciador avança o ratchet logo após
 * derivar, então a `rootKey` dos dois lados NÃO é comparável. O que precisa ser idêntico é
 * a sequência de segredos — e é ela que a ordem da concatenação pode estragar em silêncio.
 */
function doisLados(kem?: Uint8Array) {
  const idA = curve.generateKeyPair()
  const idB = curve.generateKeyPair()
  const baseA = curve.generateKeyPair() // efêmera do iniciador
  const spkB = curve.generateKeyPair() // signed prekey do receptor
  const otkB = curve.generateKeyPair() // one-time prekey do receptor

  const iniciador = buildSharedSecret({
    isInitiator: true,
    ourIdentityPriv: idA.privKey,
    ourSignedPriv: baseA.privKey, // no iniciador, ourSignedKey = a própria efêmera
    ourEphemeralPriv: baseA.privKey,
    theirIdentityPub: idB.pubKey,
    theirSignedPub: spkB.pubKey,
    theirEphemeralPub: otkB.pubKey,
    kemSharedSecret: kem,
  })

  const receptor = buildSharedSecret({
    isInitiator: false,
    ourIdentityPriv: idB.privKey,
    ourSignedPriv: spkB.privKey,
    ourEphemeralPriv: otkB.privKey,
    theirIdentityPub: idA.pubKey,
    theirSignedPub: baseA.pubKey, // no receptor, theirSignedPubKey = a baseKey recebida
    theirEphemeralPub: baseA.pubKey,
    kemSharedSecret: kem,
  })

  return { iniciador: Buffer.from(iniciador), receptor: Buffer.from(receptor) }
}

describe('buildSharedSecret — PQXDH', () => {
  it('os dois lados chegam na MESMA sequência, com o segredo do KEM', () => {
    const kp = generateKemKeyPair()
    const { ciphertext, sharedSecret } = encapsulate(kp.publicKey)
    // O receptor obtém o mesmo segredo decapsulando — é assim que ele chega ao valor.
    expect(Buffer.from(decapsulate(ciphertext, kp.privateKey))).toEqual(Buffer.from(sharedSecret))

    const { iniciador, receptor } = doisLados(sharedSecret)
    expect(iniciador).toEqual(receptor)
    expect(iniciador.length).toBe(32 * 6) // FF + a1..a4 + KEM
  })

  it('a sessão clássica continua simétrica e do tamanho de antes', () => {
    const { iniciador, receptor } = doisLados()
    expect(iniciador).toEqual(receptor)
    expect(iniciador.length).toBe(32 * 5) // FF + a1..a4, sem KEM
  })

  it('o segredo do KEM entra no FIM, sem mexer no que vinha antes', () => {
    const kp = generateKemKeyPair()
    const { sharedSecret } = encapsulate(kp.publicKey)
    const kem = Buffer.from(sharedSecret)
    // Mesmas chaves nos dois: só muda a presença do KEM.
    const base = doisLados()
    const comPq = doisLados(kem)
    expect(comPq.iniciador.length - base.iniciador.length).toBe(32)
    expect(comPq.iniciador.subarray(32 * 5)).toEqual(kem)
  })

  it('começa com 32 bytes 0xFF nos dois modos', () => {
    const esperado = Buffer.alloc(32, 0xff)
    expect(doisLados().iniciador.subarray(0, 32)).toEqual(esperado)
    expect(doisLados(encapsulate(generateKemKeyPair().publicKey).sharedSecret).iniciador.subarray(0, 32)).toEqual(esperado)
  })

  it('segredo do KEM diferente muda a sequência', () => {
    const a = doisLados(encapsulate(generateKemKeyPair().publicKey).sharedSecret)
    const b = doisLados(encapsulate(generateKemKeyPair().publicKey).sharedSecret)
    expect(a.iniciador.equals(b.iniciador)).toBe(false)
  })

  it('rejeita segredo com tamanho errado em vez de derivar lixo', () => {
    expect(() => doisLados(new Uint8Array(16))).toThrow(/32/)
  })
})
