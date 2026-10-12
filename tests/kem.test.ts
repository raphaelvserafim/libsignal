import { describe, it, expect } from 'vitest'
import { KEM, generateKemKeyPair, encapsulate, decapsulate } from '../src/crypto/kem.js'

describe('ML-KEM-1024 (PQXDH)', () => {
  it('tamanhos batem com os que o WhatsApp declara no WAKemModule', () => {
    // Se isto quebrar numa atualização da dependência, trocou de parâmetro e a
    // interoperabilidade foi embora em silêncio.
    expect(KEM).toEqual({
      PUBLIC_KEY_LENGTH: 1568,
      SECRET_KEY_LENGTH: 3168,
      CIPHERTEXT_LENGTH: 1568,
      SHARED_SECRET_LENGTH: 32,
    })
    const kp = generateKemKeyPair()
    expect(kp.publicKey.length).toBe(KEM.PUBLIC_KEY_LENGTH)
    expect(kp.privateKey.length).toBe(KEM.SECRET_KEY_LENGTH)
  })

  it('encapsula e decapsula para o mesmo segredo', () => {
    const kp = generateKemKeyPair()
    const { ciphertext, sharedSecret } = encapsulate(kp.publicKey)
    expect(ciphertext.length).toBe(KEM.CIPHERTEXT_LENGTH)
    expect(sharedSecret.length).toBe(KEM.SHARED_SECRET_LENGTH)
    expect(Buffer.from(decapsulate(ciphertext, kp.privateKey))).toEqual(Buffer.from(sharedSecret))
  })

  it('pares diferentes produzem segredos diferentes', () => {
    const a = encapsulate(generateKemKeyPair().publicKey)
    const b = encapsulate(generateKemKeyPair().publicKey)
    expect(Buffer.from(a.sharedSecret).equals(Buffer.from(b.sharedSecret))).toBe(false)
  })

  it('decapsular com a chave errada NÃO devolve o segredo original', () => {
    // ML-KEM não falha com chave errada — devolve um segredo implícito, por desenho
    // (resistência a ataque de texto cifrado escolhido). Quem detecta a divergência é o
    // KDF adiante, não esta camada. Documentado aqui para ninguém esperar exceção.
    const alvo = generateKemKeyPair()
    const outro = generateKemKeyPair()
    const { ciphertext, sharedSecret } = encapsulate(alvo.publicKey)
    const errado = decapsulate(ciphertext, outro.privateKey)
    expect(Buffer.from(errado).equals(Buffer.from(sharedSecret))).toBe(false)
  })

  it('rejeita tamanhos inválidos em vez de produzir lixo', () => {
    expect(() => encapsulate(new Uint8Array(32))).toThrow(/1568/)
    expect(() => decapsulate(new Uint8Array(10), generateKemKeyPair().privateKey)).toThrow(/1568/)
  })
})
