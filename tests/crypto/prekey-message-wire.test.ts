import { describe, it, expect } from 'vitest'
import { PreKeyWhisperMessage } from '../../src/utils/protobufs'

/**
 * Guarda da serialização dos campos PQ.
 *
 * `src/whisper/whisper-protocol.ts` é código protobuf **gerado e versionado**, e o `.proto`
 * ao lado é só a fonte — os dois podem divergir em silêncio. Foi o que aconteceu: acrescentei
 * os campos no `.proto` e o runtime continuou sem conhecê-los, o que só apareceu como
 * "Bad MAC" num teste ponta a ponta. Regenerar não era viável (o gerador atual produz código
 * incompatível com o runtime instalado), então os campos foram acrescentados à mão.
 *
 * Este teste existe para que a edição manual não se perca numa regeneração futura.
 */
describe('PreKeyWhisperMessage — campos PQXDH na rede', () => {
  const ciphertext = Buffer.alloc(1568, 7)

  it('ida e volta preserva kyberPreKeyId (7) e kyberCiphertext (8)', () => {
    const msg = PreKeyWhisperMessage.create({
      identityKey: Buffer.alloc(33, 1),
      baseKey: Buffer.alloc(33, 2),
      signedPreKeyId: 1,
      registrationId: 42,
      message: Buffer.alloc(10, 3),
      kyberPreKeyId: 9,
      kyberCiphertext: ciphertext,
    })
    const voltou = PreKeyWhisperMessage.decode(PreKeyWhisperMessage.encode(msg).finish())
    expect(voltou.kyberPreKeyId).toBe(9)
    expect(Buffer.from(voltou.kyberCiphertext)).toEqual(ciphertext)
  })

  it('mensagem clássica não ganha os campos nem cresce', () => {
    const classica = {
      identityKey: Buffer.alloc(33, 1),
      baseKey: Buffer.alloc(33, 2),
      signedPreKeyId: 1,
      registrationId: 42,
      message: Buffer.alloc(10, 3),
    }
    const bytes = PreKeyWhisperMessage.encode(PreKeyWhisperMessage.create(classica)).finish()
    const voltou = PreKeyWhisperMessage.decode(bytes)
    expect(voltou.kyberPreKeyId).toBe(0)
    expect(voltou.kyberCiphertext.length).toBe(0)
    // Os campos PQ custam ~1575 bytes; a clássica tem que continuar pequena.
    expect(bytes.length).toBeLessThan(200)
  })

  it('o ciphertext tem o tamanho do ML-KEM-1024', () => {
    expect(ciphertext.length).toBe(1568)
  })
})
