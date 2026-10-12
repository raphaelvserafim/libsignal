import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'

/**
 * ML-KEM-1024 — o KEM pós-quântico que o WhatsApp usa no PQXDH.
 *
 * Os tamanhos abaixo são os declarados pelo `WAKemModule` do cliente web real, e estão aqui
 * como asserção de contrato: se uma atualização da dependência mudar qualquer um deles, é
 * porque trocou de parâmetro e a interoperabilidade quebrou silenciosamente.
 *
 * O cliente real carrega o liboqs compilado em wasm; nós usamos implementação JS do MESMO
 * padrão NIST. O que precisa ser idêntico é o formato na rede, não quem o produz — ML-KEM-1024
 * é determinístico a partir das entradas.
 *
 * Nota de nomenclatura: a string de info do KDF do WhatsApp ainda diz "CRYSTALS-KYBER-1024",
 * mas o algoritmo pedido ao liboqs é "ML-KEM-1024" — a versão padronizada. São a mesma coisa
 * aqui; a string de info é literal e NÃO deve ser "corrigida".
 */
export const KEM = {
  PUBLIC_KEY_LENGTH: 1568,
  SECRET_KEY_LENGTH: 3168,
  CIPHERTEXT_LENGTH: 1568,
  SHARED_SECRET_LENGTH: 32,
} as const

export interface KemKeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export function generateKemKeyPair(): KemKeyPair {
  const { publicKey, secretKey } = ml_kem1024.keygen()
  return { publicKey, privateKey: secretKey }
}

/** Lado de quem INICIA a sessão: encapsula contra a chave pública do par. */
export function encapsulate(peerPublicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  if (peerPublicKey.length !== KEM.PUBLIC_KEY_LENGTH) {
    throw new Error(`KEM: chave pública com ${peerPublicKey.length} bytes, esperado ${KEM.PUBLIC_KEY_LENGTH}`)
  }
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(peerPublicKey)
  return { ciphertext: cipherText, sharedSecret }
}

/** Lado de quem RECEBE: recupera o mesmo segredo a partir do ciphertext. */
export function decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array): Uint8Array {
  if (ciphertext.length !== KEM.CIPHERTEXT_LENGTH) {
    throw new Error(`KEM: ciphertext com ${ciphertext.length} bytes, esperado ${KEM.CIPHERTEXT_LENGTH}`)
  }
  return ml_kem1024.decapsulate(ciphertext, privateKey)
}
