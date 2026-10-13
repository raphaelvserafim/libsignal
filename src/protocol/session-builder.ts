/**
 * SessionBuilder is responsible for establishing new sessions.
 * @raphaelvserafim
 */
'use strict'
import crypto from '../crypto/index.js'
import curve from '../crypto/curve.js'
import { decapsulate as kemDecapsulate, encapsulate as kemEncapsulate } from '../crypto/kem.js'
import { BaseKeyType, ChainType, Device, IncomingMessage, KeyPair, StorageInterface } from '../types/index.js'
import { PreKeyError, UntrustedIdentityKeyError } from '../utils/errors.js'
import queueJob from '../utils/queue-job.js'
import { ProtocolAddress } from './protocol-address.js'
import { SessionEntry } from './session-entry.js'
import { SessionRecord } from './session-record.js'

/**
 * Monta a sequência de segredos que alimenta o KDF da sessão.
 *
 * Clássico (X3DH):  0xFF×32 ‖ a1 ‖ a2 ‖ a3 ‖ [a4]
 * PQXDH:            o mesmo, com o segredo do ML-KEM concatenado NO FIM.
 *
 * O iniciador e o receptor calculam os MESMOS valores com os papéis trocados, por isso
 * `a1` e `a2` mudam de posição conforme o lado. Errar essa ordem não produz erro — produz
 * duas pontas derivando root keys diferentes, ou seja, sessão morta em silêncio. É por isso
 * que isto é função pura: dá para testar a simetria dos dois lados diretamente.
 *
 * Conferido contra o módulo `WASignalPQXDH` do cliente web real.
 */
export function buildSharedSecret(args: {
  isInitiator: boolean
  ourIdentityPriv: Uint8Array
  ourSignedPriv: Uint8Array
  ourEphemeralPriv?: Uint8Array
  theirIdentityPub: Uint8Array
  theirSignedPub: Uint8Array
  theirEphemeralPub?: Uint8Array
  kemSharedSecret?: Uint8Array
}): Uint8Array {
  const { isInitiator, theirIdentityPub, theirSignedPub, theirEphemeralPub, kemSharedSecret } = args

  if (kemSharedSecret && kemSharedSecret.length !== 32) {
    throw new Error(`PQXDH: shared secret com ${kemSharedSecret.length} bytes, esperado 32`)
  }

  const temA4 = !!(args.ourEphemeralPriv && theirEphemeralPub)
  const blocosDh = temA4 ? 5 : 4
  const out = new Uint8Array(32 * (blocosDh + (kemSharedSecret ? 1 : 0)))
  out.fill(0xff, 0, 32)

  const a1 = curve.calculateAgreement(theirSignedPub, args.ourIdentityPriv)
  const a2 = curve.calculateAgreement(theirIdentityPub, args.ourSignedPriv)
  const a3 = curve.calculateAgreement(theirSignedPub, args.ourSignedPriv)

  out.set(new Uint8Array(a1), isInitiator ? 32 : 32 * 2)
  out.set(new Uint8Array(a2), isInitiator ? 32 * 2 : 32)
  out.set(new Uint8Array(a3), 32 * 3)

  if (temA4) {
    out.set(new Uint8Array(curve.calculateAgreement(theirEphemeralPub!, args.ourEphemeralPriv!)), 32 * 4)
  }
  if (kemSharedSecret) out.set(kemSharedSecret, 32 * blocosDh)

  return out
}

export class SessionBuilder {
  addr: ProtocolAddress
  storage: StorageInterface

  constructor(storage: StorageInterface, protocolAddress: ProtocolAddress) {
    this.addr = protocolAddress
    this.storage = storage
  }

  async initOutgoing(device: Device) {
    const fqAddr = this.addr.toString()
    return await queueJob(fqAddr, async () => {
      if (!(await this.storage.isTrustedIdentity(this.addr.id, device.identityKey))) {
        throw new UntrustedIdentityKeyError(this.addr.id, device.identityKey)
      }
      if (!curve.verifySignature(device.identityKey, device.signedPreKey.publicKey, device.signedPreKey.signature)) {
        throw new Error('Invalid signature on device prekey bundle')
      }
      // PQXDH: o bundle só traz `<pqkey>` se o par publica chaves pós-quânticas. Sem ele a
      // sessão sai clássica — é o caminho de hoje e tem que continuar funcionando.
      // A assinatura é verificada como a da signed prekey: aceitar chave PQ não assinada
      // deixaria qualquer um injetar a própria e ler a sessão.
      let kemSharedSecret: Uint8Array | undefined
      let kyberCiphertext: Uint8Array | undefined
      if (device.pqPreKey) {
        if (!curve.verifySignature(device.identityKey, device.pqPreKey.publicKey, device.pqPreKey.signature)) {
          throw new Error('Invalid signature on device pq prekey')
        }
        const encapsulado = kemEncapsulate(device.pqPreKey.publicKey)
        kemSharedSecret = encapsulado.sharedSecret
        kyberCiphertext = encapsulado.ciphertext
      }

      const baseKey = curve.generateKeyPair()
      const devicePreKey = device.preKey && device.preKey.publicKey
      const session = await this.initSession(
        true,
        baseKey,
        undefined,
        device.identityKey,
        devicePreKey,
        device.signedPreKey.publicKey,
        device.registrationId,
        kemSharedSecret,
      )
      session.pendingPreKey = {
        signedKeyId: device.signedPreKey.keyId,
        baseKey: baseKey.pubKey,
      }
      if (device.pqPreKey && kyberCiphertext) {
        // Vão para os campos 7 e 8 do PreKeyWhisperMessage; sem eles o receptor deriva
        // o segredo clássico e a sessão não fecha.
        session.pendingPreKey.kyberPreKeyId = device.pqPreKey.keyId
        session.pendingPreKey.kyberCiphertext = kyberCiphertext
      }
      if (device.preKey) {
        session.pendingPreKey.preKeyId = device.preKey.keyId
      }
      let record = await this.storage.loadSession(fqAddr)
      if (!record) {
        record = new SessionRecord()
      } else {
        const openSession = record.getOpenSession()
        if (openSession) {
          console.warn('Closing stale open session for new outgoing prekey bundle')
          record.closeSession(openSession)
        }
      }
      record.setSession(session)
      await this.storage.storeSession(fqAddr, record)
    })
  }

  async initIncoming(record: SessionRecord, message: IncomingMessage) {
    const fqAddr = this.addr.toString()
    if (!(await this.storage.isTrustedIdentity(fqAddr, message.identityKey))) {
      throw new UntrustedIdentityKeyError(this.addr.id, message.identityKey)
    }
    if (record.getSession(message.baseKey)) {
      return
    }
    const preKeyPair = await this.storage.loadPreKey(message.preKeyId!)
    if (message.preKeyId && !preKeyPair) {
      throw new PreKeyError('Invalid PreKey ID')
    }
    const signedPreKeyPair = await this.storage.loadSignedPreKey!(message.signedPreKeyId)
    if (!signedPreKeyPair) {
      throw new PreKeyError('Missing SignedPreKey')
    }
    // PQXDH: o remetente encapsulou contra uma kyber prekey NOSSA e mandou o ciphertext.
    // Se não conseguirmos decapsular, NÃO dá para continuar: derivaríamos o segredo clássico
    // enquanto ele derivou o pós-quântico, e a sessão nasceria morta sem nenhum erro — o
    // remetente veria "Esperando por esta mensagem" para sempre. Melhor falhar alto aqui.
    let kemSharedSecret: Uint8Array | undefined
    if (message.kyberCiphertext?.length) {
      if (!this.storage.loadKyberPreKey) {
        throw new PreKeyError('Mensagem PQXDH recebida, mas o store não suporta kyber prekeys')
      }
      if (message.kyberPreKeyId == null) {
        throw new PreKeyError('Mensagem PQXDH sem kyberPreKeyId')
      }
      const kyberPair = await this.storage.loadKyberPreKey(message.kyberPreKeyId)
      if (!kyberPair) {
        throw new PreKeyError(`Kyber prekey ${message.kyberPreKeyId} não encontrada`)
      }
      kemSharedSecret = kemDecapsulate(message.kyberCiphertext, kyberPair.privateKey)
    }

    const existingOpenSession = record.getOpenSession()
    if (existingOpenSession) {
      console.warn('Closing open session in favor of incoming prekey bundle')
      record.closeSession(existingOpenSession)
    }
    record.setSession(
      await this.initSession(
        false,
        preKeyPair,
        signedPreKeyPair,
        message.identityKey,
        message.baseKey,
        undefined,
        message.registrationId,
        kemSharedSecret,
      ),
    )
    return message.preKeyId
  }

  async initSession(
    isInitiator: boolean,
    ourEphemeralKey: KeyPair | undefined,
    ourSignedKey: KeyPair | undefined,
    theirIdentityPubKey: Buffer,
    theirEphemeralPubKey: Buffer | undefined,
    theirSignedPubKey: Buffer | undefined,
    registrationId: number,
    /**
     * Segredo compartilhado do ML-KEM-1024, quando a sessão for PQXDH.
     *
     * O WhatsApp concatena este segredo **no fim** da mesma sequência do X3DH clássico
     * (0xFF ‖ a1 ‖ a2 ‖ a3 ‖ [a4]) e troca a string de info do KDF. Conferido no módulo
     * `WASignalPQXDH` do cliente web, não deduzido da especificação pública.
     *
     * Ausente = sessão clássica, byte por byte igual ao que era antes.
     */
    kemSharedSecret?: Uint8Array,
  ): Promise<SessionEntry> {
    if (isInitiator) {
      if (ourSignedKey) {
        throw new Error('Invalid call to initSession')
      }
      ourSignedKey = ourEphemeralKey
    } else {
      if (theirSignedPubKey) {
        throw new Error('Invalid call to initSession')
      }
      theirSignedPubKey = theirEphemeralPubKey
    }
    // O segredo do KEM, quando existe, ocupa UM bloco a mais no fim — sem buraco no meio,
    // porque o cliente real concatena e pula o a4 ausente em vez de deixar espaço.
    const ourIdentityKey = await this.storage.getOurIdentity()
    const sharedSecret = buildSharedSecret({
      isInitiator,
      ourIdentityPriv: ourIdentityKey.privKey,
      ourSignedPriv: ourSignedKey!.privKey,
      ourEphemeralPriv: ourEphemeralKey?.privKey,
      theirIdentityPub: theirIdentityPubKey,
      theirSignedPub: theirSignedPubKey!,
      theirEphemeralPub: theirEphemeralPubKey,
      kemSharedSecret,
    })

    // A string de info muda SÓ na sessão PQXDH. Trocá-la na clássica quebraria toda sessão
    // existente. O nome diz CRYSTALS-KYBER-1024 embora o algoritmo seja ML-KEM-1024 — é
    // literal do cliente real e não deve ser "corrigido".
    const info = kemSharedSecret ? 'WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024' : 'WhisperText'
    const masterKey = crypto.deriveSecrets(Buffer.from(sharedSecret), Buffer.alloc(32), Buffer.from(info))
    const session = SessionRecord.createEntry()
    session.registrationId = registrationId
    session.currentRatchet = {
      rootKey: masterKey[0],
      ephemeralKeyPair: isInitiator ? curve.generateKeyPair() : ourSignedKey!,
      lastRemoteEphemeralKey: theirSignedPubKey!,
      previousCounter: 0,
    }
    session.indexInfo = {
      created: Date.now(),
      used: Date.now(),
      remoteIdentityKey: theirIdentityPubKey,
      baseKey: isInitiator ? ourEphemeralKey!.pubKey : theirEphemeralPubKey!,
      baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
      closed: -1,
    }
    if (isInitiator) {
      this.calculateSendingRatchet(session, theirSignedPubKey!)
    }
    return session
  }

  calculateSendingRatchet(session: SessionEntry, remoteKey: Uint8Array) {
    const ratchet = session.currentRatchet
    const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey)
    const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from('WhisperRatchet'))
    session.addChain(ratchet.ephemeralKeyPair.pubKey, {
      messageKeys: {},
      chainKey: {
        counter: -1,
        key: masterKey[1],
      },
      chainType: ChainType.SENDING,
    })
    ratchet.rootKey = masterKey[0]
  }
}
