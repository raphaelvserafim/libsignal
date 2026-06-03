import crypto from './crypto/index.js'
import curve from './crypto/curve.js'
import * as keyhelper from './crypto/keyhelper.js'
import { ProtocolAddress } from './protocol/protocol-address.js'
import { SessionBuilder } from './protocol/session-builder.js'
import { SessionCipher } from './protocol/session-cipher.js'
import { SessionRecord } from './protocol/session-record.js'
import * as errors from './utils/errors.js'
import { GroupCipher } from './group/group-cipher.js'
import { GroupSessionBuilder } from './group/group-session-builder.js'
import { SenderKeyDistributionMessage } from './group/sender-key-distribution-message.js'
import { SenderKeyRecord } from './group/sender-key-record.js'
import { SenderKeyName } from './group/sender-key-name.js'
import * as groupKeyHelper from './group/keyhelper.js'

export {
  crypto,
  curve,
  keyhelper,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  errors,
  GroupCipher,
  GroupSessionBuilder,
  SenderKeyDistributionMessage,
  SenderKeyRecord,
  SenderKeyName,
  groupKeyHelper,
}

export type { SenderKeyStore } from './group/group-cipher.js'

const libsignal = {
  crypto,
  curve,
  keyhelper,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  GroupCipher,
  GroupSessionBuilder,
  SenderKeyDistributionMessage,
  SenderKeyRecord,
  SenderKeyName,
  groupKeyHelper,
  ...errors,
}

export default libsignal
