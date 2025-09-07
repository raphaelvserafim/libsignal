import crypto from './crypto/index.js';
import curve from './crypto/curve.js';
import * as keyhelper from './crypto/keyhelper.js';
import { ProtocolAddress } from './protocol/protocol-address.js';
import { SessionBuilder } from './protocol/session-builder.js';
import { SessionCipher } from './protocol/session-cipher.js';
import { SessionRecord } from './protocol/session-record.js';
import * as errors from './utils/errors.js';

export {
  crypto,
  curve,
  keyhelper,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  errors
};

const libsignal = {
  crypto,
  curve,
  keyhelper,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  ...errors
};

export default libsignal;