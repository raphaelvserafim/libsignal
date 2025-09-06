
/**
 * @class SignalError
 * @extends Error
 * @desc Base class for all signal-related errors.
 */
export class SignalError extends Error { }

/**
 * @class UntrustedIdentityKeyError
 * @extends SignalError
 * @desc Thrown when a message is received with an untrusted identity key.
 */
export class UntrustedIdentityKeyError extends SignalError {
  public readonly name: string = 'UntrustedIdentityKeyError';
  public readonly addr: string;
  public readonly identityKey: any; // Using 'any' as the original type is not specified

  constructor(addr: string, identityKey: any) {
    super();
    this.addr = addr;
    this.identityKey = identityKey;
  }
}

/**
 * @class SessionError
 * @extends SignalError
 * @desc Base class for session-related errors.
 */
export class SessionError extends SignalError {
  public readonly name: string = 'SessionError';

  constructor(message: string) {
    super(message);
  }
}

/**
 * @class MessageCounterError
 * @extends SessionError
 * @desc Thrown when a message counter is out of sync.
 */
export class MessageCounterError extends SessionError {
  public readonly name: string = 'MessageCounterError';

  constructor(message: string) {
    super(message);
  }
}

/**
 * @class PreKeyError
 * @extends SessionError
 * @desc Thrown when there is an issue with a prekey.
 */
export class PreKeyError extends SessionError {
  public readonly name: string = 'PreKeyError';

  constructor(message: string) {
    super(message);
  }
}