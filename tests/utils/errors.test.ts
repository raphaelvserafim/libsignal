import { describe, it, expect } from 'vitest'
import {
  SignalError,
  UntrustedIdentityKeyError,
  SessionError,
  MessageCounterError,
  PreKeyError,
} from '../../src/utils/errors'

describe('errors', () => {
  it('SignalError extends Error', () => {
    const err = new SignalError('test')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(SignalError)
    expect(err.message).toBe('test')
  })

  it('UntrustedIdentityKeyError extends SignalError', () => {
    const key = Buffer.alloc(33)
    const err = new UntrustedIdentityKeyError('addr1', key)
    expect(err).toBeInstanceOf(SignalError)
    expect(err.name).toBe('UntrustedIdentityKeyError')
    expect(err.addr).toBe('addr1')
    expect(err.identityKey).toBe(key)
  })

  it('SessionError extends SignalError', () => {
    const err = new SessionError('no session')
    expect(err).toBeInstanceOf(SignalError)
    expect(err.name).toBe('SessionError')
    expect(err.message).toBe('no session')
  })

  it('MessageCounterError extends SessionError', () => {
    const err = new MessageCounterError('counter')
    expect(err).toBeInstanceOf(SessionError)
    expect(err).toBeInstanceOf(SignalError)
    expect(err.name).toBe('MessageCounterError')
  })

  it('PreKeyError extends SessionError', () => {
    const err = new PreKeyError('missing key')
    expect(err).toBeInstanceOf(SessionError)
    expect(err.name).toBe('PreKeyError')
  })
})
