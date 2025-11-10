/**
 * ProtocolAddress represents a unique identifier for a device in the protocol.
 * It consists of an id (string) and a deviceId (number).
 * The string representation is in the format "id.deviceId".
 * @raphaelvserafim
 */

export class ProtocolAddress {
  public readonly id: string;
  public readonly deviceId: number;

  static from(encodedAddress: string): ProtocolAddress {
    if (typeof encodedAddress !== 'string') {
      throw new Error('encodedAddress must be a string');
    }

    if (!encodedAddress || encodedAddress.trim() === '') {
      throw new Error('encodedAddress cannot be empty');
    }


    // ^.+\. = começa com um ou mais caracteres seguidos de ponto
    // \d+$ = termina com um ou mais dígitos
    if (!encodedAddress.match(/^.+\.\d+$/)) {
      throw new Error('Invalid address encoding: must be in format "id.deviceId"');
    }

    // Split apenas no último ponto para permitir IDs com pontos
    const lastDotIndex = encodedAddress.lastIndexOf('.');
    const id = encodedAddress.substring(0, lastDotIndex);
    const deviceIdStr = encodedAddress.substring(lastDotIndex + 1);

    // Validação adicional do ID
    if (id.trim() === '') {
      throw new Error('Invalid address encoding: id cannot be empty');
    }

    // Parse do deviceId com validação
    const deviceId = parseInt(deviceIdStr, 10);

    if (isNaN(deviceId)) {
      throw new Error('Invalid address encoding: deviceId must be a valid number');
    }

    if (deviceId < 0) {
      throw new Error('Invalid address encoding: deviceId must be non-negative');
    }

    if (!Number.isFinite(deviceId)) {
      throw new Error('Invalid address encoding: deviceId must be finite');
    }

    // Validação de overflow (número muito grande)
    if (deviceId > Number.MAX_SAFE_INTEGER) {
      throw new Error('Invalid address encoding: deviceId exceeds maximum safe integer');
    }

    return new this(id, deviceId);
  }

  constructor(id: string, deviceId: number) {
    // Validação do tipo de id
    if (typeof id !== 'string') {
      throw new TypeError('id must be a string');
    }

    // Validação de id vazio
    if (!id || id.trim() === '') {
      throw new TypeError('id cannot be empty');
    }

    // Validação de ponto no id (encoded address)
    if (id.indexOf('.') !== -1) {
      throw new TypeError('id cannot contain dots (use ProtocolAddress.from() for encoded addresses)');
    }

    // Validação do tipo de deviceId
    if (typeof deviceId !== 'number') {
      throw new TypeError('deviceId must be a number');
    }

    // Validação de NaN
    if (isNaN(deviceId)) {
      throw new TypeError('deviceId cannot be NaN');
    }

    // Validação de número finito
    if (!Number.isFinite(deviceId)) {
      throw new TypeError('deviceId must be a finite number');
    }

    // Validação de número inteiro
    if (!Number.isInteger(deviceId)) {
      throw new TypeError('deviceId must be an integer');
    }

    // Validação de número não-negativo
    if (deviceId < 0) {
      throw new TypeError('deviceId must be non-negative');
    }

    // Validação de overflow
    if (deviceId > Number.MAX_SAFE_INTEGER) {
      throw new TypeError('deviceId exceeds maximum safe integer');
    }

    this.id = id.trim();
    this.deviceId = deviceId;
  }

  toString(): string {
    return `${this.id}.${this.deviceId}`;
  }

  is(other: ProtocolAddress): boolean {
    if (!(other instanceof ProtocolAddress)) {
      return false;
    }
    return other.id === this.id && other.deviceId === this.deviceId;
  }

  /**
   * Método auxiliar para comparação estrita de igualdade
   */
  equals(other: unknown): boolean {
    return this.is(other as ProtocolAddress);
  }

  /**
   * Método auxiliar para obter uma representação hash-like
   */
  toKey(): string {
    return this.toString();
  }
}