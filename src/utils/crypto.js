import crypto from 'node:crypto';
import env from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96-bit recommended standard for GCM
const AUTH_TAG_LENGTH_BYTES = 16; // 128-bit authentication tag

/**
 * Structured cryptographic error class for TrustVault.
 */
export class CryptoError extends Error {
  /**
   * @param {string} message - Descriptive error message.
   * @param {string} code - Machine-readable error code.
   */
  constructor(message, code = 'CRYPTO_ERROR') {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

/**
 * Helper to obtain the 32-byte master key buffer.
 *
 * @returns {Buffer}
 */
function getMasterKeyBuffer() {
  return Buffer.from(env.MASTER_ENCRYPTION_KEY, 'hex');
}

/**
 * Encrypts an in-memory document buffer using AES-256-GCM.
 * Generates an isolated 12-byte random initialization vector (IV) per invocation.
 *
 * @param {Buffer} buffer - The unencrypted document buffer.
 * @returns {{ encryptedBuffer: Buffer, iv: string, authTag: string }}
 * @throws {CryptoError} If input is invalid or not a non-empty Buffer.
 */
export function encryptBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new CryptoError('Input must be a non-empty Buffer.', 'INVALID_INPUT');
  }

  try {
    const iv = crypto.randomBytes(IV_LENGTH_BYTES);
    const key = getMasterKeyBuffer();
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    const encryptedBuffer = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      encryptedBuffer,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  } catch (err) {
    throw new CryptoError(`Encryption failed: ${err.message}`, 'ENCRYPTION_FAILED');
  }
}

/**
 * Decrypts an AES-256-GCM encrypted document buffer and authenticates data integrity.
 *
 * @param {Buffer} encryptedBuffer - The encrypted document buffer.
 * @param {string} ivHex - 24-character hexadecimal IV string (12 bytes).
 * @param {string} authTagHex - 32-character hexadecimal auth tag string (16 bytes).
 * @returns {Buffer} The verified and decrypted plaintext buffer.
 * @throws {CryptoError} If authentication fails, data was tampered with, or parameters are invalid.
 */
export function decryptBuffer(encryptedBuffer, ivHex, authTagHex) {
  if (!Buffer.isBuffer(encryptedBuffer) || encryptedBuffer.length === 0) {
    throw new CryptoError('Encrypted data must be a non-empty Buffer.', 'INVALID_INPUT');
  }

  if (!ivHex || typeof ivHex !== 'string' || ivHex.length !== IV_LENGTH_BYTES * 2) {
    throw new CryptoError(
      `IV must be a valid ${IV_LENGTH_BYTES * 2}-character hexadecimal string.`,
      'INVALID_IV'
    );
  }

  if (!authTagHex || typeof authTagHex !== 'string' || authTagHex.length !== AUTH_TAG_LENGTH_BYTES * 2) {
    throw new CryptoError(
      `Auth tag must be a valid ${AUTH_TAG_LENGTH_BYTES * 2}-character hexadecimal string.`,
      'INVALID_AUTH_TAG'
    );
  }

  try {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const key = getMasterKeyBuffer();

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  } catch (err) {
    throw new CryptoError(
      'Authentication tag verification failed: Document data has been tampered with or corrupted.',
      'DECRYPTION_FAILED'
    );
  }
}

export default {
  encryptBuffer,
  decryptBuffer,
  CryptoError
};
