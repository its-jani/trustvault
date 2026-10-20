import bcrypt from 'bcryptjs';
import env from '../config/env.js';

/**
 * Minimum allowable password length under TrustVault security policy.
 */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * Hashes a plaintext password using bcrypt with configured salt rounds.
 * Enforces minimum length requirements before hashing.
 *
 * @param {string} plaintextPassword - The raw password string.
 * @returns {Promise<string>} The generated bcrypt hash.
 * @throws {Error} If password is under minimum length or invalid.
 */
export async function hashPassword(plaintextPassword) {
  if (typeof plaintextPassword !== 'string' || plaintextPassword.length < MIN_PASSWORD_LENGTH) {
    throw new Error(
      `Password does not satisfy security policy: must be at least ${MIN_PASSWORD_LENGTH} characters long.`
    );
  }

  return await bcrypt.hash(plaintextPassword, env.BCRYPT_SALT_ROUNDS);
}

/**
 * Compares a candidate plaintext password against an existing bcrypt hash in constant time.
 *
 * @param {string} plaintextPassword - The raw password attempted during authentication.
 * @param {string} hashedPassword - The stored bcrypt hash.
 * @returns {Promise<boolean>} True if matching, false otherwise.
 */
export async function comparePassword(plaintextPassword, hashedPassword) {
  if (typeof plaintextPassword !== 'string' || typeof hashedPassword !== 'string' || !hashedPassword) {
    return false;
  }

  return await bcrypt.compare(plaintextPassword, hashedPassword);
}
