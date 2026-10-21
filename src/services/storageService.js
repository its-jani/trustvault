import supabase from '../config/supabase.js';
import env from '../config/env.js';

/**
 * Custom structured error for Supabase Storage operations.
 */
export class StorageError extends Error {
  /**
   * @param {string} message - Descriptive error message.
   * @param {string} code - Machine-readable error code.
   * @param {any} [details=null] - Upstream storage error payload.
   */
  constructor(message, code = 'STORAGE_ERROR', details = null) {
    super(message);
    this.name = 'StorageError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Uploads an encrypted document buffer directly to the private Supabase Storage bucket.
 *
 * @param {Object} params
 * @param {string} params.storagePath - Virtualized storage path (e.g. documents/ownerId/uuid).
 * @param {Buffer} params.encryptedBuffer - Ciphertext buffer.
 * @param {string} [params.mimeType='application/octet-stream'] - Content type indicator.
 * @returns {Promise<Object>} Supabase storage upload response.
 * @throws {StorageError} If upload fails or parameters are invalid.
 */
export async function uploadEncryptedDocument({ storagePath, encryptedBuffer, mimeType = 'application/octet-stream' }) {
  if (!storagePath || typeof storagePath !== 'string') {
    throw new StorageError('Storage path must be a valid non-empty string.', 'INVALID_STORAGE_PATH');
  }

  if (!Buffer.isBuffer(encryptedBuffer) || encryptedBuffer.length === 0) {
    throw new StorageError('Encrypted buffer must be a non-empty Buffer.', 'INVALID_BUFFER');
  }

  const { data, error } = await supabase.storage
    .from(env.SUPABASE_STORAGE_BUCKET)
    .upload(storagePath, encryptedBuffer, {
      contentType: mimeType,
      upsert: false
    });

  if (error) {
    throw new StorageError(
      `Failed to upload document to storage: ${error.message}`,
      'UPLOAD_FAILED',
      error
    );
  }

  return data;
}

/**
 * Downloads an encrypted document buffer from the private Supabase Storage bucket.
 *
 * @param {string} storagePath - Virtualized storage path.
 * @returns {Promise<Buffer>} The downloaded ciphertext buffer.
 * @throws {StorageError} If download fails or object does not exist.
 */
export async function downloadEncryptedDocument(storagePath) {
  if (!storagePath || typeof storagePath !== 'string') {
    throw new StorageError('Storage path must be a valid non-empty string.', 'INVALID_STORAGE_PATH');
  }

  const { data, error } = await supabase.storage
    .from(env.SUPABASE_STORAGE_BUCKET)
    .download(storagePath);

  if (error) {
    throw new StorageError(
      `Failed to download document from storage: ${error.message}`,
      'DOWNLOAD_FAILED',
      error
    );
  }

  // Convert downloaded Blob to Node.js Buffer
  const arrayBuffer = await data.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

/**
 * Deletes a document blob from the private Supabase Storage bucket.
 *
 * @param {string} storagePath - Virtualized storage path.
 * @returns {Promise<Object>} Deletion result metadata.
 * @throws {StorageError} If deletion fails.
 */
export async function deleteDocumentFromStorage(storagePath) {
  if (!storagePath || typeof storagePath !== 'string') {
    throw new StorageError('Storage path must be a valid non-empty string.', 'INVALID_STORAGE_PATH');
  }

  const { data, error } = await supabase.storage
    .from(env.SUPABASE_STORAGE_BUCKET)
    .remove([storagePath]);

  if (error) {
    throw new StorageError(
      `Failed to delete document from storage: ${error.message}`,
      'DELETE_FAILED',
      error
    );
  }

  return data;
}

export default {
  uploadEncryptedDocument,
  downloadEncryptedDocument,
  deleteDocumentFromStorage,
  StorageError
};
