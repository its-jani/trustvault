import multer from 'multer';

export const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB limit

/**
 * Configure strictly in-memory storage.
 * Documents must NEVER be written unencrypted to the local filesystem or temp folders.
 */
const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE_BYTES,
    files: 1
  }
});

/**
 * Express middleware for ingesting a single document file into RAM.
 * Intercepts Multer limits and formats clean security responses.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function uploadSingleDocument(req, res, next) {
  const handler = upload.single('document');

  handler(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({
            error: 'File size exceeds maximum allowable limit (10MB).'
          });
        }
        return res.status(400).json({ error: `File upload error: ${err.message}` });
      }
      return res.status(400).json({ error: `Upload failed: ${err.message}` });
    }
    return next();
  });
}

export default {
  uploadSingleDocument,
  MAX_FILE_SIZE_BYTES
};
