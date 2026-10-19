/**
 * Custom Operational Application Error.
 * Differentiates anticipated operational errors from unhandled programmer exceptions.
 */
export class AppError extends Error {
  /**
   * @param {string} message - Human-readable error message.
   * @param {number} statusCode - HTTP status code.
   * @param {any} [details=null] - Additional contextual details (sanitized).
   */
  constructor(message, statusCode = 500, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.details = details;

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * 404 Not Found Catch-All Middleware.
 */
export const notFoundHandler = (req, res, next) => {
  next(new AppError(`Resource not found: ${req.method} ${req.originalUrl}`, 404));
};

/**
 * Centralized Express Error Handling Middleware.
 * Strictly prevents stack trace and sensitive internal leaks in production.
 */
export const errorHandler = (err, req, res, next) => {
  const isProduction = process.env.NODE_ENV === 'production';
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';

  // Handle specific database / parser errors gracefully
  if (err.type === 'entity.parse.failed') {
    statusCode = 400;
    message = 'Malformed JSON payload provided in request body.';
  }

  // Prevent internal error details leaking in production for unhandled 500s
  if (isProduction && (!err.isOperational || statusCode === 500)) {
    message = 'An internal server error occurred. Please contact security administration.';
  }

  // Server-side logging for diagnostics
  console.error(`[ERROR] [${new Date().toISOString()}] ${req.method} ${req.originalUrl}:`, {
    statusCode,
    message: err.message,
    ...(isProduction ? {} : { stack: err.stack })
  });

  const response = {
    success: false,
    status: `${statusCode}`.startsWith('4') ? 'fail' : 'error',
    statusCode,
    message,
    timestamp: new Date().toISOString(),
    path: req.originalUrl
  };

  // Attach stack and details only in development / non-production
  if (!isProduction) {
    if (err.details) response.details = err.details;
    response.stack = err.stack;
  }

  res.status(statusCode).json(response);
};

export default errorHandler;
