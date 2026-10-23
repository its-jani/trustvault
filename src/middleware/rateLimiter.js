import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for sensitive authentication endpoints (login, register).
 * Enforces a maximum of 10 requests per 15-minute window per IP.
 */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  message: {
    error: 'Too many authentication attempts. Please try again later.'
  },
  // In test mode, allow integration test suites to run unless explicitly testing rate limits
  skip: (req) => process.env.NODE_ENV === 'test' && !req.headers['x-test-rate-limit']
});

/**
 * Global rate limiter protecting all API endpoints against unbounded traffic spikes.
 * Enforces a maximum of 200 requests per 15-minute window per IP.
 */
export const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  message: {
    error: 'Too many requests from this IP. Please try again later.'
  },
  skip: (req) => process.env.NODE_ENV === 'test' && !req.headers['x-test-global-rate-limit']
});

export default {
  authRateLimiter,
  globalRateLimiter
};
