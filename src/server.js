import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import supabase from './config/supabase.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import authRoutes from './routes/authRoutes.js';
import documentRoutes from './routes/documentRoutes.js';
import grantRoutes from './routes/grantRoutes.js';
import auditRoutes from './routes/auditRoutes.js';
import { authRateLimiter, globalRateLimiter } from './middleware/rateLimiter.js';
import { sanitizeInputs } from './middleware/validator.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// 1. Security Headers Middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'no-referrer' },
    xssFilter: true
  })
);

// 2. CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:3000', 'http://localhost:5173'];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl, server-to-server)
      if (!origin || allowedOrigins.includes(origin) || NODE_ENV === 'development') {
        return callback(null, true);
      }
      return callback(new Error('CORS request blocked by TrustVault security policy.'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  })
);

// 3. Body Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Input Sanitization Middleware
app.use(sanitizeInputs);

// 5. Public Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 6. Root Welcome Route
app.get('/', (req, res) => {
  res.status(200).json({
    service: 'TrustVault Security-First Document Platform API',
    status: 'OPERATIONAL',
    version: '1.0.0',
    documentation: '/api/health'
  });
});

// 5. Database Health Check Route
app.get('/api/health', async (req, res, next) => {
  try {
    let dbStatus = 'disconnected';
    let dbError = null;

    if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
      try {
        // Query users table directly without head/count metadata wrappers
        const { data, error } = await supabase.from('users').select('id').limit(1);

        if (error) {
          console.error('[SUPABASE HEALTHCHECK ERROR]:', error);
          dbStatus = 'degraded';
          dbError = error.message || error;
        } else {
          dbStatus = 'connected';
        }
      } catch (err) {
        console.error('[SUPABASE FETCH EXCEPTION]:', err);
        dbStatus = 'unreachable';
        dbError = err.message;
      }
    } else {
      dbStatus = 'unconfigured';
    }

    const isHealthy = dbStatus === 'connected';

    res.status(isHealthy ? 200 : 503).json({
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      database: {
        status: dbStatus,
        ...(NODE_ENV === 'development' && dbError ? { details: dbError } : {})
      },
      uptimeSeconds: Math.floor(process.uptime())
    });
  } catch (err) {
    next(err);
  }
});

// 8. Rate Limiting Middleware
app.use('/api/auth/login', authRateLimiter);
app.use('/api/auth/register', authRateLimiter);
app.use('/api', globalRateLimiter);

// 9. Application Routes
app.use('/api/auth', authRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/grants', grantRoutes);
app.use('/api/audit-logs', auditRoutes);

// 7. 404 Handler for Unmatched Endpoints
app.use(notFoundHandler);

// 8. Centralized Error Handler
app.use(errorHandler);

// Server Execution (skip in test or Vercel serverless environment)
if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) {
  const server = app.listen(PORT, () => {
    console.log(`[TrustVault] Server running in ${NODE_ENV} mode on port ${PORT}`);
    console.log(`[TrustVault] Healthcheck available at http://localhost:${PORT}/api/health`);
  });

  // Graceful shutdown handling
  const shutdown = (signal) => {
    console.log(`[TrustVault] Received ${signal}. Commencing graceful shutdown...`);
    server.close(() => {
      console.log('[TrustVault] HTTP server terminated cleanly.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

export default app;
