import dotenv from 'dotenv';

dotenv.config();

const isExecutingTest = process.env.NODE_ENV === 'test' || process.argv.some(arg => arg.includes('test'));
const NODE_ENV = process.env.NODE_ENV || (isExecutingTest ? 'test' : 'development');
const isTest = NODE_ENV === 'test' || isExecutingTest;

// Validate critical security secrets
if (!process.env.JWT_SECRET && !isTest) {
  throw new Error(
    'FATAL: JWT_SECRET environment variable is missing. Authentication cannot function securely.'
  );
}

if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32 && !isTest) {
  console.warn(
    '\x1b[33m%s\x1b[0m',
    '[TrustVault Warning] JWT_SECRET is less than 32 characters. Stronger entropy is recommended.'
  );
}

export const env = {
  PORT: parseInt(process.env.PORT, 10) || 5000,
  NODE_ENV,
  isProduction: NODE_ENV === 'production',
  isTest,
  SUPABASE_URL: process.env.SUPABASE_URL || 'https://placeholder.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-key',
  JWT_SECRET: process.env.JWT_SECRET || (isTest ? 'test_jwt_secret_key_minimum_32_characters_long' : ''),
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
  BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12
};

export default env;
