import supabase from '../config/supabase.js';
import { hashPassword, comparePassword } from '../utils/password.js';
import { generateToken, VALID_ROLES } from '../utils/jwt.js';
import { logAuditEvent } from '../utils/auditLogger.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Registers a new user account with role assignment and audit logging.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function register(req, res, next) {
  try {
    const { email, password, full_name, role } = req.body || {};
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    // 1. Input Validation
    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const assignedRole = role || 'VIEWER';
    if (!VALID_ROLES.includes(assignedRole)) {
      return res.status(400).json({
        error: `Invalid role specified. Permissible roles: ${VALID_ROLES.join(', ')}.`
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const fullName = typeof full_name === 'string' && full_name.trim()
      ? full_name.trim()
      : normalizedEmail.split('@')[0];

    // 2. Conflict Check (Email Uniqueness)
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', normalizedEmail)
      .maybeSingle();

    if (checkError) {
      return next(checkError);
    }

    if (existingUser) {
      await logAuditEvent({
        userId: null,
        action: 'REGISTRATION_CONFLICT',
        resource: req.originalUrl,
        details: { email: normalizedEmail, reason: 'EMAIL_ALREADY_EXISTS' },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(409).json({ error: 'Email already registered.' });
    }

    // 3. Password Hashing
    const password_hash = await hashPassword(password);

    // 4. Persistence
    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert([
        {
          email: normalizedEmail,
          password_hash,
          full_name: fullName,
          role: assignedRole
        }
      ])
      .select('id, email, full_name, role, created_at')
      .single();

    if (insertError) {
      return next(insertError);
    }

    // 5. Audit Logging (Zero-trust immutable audit trail)
    await logAuditEvent({
      userId: newUser.id,
      action: 'USER_REGISTERED',
      resource: `/users/${newUser.id}`,
      details: { email: newUser.email, role: newUser.role },
      ipAddress,
      status: 'SUCCESS'
    });

    // 6. Response (Never leak password_hash)
    return res.status(201).json({
      message: 'User registered successfully.',
      user: {
        id: newUser.id,
        email: newUser.email,
        full_name: newUser.full_name,
        role: newUser.role,
        created_at: newUser.created_at
      }
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * Authenticates user credentials, generates a signed JWT session, and logs audit events.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};
    const ipAddress = req.ip || req.socket?.remoteAddress || 'unknown';

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // 1. Fetch User Record
    const { data: user, error: fetchError } = await supabase
      .from('users')
      .select('id, email, password_hash, full_name, role')
      .eq('email', normalizedEmail)
      .maybeSingle();

    if (fetchError) {
      return next(fetchError);
    }

    // 2. Guard against non-existent users (Constant error message to prevent enumeration)
    if (!user) {
      await logAuditEvent({
        userId: null,
        action: 'LOGIN_FAILED_UNKNOWN_USER',
        resource: req.originalUrl,
        details: { attemptedEmail: normalizedEmail },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // 3. Constant-Time Password Verification
    const isMatch = await comparePassword(password, user.password_hash);

    if (!isMatch) {
      await logAuditEvent({
        userId: user.id,
        action: 'LOGIN_FAILED_INVALID_PASSWORD',
        resource: req.originalUrl,
        details: { email: user.email },
        ipAddress,
        status: 'DENIED'
      });

      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // 4. Issue Authoritative Session JWT
    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    // 5. Successful Audit Record
    await logAuditEvent({
      userId: user.id,
      action: 'USER_LOGIN_SUCCESS',
      resource: req.originalUrl,
      details: { email: user.email, role: user.role },
      ipAddress,
      status: 'SUCCESS'
    });

    // 6. Response
    return res.status(200).json({
      message: 'Login successful.',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * Returns current authenticated user identity extracted by authenticateToken middleware.
 *
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
export function getMe(req, res) {
  return res.status(200).json({
    user: req.user
  });
}

export default {
  register,
  login,
  getMe
};
