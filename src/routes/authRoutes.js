import { Router } from 'express';
import { register, login, getMe } from '../controllers/authController.js';
import { authenticateToken } from '../middleware/auth.js';

const router = Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user account (defaults to VIEWER)
 * @access  Public
 */
router.post('/register', register);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate credentials and receive signed session JWT
 * @access  Public
 */
router.post('/login', login);

/**
 * @route   GET /api/auth/me
 * @desc    Retrieve verified identity claims of current user
 * @access  Protected (Bearer JWT required)
 */
router.get('/me', authenticateToken, getMe);

export default router;
