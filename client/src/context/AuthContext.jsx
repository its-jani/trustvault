import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import apiClient from '../api/client';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('trustvault_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(() => localStorage.getItem('trustvault_token') || null);
  const [isLoading, setIsLoading] = useState(true);

  // Rehydrate session claims from /api/auth/me on initial boot
  const rehydrateSession = useCallback(async () => {
    const savedToken = localStorage.getItem('trustvault_token');
    if (!savedToken) {
      setUser(null);
      setToken(null);
      setIsLoading(false);
      return;
    }

    try {
      const res = await apiClient('/auth/me');
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setToken(savedToken);
        localStorage.setItem('trustvault_user', JSON.stringify(data.user));
      } else {
        // Stale or revoked token
        localStorage.removeItem('trustvault_token');
        localStorage.removeItem('trustvault_user');
        setUser(null);
        setToken(null);
      }
    } catch (err) {
      console.warn('[TrustVault Auth] Could not reach auth/me verification endpoint:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    rehydrateSession();
  }, [rehydrateSession]);

  /**
   * Log in user with credentials.
   */
  const login = async ({ email, password }) => {
    const res = await apiClient('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || data.message || 'Login failed. Please check credentials.');
    }

    localStorage.setItem('trustvault_token', data.token);
    localStorage.setItem('trustvault_user', JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
    return data.user;
  };

  /**
   * Register a new user account.
   */
  const register = async ({ email, password, full_name, role = 'VIEWER' }) => {
    const res = await apiClient('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name, role })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || data.message || 'Registration failed.');
    }

    // Auto-login if registration returned a session token
    if (data.token) {
      localStorage.setItem('trustvault_token', data.token);
      localStorage.setItem('trustvault_user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
    }

    return data.user;
  };

  /**
   * Log out active user and clear session state.
   */
  const logout = () => {
    localStorage.removeItem('trustvault_token');
    localStorage.removeItem('trustvault_user');
    setUser(null);
    setToken(null);
    window.location.href = '/login';
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        register,
        logout,
        rehydrateSession
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
