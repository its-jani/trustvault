const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

/**
 * Universal API Client with automatic Bearer Token injection and 401 redirection.
 *
 * @param {string} endpoint - Relative API endpoint path (e.g., '/auth/login')
 * @param {RequestInit} [options={}] - Fetch configuration options
 * @returns {Promise<Response>}
 */
export async function apiClient(endpoint, options = {}) {
  const token = localStorage.getItem('trustvault_token');
  const headers = {
    ...options.headers
  };

  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const url = `${BASE_URL}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers
    });

    // Handle 401 Unauthorized globally: evict stale token and redirect
    if (response.status === 401) {
      localStorage.removeItem('trustvault_token');
      localStorage.removeItem('trustvault_user');
      if (
        typeof window !== 'undefined' &&
        !window.location.pathname.startsWith('/login') &&
        !window.location.pathname.startsWith('/register')
      ) {
        window.location.href = '/login?expired=true';
      }
    }

    return response;
  } catch (err) {
    console.error(`[API Error] ${options.method || 'GET'} ${url}:`, err);
    throw err;
  }
}

export default apiClient;
