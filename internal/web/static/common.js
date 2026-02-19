(() => {
  const tokenKey = 'apim.web.token';

  function token() {
    return localStorage.getItem(tokenKey) || '';
  }

  function setToken(v) {
    if (!v) {
      localStorage.removeItem(tokenKey);
      return;
    }
    localStorage.setItem(tokenKey, v.trim());
  }

  async function api(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (!headers['Content-Type'] && options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    const t = token();
    if (t) {
      headers['Authorization'] = `Bearer ${t}`;
    }
    const resp = await fetch(path, Object.assign({}, options, {
      headers,
      credentials: 'include',
    }));
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) {}
    if (!resp.ok) {
      const message = data && data.error ? data.error : `HTTP ${resp.status}`;
      const err = new Error(message);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  async function register(email, password) {
    return api('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async function login(email, password) {
    return api('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async function logout() {
    try {
      await api('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      setToken('');
    }
  }

  function normalizePrincipal(input) {
    if (!input || typeof input !== 'object') return null;
    const role = String(input.role ?? input.Role ?? '').trim().toLowerCase();
    const email = String(input.email ?? input.Email ?? '').trim();
    const provider = String(input.provider ?? input.Provider ?? '').trim();
    const subject = String(input.subject ?? input.Subject ?? '').trim();
    const userId = input.user_id ?? input.userId ?? input.UserID ?? null;
    if (!role) return null;
    return {
      role,
      email,
      provider,
      subject,
      user_id: userId,
    };
  }

  async function fetchPrincipal() {
    try {
      const data = await api('/api/v1/auth/me');
      return normalizePrincipal(data && data.principal ? data.principal : null);
    } catch (err) {
      if (err && err.status === 401) {
        return null;
      }
      throw err;
    }
  }

  function routeForRole(role) {
    if (role === 'admin') return '/webapp/admin/overview';
    if (role === 'user') return '/webapp/user/plans';
    return '/web/login';
  }

  async function redirectByRole() {
    const principal = await fetchPrincipal();
    if (!principal) {
      window.location.assign('/web/login');
      return null;
    }
    window.location.assign(routeForRole(principal.role));
    return principal;
  }

  function htmlEscape(input) {
    const s = String(input ?? '');
    return s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function fmtTime(input) {
    if (!input) return '-';
    const d = new Date(input);
    if (Number.isNaN(d.getTime())) return String(input);
    return d.toISOString();
  }

  function fmtNum(input) {
    if (input === null || input === undefined) return '-';
    return Number(input).toLocaleString();
  }

  function q(id) {
    return document.getElementById(id);
  }

  function on(el, event, fn) {
    if (el) el.addEventListener(event, fn);
  }

  async function requireSession(roles) {
    const principal = await fetchPrincipal();
    if (!principal) {
      window.location.assign('/web/login');
      throw new Error('missing session principal');
    }
    const normalizedRoles = Array.isArray(roles)
      ? roles.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean)
      : [];
    if (normalizedRoles.length > 0 && !normalizedRoles.includes(principal.role)) {
      window.location.assign(routeForRole(principal.role));
      throw new Error(`role ${principal.role} cannot access this page`);
    }
    return principal;
  }

  window.APIMWeb = {
    token,
    setToken,
    api,
    register,
    login,
    logout,
    fetchPrincipal,
    routeForRole,
    redirectByRole,
    htmlEscape,
    fmtTime,
    fmtNum,
    q,
    on,
    requireSession,
  };
})();
