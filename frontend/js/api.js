'use strict';

/**
 * Secure Exam Question Paper System — API Client
 * Talks to the Express backend in ../backend (same origin, /api/*)
 */

const API = {
    baseUrl: '/api',

    // The access token and user live in MEMORY only (never localStorage), so an
    // XSS bug can't lift a persistent token. Reloading the page restores the
    // session silently via the httpOnly refresh cookie (see Auth.init).
    _token: null,
    _user: null,

    getToken() { return this._token; },
    setToken(token) { this._token = token || null; },
    getUser() { return this._user; },
    setUser(user) { this._user = user || null; },
    clearAuth() { this._token = null; this._user = null; },

    // Only one refresh call in flight at a time; concurrent 401s all await it
    // instead of each racing to hit /auth/refresh (which would rotate the
    // cookie under each other and fail all but one).
    _refreshInFlight: null,

    async _doRefresh() {
        if (!this._refreshInFlight) {
            this._refreshInFlight = fetch(`${this.baseUrl}/auth/refresh`, {
                method: 'POST',
                credentials: 'include'
            })
                .then(async (res) => {
                    if (!res.ok) return null;
                    const data = await res.json();
                    this.setToken(data.token);
                    this.setUser(data.user);
                    return data.token;
                })
                .catch(() => null)
                .finally(() => { this._refreshInFlight = null; });
        }
        return this._refreshInFlight;
    },

    async request(endpoint, options = {}, _isRetry = false) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { ...(options.headers || {}) };

        const token = this.getToken();
        if (token && !headers['Authorization']) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        if (!(options.body instanceof FormData) && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers,
                credentials: 'include' // sends/receives the httpOnly refresh cookie
            });

            // A 401 on anything other than login/signup/refresh means the access
            // token expired (normal, every 15 min) — try one silent refresh+retry
            // before giving up and forcing the user to log in again.
            const isAuthEndpoint = endpoint.startsWith('/auth/login') || endpoint.startsWith('/auth/signup') || endpoint.startsWith('/auth/refresh');
            if (response.status === 401 && !isAuthEndpoint && !_isRetry) {
                const newToken = await this._doRefresh();
                if (newToken) {
                    return this.request(endpoint, options, true);
                }
                this.clearAuth();
                window.dispatchEvent(new CustomEvent('auth:expired'));
                throw new Error('Session expired. Please sign in again.');
            }

            // Handle blob downloads (e.g. PDF decryption)
            if (options.isBlob) {
                if (!response.ok) {
                    const errJson = await response.json();
                    throw new Error(errJson.message || 'Download failed');
                }
                const blob = await response.blob();
                return { ok: true, blob };
            }

            const data = await response.json();

            if (!response.ok) {
                if (response.status === 401 && !endpoint.includes('/auth/login')) {
                    this.clearAuth();
                    window.dispatchEvent(new CustomEvent('auth:expired'));
                }
                throw new Error(data.message || `Request failed with status ${response.status}`);
            }

            return data;
        } catch (err) {
            console.error(`[API Error] ${endpoint}:`, err.message);
            throw err;
        }
    },

    // Auth Endpoints  (backend: /api/auth/*)
    auth: {
        login(email, password) {
            return API.request('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ email, password })
            });
        },
        signup(payload) {
            return API.request('/auth/signup', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
        },
        me() {
            return API.request('/auth/me');
        },
        // Silent session restore on page load — succeeds only if a valid
        // httpOnly refresh cookie is still present.
        refresh() {
            return API._doRefresh();
        },
        logout() {
            return API.request('/auth/logout', { method: 'POST' }).catch(() => {});
        },
        // approvers + invigilators, used to pick who receives key shares
        approvers() {
            return API.request('/auth/approvers');
        }
    },

    // Admin Endpoints  (backend: /api/admin/*) — visible to admin accounts only
    admin: {
        users() {
            return API.request('/admin/users');
        },
        setRole(userId, role) {
            return API.request(`/admin/users/${userId}/role`, {
                method: 'PATCH',
                body: JSON.stringify({ role })
            });
        }
    },

    // Paper Endpoints  (backend: /api/papers/*)
    papers: {
        list() {
            return API.request('/papers');
        },
        status(id) {
            return API.request(`/papers/${id}/status`);
        },
        upload(formData) {
            return API.request('/papers', {
                method: 'POST',
                body: formData
            });
        },
        approve(id) {
            return API.request(`/papers/${id}/approve`, {
                method: 'POST'
            });
        },
        // Invigilator only: gated decrypt (approvals + time-lock). Returns the file.
        unlock(id) {
            return API.request(`/papers/${id}/unlock`, {
                method: 'POST',
                isBlob: true
            });
        }
    },

    // Audit Endpoints  (backend: /api/audit)
    audit: {
        history(paperId) {
            return API.request(`/audit${paperId ? `?paperId=${encodeURIComponent(paperId)}` : ''}`);
        },
        verify(force = false) {
            return API.request(`/audit/verify${force ? '?force=true' : ''}`);
        },
        demoStatus() {
            return API.request('/audit/demo-status');
        },
        simulateTamper(targetId) {
            return API.request('/audit/simulate-tamper', {
                method: 'POST',
                body: JSON.stringify(targetId ? { targetId } : {})
            });
        },
        restoreTamper() {
            return API.request('/audit/restore-tamper', {
                method: 'POST'
            });
        }
    }
};

// One-time cleanup of keys left behind by older versions of this app
try { localStorage.removeItem('exam_auth_token'); localStorage.removeItem('exam_auth_user'); } catch (e) { /* storage blocked */ }

window.API = API;
