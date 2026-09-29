'use strict';

/**
 * Auth Module — JWT Token & Secure Session Management
 * Role-based UI guards for Setter, Approver, Invigilator (matches backend roles)
 * Strictly starts on Login page without headers or quick-role switchers
 */

const Auth = {
    currentUser: null,

    async init() {
        this.setupEventListeners();

        // Try a silent session restore using the httpOnly refresh cookie
        // (this is the whole point of having a refresh token: the user
        // doesn't have to log in again just because the tab was reloaded
        // or the 15-minute access token expired while they were away).
        const restored = await this.tryRestoreSession();

        if (!restored && !this.currentUser) {
            // Only clear auth state if nothing else signed the user in while
            // this restore attempt was in flight (e.g. they typed their
            // password and hit submit before the silent check resolved) —
            // otherwise this would silently log out a user who just logged in.
            API.clearAuth();
        }

        this.applyAuthState();

        // A manual login already redirects itself (see handleLogin); only
        // auto-redirect here for a successful SILENT restore on page load.
        if (restored && this.currentUser) {
            this.redirectByRole(this.currentUser.role);
        }
    },

    async tryRestoreSession() {
        try {
            const token = await API.auth.refresh();
            if (!token) return false;
            this.currentUser = API.getUser();
            return Boolean(this.currentUser);
        } catch (err) {
            return false;
        }
    },

    setupEventListeners() {
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        const showSignup = document.getElementById('show-signup-btn');
        const showLogin = document.getElementById('show-login-btn');
        const signupForm = document.getElementById('signup-form');
        const toggleForms = (signup) => {
            loginForm.style.display = signup ? 'none' : '';
            signupForm.style.display = signup ? '' : 'none';
            showSignup.parentElement.style.display = signup ? 'none' : '';
        };
        if (showSignup && showLogin && signupForm && loginForm) {
            showSignup.addEventListener('click', (e) => { e.preventDefault(); toggleForms(true); });
            showLogin.addEventListener('click', (e) => { e.preventDefault(); toggleForms(false); });
            signupForm.addEventListener('submit', (e) => this.handleSignup(e, toggleForms));
        }

        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        window.addEventListener('auth:expired', () => {
            this.handleLogout('Your session has expired. Please sign in again.');
        });
    },

    async handleLogin(e) {
        if (e) e.preventDefault();

        const email = document.getElementById('login-email')?.value.trim();
        const password = document.getElementById('login-password')?.value;

        if (!email || !password) {
            App.showToast('Please enter both academic email and password.', 'warning');
            return;
        }

        const submitBtn = document.getElementById('login-submit-btn');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Authenticating Credentials...';
        }

        try {
            const res = await API.auth.login(email, password);
            API.setToken(res.token);
            API.setUser(res.user);
            this.currentUser = res.user;

            App.showToast(`Signed in successfully as ${res.user.name}.`, 'success');
            this.applyAuthState();

            // Direct to appropriate initial dashboard view based on institutional role
            this.redirectByRole(res.user.role);
        } catch (err) {
            App.showToast(err.message || 'Authentication failed. Please verify credentials.', 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Sign In';
            }
        }
    },

    async handleSignup(e, toggleForms) {
        e.preventDefault();
        const name = document.getElementById('signup-name').value.trim();
        const email = document.getElementById('signup-email').value.trim();
        const password = document.getElementById('signup-password').value;

        const btn = document.getElementById('signup-submit-btn');
        btn.disabled = true;
        btn.textContent = 'Creating account...';

        try {
            const res = await API.auth.signup({ name, email, password });
            App.showToast(res.message || 'Account created. An admin will assign your role before you can sign in.', 'success');
            document.getElementById('signup-form').reset();
            document.getElementById('login-email').value = email;
            toggleForms(false);
        } catch (err) {
            App.showToast(err.message || 'Sign up failed.', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Create Account';
        }
    },

    async handleLogout(msg) {
        // Tell the server too: this revokes the refresh token (tokenVersion
        // bump) so the cookie can't be replayed even if it leaks. Fire this
        // before clearing local state, but don't block sign-out on it.
        await API.auth.logout();

        API.clearAuth();
        this.currentUser = null;
        this.applyAuthState();
        App.showToast(msg || 'Signed out of portal.', 'info');
        App.switchView('view-login');

        // Reset login form fields
        const loginForm = document.getElementById('login-form');
        if (loginForm) loginForm.reset();
    },

    redirectByRole(role) {
        switch (role) {
            case 'setter':
                App.switchView('view-upload');
                break;
            case 'approver':
                App.switchView('view-approvals');
                break;
            case 'invigilator':
                App.switchView('view-unlock');
                break;
            case 'admin':
            default:
                // admin (and any unrecognized role) lands on the dashboard
                App.switchView('view-dashboard');
                break;
        }
    },

    applyAuthState() {
        const isAuth = Boolean(this.currentUser && API.getToken());
        const user = this.currentUser;

        // Header and navigation elements
        const appHeader = document.getElementById('app-header');
        const userMenu = document.getElementById('user-menu');
        const navTabs = document.getElementById('main-nav-tabs');

        if (isAuth && user) {
            document.body.classList.remove('login-mode');
            if (appHeader) appHeader.style.display = 'flex';

            if (userMenu) {
                userMenu.style.display = 'flex';
                const nameEl = document.getElementById('user-display-name');
                if (nameEl) nameEl.textContent = user.name;
                
                const roleBadge = document.getElementById('user-display-role');
                if (roleBadge) {
                    roleBadge.textContent = user.role.toUpperCase();
                    roleBadge.className = `role-tag ${user.role}`;
                }

                const avatar = document.getElementById('user-avatar-initial');
                if (avatar) {
                    avatar.textContent = (user.name || user.email || 'U').charAt(0).toUpperCase();
                }
            }

            if (navTabs) navTabs.style.display = 'flex';

            // Apply role-based filtering to navigation tabs
            this.applyRoleNavGuards(user.role);
        } else {
            document.body.classList.add('login-mode');
            if (appHeader) appHeader.style.display = 'none';
            if (userMenu) userMenu.style.display = 'none';
            if (navTabs) navTabs.style.display = 'none';
            App.switchView('view-login');
        }
    },

    applyRoleNavGuards(role) {
        const tabDashboard = document.getElementById('tab-dashboard');
        const tabUpload = document.getElementById('tab-upload');
        const tabApprovals = document.getElementById('tab-approvals');
        const tabUnlock = document.getElementById('tab-unlock');
        const tabAudit = document.getElementById('tab-audit');
        const tabUsers = document.getElementById('tab-users');

        // Dashboard and Audit verification are available to all authenticated roles
        if (tabDashboard) tabDashboard.style.display = 'flex';
        if (tabAudit) tabAudit.style.display = 'flex';

        // Role-specific workflow actions (mirrors backend route permissions)
        const isSetter = role === 'setter';
        const isInvigilator = role === 'invigilator';
        const isAdmin = role === 'admin';
        // Admin manages accounts only — it never sees the paper approval board
        if (tabApprovals) tabApprovals.style.display = isAdmin ? 'none' : 'flex';
        if (tabUpload) tabUpload.style.display = isSetter ? 'flex' : 'none';
        if (tabUnlock) tabUnlock.style.display = isInvigilator ? 'flex' : 'none';
        if (tabUsers) tabUsers.style.display = isAdmin ? 'flex' : 'none';
    }
};

window.Auth = Auth;
