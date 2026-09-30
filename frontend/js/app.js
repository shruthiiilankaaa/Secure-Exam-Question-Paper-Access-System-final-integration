'use strict';

/**
 * Main Application Orchestrator
 * Connects frontend views to the backend API (/api/auth, /api/papers, /api/audit)
 * Minimal Futuristic Enterprise Interface (Linear / Notion / Stripe / Apple)
 */

const App = {
    currentView: 'view-login',
    activeFilter: 'ALL',
    cachedPapers: [],
    cachedAuditLogs: [],
    people: {},

    init() {
        Auth.init();
        this.setupNavigation();
        this.setupUploadHandlers();
        this.setupUnlockHandlers();
        this.setupApprovalHandlers();
        this.setupAuditHandlers();
        this.setupModals();
    },

    // Navigation & Views
    setupNavigation() {
        document.querySelectorAll('.nav-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetView = btn.dataset.view;
                if (targetView) {
                    this.switchView(targetView);
                }
            });
        });
    },

    switchView(viewId) {
        // Guard protected views
        if (viewId !== 'view-login' && !API.getToken()) {
            this.switchView('view-login');
            return;
        }

        // Role-based view guards
        const user = Auth.currentUser;
        if (user) {
            if (user.role === 'admin' && (viewId === 'view-upload' || viewId === 'view-unlock')) {
                this.switchView('view-dashboard');
                return;
            }
            if (user.role !== 'admin' && viewId === 'view-users') {
                this.switchView('view-dashboard');
                return;
            }
        }

        document.querySelectorAll('.page-view').forEach(view => {
            view.classList.remove('active-view');
        });

        const target = document.getElementById(viewId);
        if (target) {
            target.classList.add('active-view');
            this.currentView = viewId;
        }

        const appHeader = document.getElementById('app-header');
        if (viewId === 'view-login') {
            document.body.classList.add('login-mode');
            if (appHeader) appHeader.style.display = 'none';
        } else {
            document.body.classList.remove('login-mode');
            if (appHeader && API.getToken()) appHeader.style.display = 'flex';
        }

        document.querySelectorAll('.nav-tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === viewId);
        });

        // Trigger view-specific data refresh
        if (viewId === 'view-dashboard') this.loadDashboardData();
        if (viewId === 'view-approvals') this.loadApprovalsData();
        if (viewId === 'view-unlock') this.loadUnlockData();
        if (viewId === 'view-upload') this.loadApproverChoices();
        if (viewId === 'view-audit') this.loadAuditData();
        if (viewId === 'view-users') this.loadUsersData();
    },

    // Toast Notifications (Clean text without emojis)
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        const body = document.createElement('div');
        body.style.flex = '1';
        body.textContent = String(message ?? '');   // textContent: message is never parsed as HTML
        toast.appendChild(body);
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 150ms ease';
            setTimeout(() => toast.remove(), 200);
        }, 3500);
    },

    // -------------------------------------------------------------
    // PART 1 (Dashboard): Role-Specific Actions & Stat Metrics
    // -------------------------------------------------------------
    async loadDashboardData() {
        const user = Auth.currentUser;
        if (!user) return;

        const roleBanner = document.getElementById('dash-role-banner');
        if (roleBanner) {
            const dateStr = new Date().toLocaleDateString('en-US', {
                weekday: 'short',
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });

            let quickActionBtn = '';
            if (user.role === 'setter') {
                quickActionBtn = `<button class="btn btn-primary btn-sm" data-act="switchView" data-arg="view-upload">Upload New Paper</button>`;
            } else if (user.role === 'approver') {
                quickActionBtn = `<button class="btn btn-primary btn-sm" data-act="switchView" data-arg="view-approvals">Review Pending</button>`;
            } else if (user.role === 'invigilator') {
                quickActionBtn = `<button class="btn btn-emerald btn-sm" data-act="switchView" data-arg="view-unlock">Unlock Paper</button>`;
            } else if (user.role === 'admin') {
                quickActionBtn = `<button class="btn btn-primary btn-sm" data-act="switchView" data-arg="view-users">Manage Users</button>`;
            }

            roleBanner.innerHTML = `
                <div class="dash-hero-banner">
                    <div class="dash-hero-content">
                        <div class="dash-hero-topline">
                            <span class="dash-hero-chip">
                                <span class="pulse-indicator"></span>
                                <span>Cryptographic Core Active &bull; Examination Session 2026</span>
                            </span>
                            <span class="dash-hero-date">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                                <span>${dateStr}</span>
                            </span>
                        </div>
                        
                        <div class="dash-hero-main">
                            <div class="dash-hero-text">
                                <h1 class="dash-hero-title">Welcome back, ${this.esc(user.name)}</h1>
                                <p class="dash-hero-subtitle">
                                    Role: <span class="role-tag ${user.role}">${user.role.toUpperCase()}</span>
                                    <span>&bull;</span>
                                    <span>${this.esc(user.email || '')}</span>
                                    <span>&bull;</span>
                                    <span style="color:#16a34a; font-weight:600">● Session Secure</span>
                                </p>
                            </div>
                            
                            <div class="dash-hero-actions">
                                <button class="dash-refresh-btn" data-act="loadDashboardData" title="Reload examination metrics">
                                    <svg class="refresh-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <polyline points="23 4 23 10 17 10"></polyline>
                                        <polyline points="1 20 1 14 7 14"></polyline>
                                        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
                                    </svg>
                                    <span>Refresh Board</span>
                                </button>
                                ${quickActionBtn}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        try {
            const [papersRes, verifyRes] = await Promise.all([
                API.papers.list(),
                API.audit.verify()
            ]);

            const papers = (papersRes.papers || []).map(p => this.decoratePaper(p));
            this.cachedPapers = papers;

            const elTotal = document.getElementById('stat-total-papers');
            const elPending = document.getElementById('stat-pending');
            const elReady = document.getElementById('stat-ready');
            const auditBadge = document.getElementById('stat-audit-status');

            if (elTotal) elTotal.textContent = papers.length;
            if (elPending) elPending.textContent = papers.filter(p => p.uiStatus === 'PENDING').length;
            if (elReady) elReady.textContent = papers.filter(p => p.uiStatus === 'READY_FOR_EXAM').length;

            if (auditBadge) {
                if (verifyRes.valid) {
                    auditBadge.textContent = '100% INTACT';
                    auditBadge.style.color = '#16a34a';
                } else {
                    auditBadge.textContent = 'TAMPERED';
                    auditBadge.style.color = '#dc2626';
                }
            }

            this.renderRoleActionPanel(user.role);
        } catch (err) {
            console.error('Error loading dashboard:', err);
        }
    },

    renderRoleActionPanel(role) {
        const container = document.getElementById('role-action-panel');
        if (!container) return;

        const card = (title, text, btnClass, view, label) => `
            <div class="glass-card highlight">
                <h3 style="margin-bottom:0.75rem; color:var(--text-primary); font-size:var(--font-size-card-title); font-weight:600">${title}</h3>
                <p style="color:var(--text-secondary); font-size:var(--font-size-body); margin-bottom:1.5rem">${text}</p>
                <button class="btn ${btnClass}" data-act="switchView" data-arg="${view}">${label}</button>
            </div>`;

        let content = '';
        if (role === 'setter') {
            content = card('Question Paper Authoring Station',
                "Upload examination question papers to be encrypted with AES-256-GCM. The key is split with Shamir's Secret Sharing (k-of-n) and one share is issued to each designated approver.",
                'btn-primary', 'view-upload', 'Upload New Question Paper');
        } else if (role === 'approver') {
            const pendingCount = this.cachedPapers.filter(p =>
                p.uiStatus === 'PENDING' && !p.approvals.some(a => a.approverId === Auth.currentUser.id)).length;
            content = card('Approver Authorization Station',
                `You have <strong>${pendingCount}</strong> paper(s) awaiting your approval. Each approval counts toward the threshold needed for exam unlock.`,
                'btn-primary', 'view-approvals', 'Review Pending Question Papers');
        } else if (role === 'invigilator') {
            const readyCount = this.cachedPapers.filter(p => p.ready).length;
            content = card('Invigilator Examination Station',
                `Papers currently ready to decrypt: <strong>${readyCount}</strong>. A paper unlocks only when enough approvers have signed off and the exam window is open.`,
                'btn-emerald', 'view-unlock', 'Unlock Exam Paper');
        } else if (role === 'admin') {
            content = card('Administration',
                'Manage user accounts and assign examination roles.',
                'btn-primary', 'view-users', 'Manage Users');
        }
        container.innerHTML = content;
    },

    // -------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------
    esc(v) {
        return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    },

    fmtWindow(p) {
        const s = new Date(p.examStartTime), e = new Date(p.examEndTime);
        const opts = { hour: '2-digit', minute: '2-digit' };
        return `${s.toLocaleDateString()} ${s.toLocaleTimeString([], opts)} - ${e.toLocaleTimeString([], opts)}`;
    },

    // Backend statuses are locked / pending_approval / unlocked. The UI adds
    // time-lock awareness on top (same rules the backend enforces on unlock).
    decoratePaper(p) {
        const now = Date.now();
        const start = new Date(p.examStartTime).getTime();
        const end = new Date(p.examEndTime).getTime();
        const approvals = p.approvals || [];
        const enough = approvals.length >= p.k;
        const inWindow = now >= start && now <= end;

        let uiStatus = 'PENDING';
        if (p.status === 'unlocked') uiStatus = 'UNLOCKED';
        else if (enough) uiStatus = now < start ? 'TIME_LOCKED' : (inWindow ? 'READY_FOR_EXAM' : 'EXPIRED');

        return { ...p, approvals, uiStatus, ready: enough && inWindow };
    },

    getStatusBadgeClass(status) {
        switch (status) {
            case 'PENDING': return 'pending';
            case 'TIME_LOCKED': return 'time-locked';
            case 'READY_FOR_EXAM': return 'ready';
            case 'UNLOCKED': return 'approved';
            case 'EXPIRED': return 'rejected';
            default: return 'pending';
        }
    },

    async ensurePeople() {
        if (Object.keys(this.people).length) return;
        try {
            const res = await API.auth.approvers();
            (res.users || []).forEach(u => { this.people[u.id] = u; });
        } catch (e) { /* names are a nicety; ids still work */ }
    },

    personName(id) {
        const u = this.people[id];
        return u ? `${u.name} (${u.role})` : `User ${String(id).slice(-6)}`;
    },

    // -------------------------------------------------------------
    // Upload (setter)  ->  POST /api/papers
    // -------------------------------------------------------------
    async loadApproverChoices() {
        const box = document.getElementById('upload-approvers');
        if (!box) return;
        try {
            const res = await API.auth.approvers();
            const users = res.users || [];
            users.forEach(u => { this.people[u.id] = u; });
            if (!users.length) {
                box.innerHTML = '<span style="color:var(--text-muted); font-size:14px">No approver or invigilator accounts exist yet. Create some via "Create an account" on the sign-in page.</span>';
                return;
            }
            box.innerHTML = users.map(u => `
                <label style="display:flex; align-items:center; gap:0.6rem; font-size:14px; color:var(--text-primary); cursor:pointer">
                    <input type="checkbox" value="${this.esc(u.id)}">
                    <span><strong>${this.esc(u.name)}</strong> <span style="color:var(--text-secondary)">— ${this.esc(u.role)}, ${this.esc(u.email)}</span></span>
                </label>`).join('');
        } catch (err) {
            box.innerHTML = `<span style="color:#dc2626; font-size:14px">${this.esc(err.message)}</span>`;
        }
    },

    setupUploadHandlers() {
        const form = document.getElementById('upload-paper-form');
        const dropzone = document.getElementById('file-dropzone');
        const fileInput = document.getElementById('paper-file-input');
        const fileNameDisplay = document.getElementById('selected-file-name');

        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => fileInput.click());
            dropzone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            });
            dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
            dropzone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
                if (e.dataTransfer.files.length) {
                    fileInput.files = e.dataTransfer.files;
                    if (fileNameDisplay) {
                        fileNameDisplay.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
                    }
                }
            });
            fileInput.addEventListener('change', () => {
                if (fileInput.files.length && fileNameDisplay) {
                    fileNameDisplay.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
                }
            });
        }

        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const submitBtn = document.getElementById('upload-submit-btn');

                const title = document.getElementById('upload-title').value.trim();
                const date = document.getElementById('upload-date').value;
                const start = document.getElementById('upload-start-time').value;
                const end = document.getElementById('upload-end-time').value;
                const k = parseInt(document.getElementById('upload-k').value, 10);
                const approverIds = [...document.querySelectorAll('#upload-approvers input:checked')].map(i => i.value);

                if (!fileInput || !fileInput.files.length) return this.showToast('Please choose a file to upload.', 'warning');
                if (approverIds.length < 2) return this.showToast('Select at least 2 approvers.', 'warning');
                if (!(k >= 2 && k <= approverIds.length)) return this.showToast(`k must be between 2 and ${approverIds.length}.`, 'warning');

                const startAt = new Date(`${date}T${start}`);
                const endAt = new Date(`${date}T${end}`);
                if (!(endAt > startAt)) return this.showToast('Window end time must be after start time.', 'warning');

                const formData = new FormData();
                formData.append('title', title);
                formData.append('examStartTime', startAt.toISOString());
                formData.append('examEndTime', endAt.toISOString());
                formData.append('k', String(k));
                formData.append('approverIds', JSON.stringify(approverIds));
                formData.append('file', fileInput.files[0]);

                submitBtn.disabled = true;
                submitBtn.textContent = 'Encrypting with AES-256 & Splitting Key...';
                try {
                    const res = await API.papers.upload(formData);
                    this.showToast(`'${res.title}' encrypted & uploaded (${res.k}-of-${res.n}).`, 'success');
                    form.reset();
                    document.querySelectorAll('#upload-approvers input').forEach(i => { i.checked = false; });
                    if (fileNameDisplay) fileNameDisplay.textContent = '';
                    this.switchView('view-approvals');
                } catch (err) {
                    this.showToast(err.message || 'Upload failed', 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Encrypt & Upload Question Paper';
                }
            });
        }
    },

    // -------------------------------------------------------------
    // Unlock (invigilator)  ->  POST /api/papers/:id/unlock
    // -------------------------------------------------------------
    setupUnlockHandlers() {
        const form = document.getElementById('unlock-request-form');
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const paperId = document.getElementById('unlock-paper-select').value;
                if (!paperId) return this.showToast('Please select an exam paper', 'warning');
                await this.downloadDecryptedPaper(paperId);
            });
        }
    },

    async loadUnlockData() {
        try {
            const res = await API.papers.list();
            const papers = (res.papers || []).map(p => this.decoratePaper(p));
            this.cachedPapers = papers;

            const select = document.getElementById('unlock-paper-select');
            if (select) {
                select.innerHTML = '<option value="">-- Choose Exam Paper --</option>' +
                    papers.map(p => `<option value="${this.esc(p.id)}">${this.esc(p.title)} (${p.uiStatus.replace(/_/g, ' ')})</option>`).join('');
            }

            const tableBody = document.getElementById('unlock-requests-table-body');
            if (!tableBody) return;

            if (!papers.length) {
                tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:2rem">No papers found.</td></tr>`;
                return;
            }

            tableBody.innerHTML = papers.map(p => `
                <tr>
                    <td><strong>${this.esc(p.title)}</strong><br><small style="color:var(--text-secondary)">${this.esc(p.originalFilename)}</small></td>
                    <td style="font-size:0.8rem">${this.esc(this.fmtWindow(p))}</td>
                    <td>${p.approvals.length} / ${p.k}</td>
                    <td><span class="status-badge ${this.getStatusBadgeClass(p.uiStatus)}">${p.uiStatus.replace(/_/g, ' ')}</span></td>
                    <td>
                        ${(p.ready && Auth.currentUser?.role === 'invigilator') ? `
                            <button class="btn btn-emerald btn-sm" data-act="downloadDecryptedPaper" data-arg="${this.esc(p.id)}">Decrypt &amp; Download</button>
                        ` : (Auth.currentUser?.role === 'admin' ? `<span style="font-size:0.8rem; color:var(--text-muted)">Invigilator role required</span>` : (p.ready ? `<span style="font-size:0.8rem; color:var(--text-muted)">Invigilator role required</span>` : `<span style="font-size:0.8rem; color:var(--text-muted)">Locked until approvals &amp; window</span>`))}
                    </td>
                </tr>`).join('');
        } catch (err) {
            console.error('Error loading unlock data:', err);
        }
    },

    async downloadDecryptedPaper(paperId) {
        if (Auth.currentUser?.role === 'admin') {
            this.showToast('Admins cannot decrypt examination papers.', 'warning');
            return;
        }
        const paper = this.cachedPapers.find(p => p.id === paperId);
        this.showToast('Reconstructing AES-256 key from Shamir shares & decrypting...', 'info');
        try {
            const res = await API.papers.unlock(paperId);
            const url = window.URL.createObjectURL(res.blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = paper?.originalFilename || `paper_${paperId}`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            this.showToast('Paper decrypted and downloaded.', 'success');
            this.loadUnlockData();
        } catch (err) {
            this.showToast(err.message || 'Access denied', 'error');
        }
    },

    // -------------------------------------------------------------
    // Approval board  ->  GET /api/papers, POST /api/papers/:id/approve
    // -------------------------------------------------------------
    setupApprovalHandlers() {
        document.querySelectorAll('.filter-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.activeFilter = btn.dataset.filter;
                this.renderApprovalCards();
            });
        });
    },

    async loadApprovalsData() {
        try {
            await this.ensurePeople();
            const res = await API.papers.list();
            this.cachedPapers = (res.papers || []).map(p => this.decoratePaper(p));
            this.renderApprovalCards();
        } catch (err) {
            console.error('Error loading approvals:', err);
        }
    },

    renderApprovalCards() {
        const container = document.getElementById('approval-cards-grid');
        if (!container) return;

        let papers = [...this.cachedPapers];
        if (this.activeFilter !== 'ALL') {
            papers = papers.filter(p => p.uiStatus === this.activeFilter);
        }

        if (!papers.length) {
            container.innerHTML = `
                <div style="grid-column: 1 / -1; text-align:center; padding:3rem; color:var(--text-muted)">
                    No papers found matching filter '${this.esc(this.activeFilter)}'.
                </div>`;
            return;
        }

        const user = Auth.currentUser;

        container.innerHTML = papers.map(p => {
            const approvedCount = p.approvals.length;
            const percent = Math.min(100, Math.round((approvedCount / p.k) * 100));
            const isDesignated = (p.approverIds || []).includes(user?.id);
            const isUserApproved = p.approvals.some(a => a.approverId === user?.id);
            const canApprove = user?.role !== 'admin' && (user?.role === 'approver' || user?.role === 'invigilator') && isDesignated && !isUserApproved;
            const canDecrypt = user?.role !== 'admin' && user?.role === 'invigilator' && p.ready;

            return `
                <div class="paper-card">
                    <div class="paper-card-header">
                        <div class="paper-code">${this.esc(p.originalFilename)}</div>
                        <span class="status-badge ${this.getStatusBadgeClass(p.uiStatus)}">${p.uiStatus.replace(/_/g, ' ')}</span>
                    </div>

                    <div class="paper-body">
                        <div class="paper-title">${this.esc(p.title)}</div>
                        <div class="paper-meta">${p.n} approvers | ${p.k} required</div>
                        <div class="paper-date">Exam window: <strong style="color:var(--text-primary)">${this.esc(this.fmtWindow(p))}</strong></div>

                        <div class="threshold-progress">
                            <div style="display:flex; justify-content:space-between; font-size:13px">
                                <span style="color:var(--text-secondary)">Approval Progress:</span>
                                <strong style="color:var(--text-primary)">${approvedCount} / ${p.k} approvals (${p.n} shares issued)</strong>
                            </div>
                            <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: ${percent}%"></div></div>
                        </div>
                    </div>

                    <div class="paper-footer">
                        ${canApprove ? `<button class="btn btn-emerald btn-sm" data-act="openApproveModal" data-arg="${this.esc(p.id)}">Approve</button>` : ''}
                        ${canDecrypt ? `<button class="btn btn-primary btn-sm" data-act="downloadDecryptedPaper" data-arg="${this.esc(p.id)}">Decrypt &amp; Download</button>` : ''}
                        <button class="btn btn-secondary btn-sm" data-act="openPaperDetailsModal" data-arg="${this.esc(p.id)}">Details</button>
                    </div>
                </div>`;
        }).join('');
    },

    // -------------------------------------------------------------
    // Audit  ->  GET /api/audit, GET /api/audit/verify
    // -------------------------------------------------------------
    setupAuditHandlers() {
        const verifyBtn = document.getElementById('run-verify-btn');
        if (verifyBtn) verifyBtn.addEventListener('click', () => this.runAuditVerification());

        const actionFilter = document.getElementById('audit-action-filter');
        const searchInput = document.getElementById('audit-search-input');
        if (actionFilter) actionFilter.addEventListener('change', () => this.filterAuditLogs());
        if (searchInput) searchInput.addEventListener('input', () => this.filterAuditLogs());
    },

    async fetchAuditLogs() {
        const logs = await API.audit.history();
        // index = position in the chain; matches `brokenAtIndex` from /audit/verify
        this.cachedAuditLogs = (Array.isArray(logs) ? logs : []).map((l, i) => ({ ...l, index: Number.isInteger(l.index) ? l.index : i }));
    },

    async loadAuditData() {
        try {
            const [, verifyRes] = await Promise.all([this.fetchAuditLogs(), API.audit.verify()]);
            this.lastVerify = verifyRes;
            this.renderVerificationBanner(verifyRes);
            this.renderAuditTable(this.cachedAuditLogs, verifyRes);
        } catch (err) {
            console.error('Error loading audit data:', err);
        }
    },

    async runAuditVerification() {
        const btn = document.getElementById('run-verify-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Recalculating SHA-256 Hashes...';
        }
        try {
            const res = await API.audit.verify();
            this.lastVerify = res;
            await this.fetchAuditLogs();
            this.renderVerificationBanner(res);
            this.renderAuditTable(this.cachedAuditLogs, res);

            if (res.valid) {
                this.showToast('Audit chain verified: every entry hash and link matches.', 'success');
            } else {
                this.showToast(`TAMPERING DETECTED at block #${res.brokenAtIndex}!`, 'error');
            }
        } catch (err) {
            this.showToast(err.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Verify Hash Chain Now';
            }
        }
    },

    renderVerificationBanner(v) {
        const banner = document.getElementById('verification-banner');
        if (!banner) return;

        if (v.valid) {
            banner.className = 'verification-banner valid';
            banner.innerHTML = `
                <div>
                    <div class="banner-title">
                        <span class="alert-indicator success"></span>
                        Audit Chain Valid — Cryptographically Intact
                    </div>
                    <div class="banner-desc">
                        All <strong>${v.entriesChecked ?? 0}</strong> ledger entries verified: every stored hash matches its recomputed hash and every entry links to the one before it.
                    </div>
                </div>`;
        } else {
            const bad = this.cachedAuditLogs.find(l => l.index === v.brokenAtIndex);
            banner.className = 'verification-banner tampered';
            banner.innerHTML = `
                <div style="width:100%">
                    <div style="display:flex; align-items:center; gap:0.85rem">
                        <div>
                            <div class="banner-title" style="color:#b91c1c; font-size:16px; font-weight:600">
                                Tampering Detected — Chain Broken at Block #${v.brokenAtIndex}
                            </div>
                            <div class="banner-desc" style="color:#64748b; font-size:14px; margin-top:2px">${this.esc(v.reason)}</div>
                        </div>
                    </div>
                    <div class="corrupted-alert-panel">
                        <div class="corrupted-grid">
                            <div>
                                <span style="color:var(--text-secondary); font-size:12px">Block:</span><br>
                                <strong style="color:var(--text-primary); font-size:14px">#${v.brokenAtIndex} (${this.esc(bad?.action || 'unknown')})</strong>
                            </div>
                            <div>
                                <span style="color:var(--text-secondary); font-size:12px">Stored hash:</span><br>
                                <span class="hash-pill" style="color:#b91c1c; background:#ffffff; border-color:#fca5a5">${this.esc(bad?.hash || '')}</span>
                            </div>
                        </div>
                    </div>
                </div>`;
        }
    },

    actorInfo(l) {
        if (l.actor && typeof l.actor === 'object') {
            return { id: l.actor._id, name: l.actor.name, email: l.actor.email, role: l.actor.role };
        }
        return { id: l.actor, name: l.actor ? `User ${String(l.actor).slice(-6)}` : 'system', email: '', role: '' };
    },

    paperInfo(l) {
        if (l.paperId && typeof l.paperId === 'object') return { id: l.paperId._id, title: l.paperId.title };
        return { id: l.paperId, title: l.paperId ? `Paper ${String(l.paperId).slice(-6)}` : '—' };
    },

    renderAuditTable(logs, verifyRes) {
        const tableBody = document.getElementById('audit-table-body');
        if (!tableBody) return;

        const corruptedIdx = (!verifyRes || verifyRes.valid) ? -1 : verifyRes.brokenAtIndex;

        if (!logs.length) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:2.5rem; color:var(--text-muted)">No audit log records found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = logs.map(l => {
            const isCorrupted = (l.index === corruptedIdx);
            const actor = this.actorInfo(l);
            const paper = this.paperInfo(l);

            let actionClass = 'upload';
            if (l.action.includes('UNLOCK')) actionClass = 'unlock';
            if (l.action.includes('APPROV')) actionClass = 'approve';
            if (l.action.includes('DENIED')) actionClass = 'tamper';

            return `
                <tr class="${isCorrupted ? 'corrupted-row' : ''}">
                    <td><strong style="color:${isCorrupted ? '#b91c1c' : 'var(--text-primary)'}">#${l.index}</strong></td>
                    <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-secondary)">${this.esc(new Date(l.timestamp).toLocaleString())}</td>
                    <td>
                        <div style="font-weight:600; color:var(--text-primary)">${this.esc(actor.name)}</div>
                        <div style="font-size:0.72rem; color:var(--text-muted)">${this.esc(actor.email)}</div>
                    </td>
                    <td>${actor.role ? `<span class="role-tag ${this.esc(actor.role)}">${this.esc(actor.role)}</span>` : ''}</td>
                    <td><span class="action-tag ${actionClass}">${this.esc(l.action)}</span></td>
                    <td><div style="font-weight:500">${this.esc(paper.title)}</div></td>
                    <td>${isCorrupted
                        ? '<span class="status-badge rejected" style="font-size:0.7rem">Tampered</span>'
                        : '<span class="status-badge ready" style="font-size:0.7rem">Valid</span>'}</td>
                    <td><button class="btn btn-outline btn-sm" data-act="openProofModal" data-arg="${l.index}">Proof</button></td>
                </tr>`;
        }).join('');
    },

    filterAuditLogs() {
        const action = document.getElementById('audit-action-filter')?.value || 'ALL';
        const query = document.getElementById('audit-search-input')?.value.toLowerCase().trim() || '';

        let filtered = [...this.cachedAuditLogs];
        if (action !== 'ALL') filtered = filtered.filter(l => l.action === action);

        if (query) {
            filtered = filtered.filter(l => {
                const a = this.actorInfo(l), p = this.paperInfo(l);
                return [a.name, a.email, l.action, p.title, l.hash, JSON.stringify(l.details || {})]
                    .some(v => String(v || '').toLowerCase().includes(query));
            });
        }
        this.renderAuditTable(filtered, this.lastVerify || { valid: true });
    },

    openProofModal(logIndex) {
        logIndex = Number(logIndex);
        const log = this.cachedAuditLogs.find(l => l.index === logIndex);
        if (!log) return;
        const a = this.actorInfo(log), p = this.paperInfo(log);

        const body = document.getElementById('proof-modal-body');
        if (body) {
            body.innerHTML = `
                <div style="font-size:0.875rem; display:flex; flex-direction:column; gap:1rem">
                    <div style="background:#f8fafc; padding:1rem; border-radius:var(--radius-md); border:1px solid var(--border-subtle)">
                        <div style="color:var(--blue-primary); font-weight:700; margin-bottom:0.5rem">hash = SHA-256( JSON{ action, actor, paperId, details, timestamp, prevHash } )</div>
                        <div style="font-family:var(--font-mono); font-size:0.75rem; word-break:break-all; color:#374151; background:#ffffff; padding:0.5rem; border:1px solid #e2e8f0; border-radius:4px">
                            ${this.esc(JSON.stringify({ action: log.action, actor: a.id || null, paperId: p.id || null, details: log.details || {}, timestamp: log.timestamp, prevHash: log.prevHash }))}
                        </div>
                    </div>
                    <div>
                        <span style="color:var(--text-secondary)">Previous entry hash (link):</span><br>
                        <span class="hash-pill" style="word-break:break-all; display:block; margin-top:0.25rem">${this.esc(log.prevHash)}</span>
                    </div>
                    <div>
                        <span style="color:var(--text-secondary)">This entry's sealed hash:</span><br>
                        <span class="hash-pill" style="word-break:break-all; display:block; margin-top:0.25rem; color:#15803d; border-color:#86efac; background:#f0fdf4">${this.esc(log.hash)}</span>
                    </div>
                    <div style="background:#f8fafc; padding:0.75rem 1rem; border-radius:var(--radius-md); border:1px solid var(--border-subtle)">
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem"><span style="color:var(--text-secondary)">Action:</span><strong>${this.esc(log.action)}</strong></div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem"><span style="color:var(--text-secondary)">Actor:</span><strong>${this.esc(a.name)}${a.role ? ` (${this.esc(a.role)})` : ''}</strong></div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem"><span style="color:var(--text-secondary)">Paper:</span><strong>${this.esc(p.title)}</strong></div>
                        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem"><span style="color:var(--text-secondary)">Details:</span><strong style="font-family:var(--font-mono); font-size:0.75rem">${this.esc(JSON.stringify(log.details || {}))}</strong></div>
                        <div style="display:flex; justify-content:space-between"><span style="color:var(--text-secondary)">Timestamp:</span><strong style="font-family:var(--font-mono); font-size:0.78rem">${this.esc(log.timestamp)}</strong></div>
                    </div>
                </div>`;
        }
        document.getElementById('proof-modal').classList.add('active');
    },


    // -------------------------------------------------------------
    // Users (admin)  ->  GET /api/admin/users, PATCH /api/admin/users/:id/role
    // -------------------------------------------------------------
    async loadUsersData() {
        const tableBody = document.getElementById('users-table-body');
        if (!tableBody) return;

        // Loading state
        tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:2rem; color:var(--text-muted)">Loading users...</td></tr>`;

        try {
            const res = await API.admin.users();
            const users = res.users || [];
            users.forEach(u => { this.people[u.id] = u; });

            // Sort pending users first; then by createdAt descending
            users.sort((a, b) => {
                const aPending = (a.role || '').toLowerCase() === 'pending';
                const bPending = (b.role || '').toLowerCase() === 'pending';
                if (aPending && !bPending) return -1;
                if (!aPending && bPending) return 1;
                return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
            });

            if (!users.length) {
                tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:2rem; color:var(--text-muted)">No users found.</td></tr>`;
                return;
            }

            const currentAdminId = Auth.currentUser?.id || Auth.currentUser?._id;

            // Role dropdown may contain ONLY: Pending, Setter, Approver, Invigilator
            // Do NOT include Admin as an option
            const roleOptions = [
                { value: 'pending', label: 'Pending' },
                { value: 'setter', label: 'Setter' },
                { value: 'approver', label: 'Approver' },
                { value: 'invigilator', label: 'Invigilator' }
            ];

            tableBody.innerHTML = users.map(u => {
                const isSelf = currentAdminId && String(u.id) === String(currentAdminId);
                const isAdminRow = (u.role || '').toLowerCase() === 'admin';
                const formattedDate = u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—';

                // Escaped user-controlled fields
                const escapedName = this.esc(u.name);
                const escapedEmail = this.esc(u.email);
                const escapedRole = this.esc(u.role);
                const escapedDate = this.esc(formattedDate);
                const escapedId = this.esc(u.id);

                const optionsHtml = roleOptions.map(opt =>
                    `<option value="${this.esc(opt.value)}" ${(u.role || '').toLowerCase() === opt.value ? 'selected' : ''}>${this.esc(opt.label)}</option>`
                ).join('');

                return `
                    <tr>
                        <td><strong>${escapedName}</strong>${isSelf ? ' <span style="color:var(--text-muted); font-size:0.75rem">(you)</span>' : ''}</td>
                        <td style="color:var(--text-secondary)">${escapedEmail}</td>
                        <td><span class="role-tag ${escapedRole}">${escapedRole.toUpperCase()}</span></td>
                        <td style="font-size:0.85rem; color:var(--text-secondary)">${escapedDate}</td>
                        <td>
                            ${isAdminRow
                                ? `<span style="font-size:0.8rem; color:var(--text-muted)">Admin account</span>`
                                : (isSelf
                                    ? `<span style="font-size:0.8rem; color:var(--text-muted)">Cannot change own role</span>`
                                    : `<div style="display:flex; gap:0.5rem; align-items:center">
                                            <select class="form-select" style="width:auto; padding:0.35rem 0.65rem; font-size:0.85rem" id="role-select-${escapedId}">
                                                ${optionsHtml}
                                            </select>
                                            <button class="btn btn-secondary btn-sm" data-act="saveRole" data-arg="${escapedId}">Save</button>
                                       </div>`)}
                        </td>
                    </tr>`;
            }).join('');
        } catch (err) {
            tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:2rem; color:#dc2626">${this.esc(err.message || 'Failed to load users')}</td></tr>`;
            this.showToast(err.message || 'Failed to load users', 'error');
        }
    },

    async saveRole(userId) {
        const select = document.getElementById(`role-select-${userId}`);
        if (!select) return;
        const role = select.value;

        // Validate the selected role is only: setter, approver, invigilator
        const allowedRoles = ['setter', 'approver', 'invigilator'];
        if (!allowedRoles.includes(role)) {
            this.showToast('Please select a valid examination role (Setter, Approver, or Invigilator).', 'warning');
            return;
        }

        try {
            await API.admin.setRole(userId, role);
            this.showToast(`Role updated to ${role}.`, 'success');
            await this.loadUsersData();
        } catch (err) {
            this.showToast(err.message || 'Could not update role', 'error');
        }
    },

    // -------------------------------------------------------------
    // Modals
    // -------------------------------------------------------------
    setupModals() {
        document.querySelectorAll('.close-modal-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
            });
        });

        const approveForm = document.getElementById('approve-sign-form');
        if (approveForm) {
            approveForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                if (Auth.currentUser?.role === 'admin') {
                    this.showToast('Admins cannot approve examination papers.', 'warning');
                    return;
                }
                const paperId = document.getElementById('approve-paper-id').value;
                try {
                    const r = await API.papers.approve(paperId);
                    this.showToast(`Approval recorded (${r.approvalCount}/${r.threshold}).`, 'success');
                    document.getElementById('approve-modal').classList.remove('active');
                    this.loadApprovalsData();
                } catch (err) {
                    this.showToast(err.message, 'error');
                }
            });
        }
    },

    openApproveModal(paperId) {
        if (Auth.currentUser?.role === 'admin') {
            this.showToast('Admins cannot approve examination papers.', 'warning');
            return;
        }
        const paper = this.cachedPapers.find(p => p.id === paperId);
        document.getElementById('approve-paper-id').value = paperId;
        document.getElementById('approve-modal-code').textContent = paper?.title || paperId;
        document.getElementById('approve-modal').classList.add('active');
    },

    openPaperDetailsModal(paperId) {
        const p = this.cachedPapers.find(x => x.id === paperId);
        if (!p) return;

        const approvedIds = new Set(p.approvals.map(a => a.approverId));
        const rows = (p.approverIds || []).map(id => {
            const done = p.approvals.find(a => a.approverId === id);
            return `
                <div style="display:flex; justify-content:space-between; align-items:center; background:#f8fafc; border:1px solid var(--border-subtle); padding:0.6rem 0.85rem; border-radius:6px; margin-bottom:0.35rem">
                    <div>
                        <div style="font-weight:600; color:var(--text-primary)">${this.esc(this.personName(id))}</div>
                        <div style="font-size:0.72rem; color:var(--text-muted)">${done ? 'Approved ' + this.esc(new Date(done.approvedAt).toLocaleString()) : 'Awaiting approval'}</div>
                    </div>
                    <span class="status-badge ${approvedIds.has(id) ? 'ready' : 'pending'}">${approvedIds.has(id) ? 'APPROVED' : 'PENDING'}</span>
                </div>`;
        }).join('');

        const body = document.getElementById('details-modal-body');
        if (body) {
            body.innerHTML = `
                <div style="display:flex; flex-direction:column; gap:1rem; font-size:0.875rem">
                    <div>
                        <div style="font-size:1.25rem; font-weight:700; color:var(--text-primary)">${this.esc(p.title)}</div>
                        <div style="color:var(--text-secondary); margin-top:0.25rem">${this.esc(p.originalFilename)}</div>
                    </div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.75rem; background:#f8fafc; border:1px solid var(--border-subtle); padding:1rem; border-radius:var(--radius-md)">
                        <div><span style="color:var(--text-secondary); font-size:13px">Status:</span><br><strong class="status-badge ${this.getStatusBadgeClass(p.uiStatus)}" style="margin-top:0.25rem">${p.uiStatus.replace(/_/g, ' ')}</strong></div>
                        <div><span style="color:var(--text-secondary); font-size:13px">Threshold (k of n):</span><br><strong style="color:var(--text-primary)">${p.k} of ${p.n} approvers</strong></div>
                        <div style="grid-column:1 / -1"><span style="color:var(--text-secondary); font-size:13px">Exam window:</span><br><strong style="color:var(--text-primary)">${this.esc(this.fmtWindow(p))}</strong></div>
                    </div>
                    <div>
                        <div style="font-weight:600; color:var(--text-primary); margin-bottom:0.5rem">Designated Approvers (one Shamir share each):</div>
                        ${rows || '<div style="color:var(--text-muted)">No approvers recorded.</div>'}
                    </div>
                </div>`;
        }
        document.getElementById('details-modal').classList.add('active');
    }
};

window.App = App;

// Delegated click handling for [data-act] buttons (replaces inline onclick=, which the
// Content-Security-Policy blocks). Only methods that exist on App can be invoked.
document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-act]');
    if (!el) return;
    const fn = App[el.dataset.act];
    if (typeof fn !== 'function') return;
    if (el.tagName === 'A') e.preventDefault();
    fn.call(App, ...(el.dataset.arg !== undefined ? [el.dataset.arg] : []));
});

// Bootstrap on DOM loaded
document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
