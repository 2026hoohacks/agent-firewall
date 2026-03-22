/* AgentGuard dashboard — SSE live feed + summary polling */

(function () {
    'use strict';

    const root = document.getElementById('dashboard-root');
    if (!root) return;

    // ── elements ──────────────────────────────────────────────────────────────
    const feedList   = document.getElementById('feed-list');
    const sseStatus  = document.getElementById('sse-status');

    // ── plain-English mapping ─────────────────────────────────────────────────
    // Handles both interceptor SSE events and demo-store dashboard events
    function toPlainEnglish(ev) {
        // Interceptor events have: action, status, path
        if (ev.action === 'read_file') {
            if (ev.status === 'allowed') {
                return 'AI read a file safely';
            }
            if (ev.status === 'blocked') {
                const p = (ev.path || '').toLowerCase();
                if (p.includes('id_rsa') || p.includes('id_dsa') || p.includes('id_ed25519') || p.includes('.pem') || p.includes('.key')) {
                    return 'AI tried to access your private key — blocked';
                }
                if (p.includes('.env') || p.includes('credentials') || p.includes('secret') || p.includes('token') || p.includes('password')) {
                    return 'AI tried to read sensitive credentials — blocked';
                }
                if (p.includes('.aws') || p.includes('.kube')) {
                    return 'AI tried to read cloud credentials — blocked';
                }
                return 'AI tried to read a sensitive file — blocked';
            }
        }

        // Dashboard demo-store events have: type, description
        const type = ev.type || '';
        if (type === 'sensitive_file_access')      return 'AI attempted to read sensitive credentials';
        if (type === 'unauthorized_tool_call')      return 'AI tried to run an unauthorized command';
        if (type === 'suspicious_external_request') return 'AI tried to contact an unknown external server';
        if (type === 'prompt_injection')            return 'Hidden instruction detected in content';
        if (type === 'large_outbound_transfer')     return 'AI tried to send a large amount of data externally';
        if (type === 'policy_violation')            return 'AI action violated security policy';

        // Fallback: use description or path
        return ev.description || ev.path || 'Agent activity recorded';
    }

    function severityDot(ev) {
        const status = ev.status || '';
        const sev    = ev.severity || '';
        if (status === 'blocked' || sev === 'critical' || sev === 'high') return 'dot-red';
        if (status === 'pending' || sev === 'medium')                      return 'dot-yellow';
        return 'dot-green';
    }

    function fmtTime(ev) {
        const ts = ev.timestamp;
        if (!ts) return '';
        // numeric unix timestamp
        if (typeof ts === 'number') return new Date(ts * 1000).toLocaleTimeString();
        // ISO string
        return new Date(ts).toLocaleTimeString();
    }

    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ── expandable feed items ─────────────────────────────────────────────────
    function collapseAll() {
        document.querySelectorAll('.feed-item-detail').forEach(d => d.classList.add('hidden'));
        document.querySelectorAll('.feed-item').forEach(i => i.classList.remove('feed-item-open'));
    }

    function makeFeedItem(ev) {
        const id      = ev.id || ev.timestamp || Math.random();
        const plain   = toPlainEnglish(ev);
        const dot     = severityDot(ev);
        const time    = fmtTime(ev);
        const status  = ev.status || '';
        const sev     = ev.severity || '';
        const type    = ev.type || ev.action || '';
        const explain = ev.explanation || ev.description || ev.detail || '';

        const statusCls = status === 'blocked' ? 'badge st-bad'
                        : status === 'allowed' ? 'badge st-ok'
                        : status === 'pending' ? 'badge st-pending'
                        : 'badge';
        const sevCls    = (sev === 'critical' || sev === 'high') ? 'badge sev-high'
                        : sev === 'medium' ? 'badge sev-med'
                        : sev ? 'badge sev-low' : '';

        // Reconstruct agent tool call JSON from event fields
        const toolJson = ev.action ? JSON.stringify(
            Object.fromEntries(
                [['tool', ev.action], ev.path ? ['path', ev.path] : null].filter(Boolean)
            ), null, 2
        ) : null;
        const toolJsonCls = status === 'blocked' ? 'feed-tool-json feed-tool-json-blocked'
                          : 'feed-tool-json feed-tool-json-allowed';

        const li = document.createElement('li');
        li.className = 'feed-item';
        li.dataset.feedId = String(id);
        li.innerHTML = `
            <div class="feed-item-row">
                <span class="feed-dot ${dot}"></span>
                <span class="feed-plain">${esc(plain)}</span>
                <span class="feed-time">${esc(time)}</span>
                <span class="feed-chevron">&#8250;</span>
            </div>
            <div class="feed-item-detail hidden">
                <dl class="feed-dl">
                    ${type   ? `<dt>Event type</dt><dd class="mono">${esc(type)}</dd>` : ''}
                    ${sev    ? `<dt>Severity</dt><dd><span class="${sevCls}">${esc(sev)}</span></dd>` : ''}
                    ${status ? `<dt>Status</dt><dd><span class="${statusCls}">${esc(status)}</span></dd>` : ''}
                    ${explain ? `<dt>Explanation</dt><dd>${esc(explain)}</dd>` : ''}
                    ${time   ? `<dt>Time</dt><dd class="mono">${esc(time)}</dd>` : ''}
                </dl>
                ${toolJson ? `<div class="feed-tool-call-label">Agent tool call</div><pre class="${toolJsonCls}">${esc(toolJson)}</pre>` : ''}
            </div>`;

        li.querySelector('.feed-item-row').addEventListener('click', () => {
            const detail = li.querySelector('.feed-item-detail');
            const isOpen = !detail.classList.contains('hidden');
            collapseAll();
            if (!isOpen) {
                detail.classList.remove('hidden');
                li.classList.add('feed-item-open');
            }
        });

        return li;
    }

    function prependFeedItem(ev) {
        if (!feedList) return;
        const empty = feedList.querySelector('.feed-empty');
        if (empty) empty.remove();

        const li = makeFeedItem(ev);
        feedList.insertBefore(li, feedList.firstChild);

        // Keep list from growing unboundedly
        const items = feedList.querySelectorAll('.feed-item');
        if (items.length > 50) items[items.length - 1].remove();
    }

    // ── seed with existing interceptor events (history) ───────────────────────
    async function loadHistory() {
        try {
            const res = await fetch('/api/events/history');
            if (!res.ok) return;
            const events = await res.json();
            if (!Array.isArray(events) || !events.length) return;
            // Add oldest first so newest ends up at top after prepending
            [...events].reverse().forEach(ev => prependFeedItem(ev));
        } catch (_) {}
    }

    // ── SSE connection ────────────────────────────────────────────────────────
    function connectSSE() {
        const es = new EventSource('/api/events/stream');

        es.onopen = () => {
            if (sseStatus) sseStatus.textContent = 'Live';
        };

        es.onmessage = (e) => {
            try {
                const ev = JSON.parse(e.data);
                prependFeedItem(ev);
            } catch (_) {}
        };

        es.onerror = () => {
            if (sseStatus) sseStatus.textContent = 'Reconnecting…';
            es.close();
            setTimeout(connectSSE, 3000);
        };
    }

    // ── summary polling (3 cards, no risk score) ──────────────────────────────
    async function pollSummary() {
        try {
            const res = await fetch('/api/events');
            if (!res.ok) return;
            const data = await res.json();
            const s = data.summary || {};
            const cardSession = document.getElementById('card-session');
            const cardTotal   = document.getElementById('card-total');
            const cardBlocked = document.getElementById('card-blocked');
            if (cardSession) cardSession.textContent = s.session_active ? 'Monitoring' : 'Idle';
            if (cardTotal)   cardTotal.textContent   = s.total_events ?? '—';
            if (cardBlocked) cardBlocked.textContent  = s.blocked_actions ?? '—';
        } catch (_) {}
    }

    // ── init ──────────────────────────────────────────────────────────────────
    loadHistory();
    connectSSE();
    pollSummary();
    setInterval(pollSummary, 5000);

})();
