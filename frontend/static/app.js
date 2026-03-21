/* AgentGuard dashboard — polls /api/events, decisions via /api/decision */

(function () {
    'use strict';

    const root = document.getElementById('dashboard-root');
    if (!root) return;

    const POLL_MS = 3000;
    let selectedId = null;
    let lastEvents = [];

    const feedEl = document.getElementById('event-feed');
    const queueEl = document.getElementById('review-queue');
    const pollStatus = document.getElementById('poll-status');
    const pendingCount = document.getElementById('pending-count');

    const detailEmpty = document.getElementById('detail-empty');
    const detailBody = document.getElementById('detail-body');
    const detailActions = document.getElementById('detail-actions');
    const btnApprove = document.getElementById('btn-approve');
    const btnBlock = document.getElementById('btn-block');

    const authConfigured = root.dataset.authConfigured === 'true';
    const loggedIn = root.dataset.loggedIn === 'true';

    function setSummary(s) {
        document.getElementById('card-session').textContent = s.session_active ? 'Monitoring' : 'Idle';
        document.getElementById('card-total').textContent = s.total_events;
        document.getElementById('card-flagged').textContent = s.flagged_events;
        document.getElementById('card-blocked').textContent = s.blocked_actions;
        document.getElementById('card-risk').textContent = s.risk_score;
    }

    function severityClass(sev) {
        if (sev === 'critical' || sev === 'high') return 'sev-high';
        if (sev === 'medium') return 'sev-med';
        return 'sev-low';
    }

    function statusClass(st) {
        if (st === 'pending') return 'st-pending';
        if (st === 'allowed') return 'st-ok';
        if (st === 'blocked') return 'st-bad';
        return '';
    }

    function liEvent(ev, compact) {
        const li = document.createElement('li');
        li.className = 'event-li' + (selectedId === ev.id ? ' is-selected' : '');
        li.dataset.id = String(ev.id);
        const timeShort = (ev.timestamp || '').replace('T', ' ').slice(0, 19);
        li.innerHTML = `
            <div class="event-li-main">
                <span class="mono event-type">${escapeHtml(ev.type)}</span>
                ${compact ? '' : `<span class="event-desc">${escapeHtml(ev.description)}</span>`}
            </div>
            <div class="event-li-meta">
                <span class="badge ${severityClass(ev.severity)}">${escapeHtml(ev.severity)}</span>
                <span class="badge ${statusClass(ev.status)}">${escapeHtml(ev.status)}</span>
                <span class="mono time">${escapeHtml(timeShort)}</span>
            </div>`;
        li.addEventListener('click', () => selectEvent(ev.id));
        return li;
    }

    function renderLists(events) {
        feedEl.innerHTML = '';
        queueEl.innerHTML = '';
        const pending = events.filter((e) => e.status === 'pending');
        pendingCount.textContent = `${pending.length} pending`;

        events.forEach((ev) => feedEl.appendChild(liEvent(ev, false)));
        pending.forEach((ev) => queueEl.appendChild(liEvent(ev, true)));

        if (!events.length) {
            feedEl.innerHTML = '<li class="event-empty">No events yet.</li>';
        }
        if (!pending.length) {
            queueEl.innerHTML = '<li class="event-empty">Queue clear.</li>';
        }
    }

    function findEvent(id) {
        return lastEvents.find((e) => e.id === id);
    }

    function selectEvent(id) {
        selectedId = id;
        document.querySelectorAll('.event-li').forEach((el) => {
            el.classList.toggle('is-selected', el.dataset.id === String(id));
        });
        const ev = findEvent(id);
        if (!ev) {
            detailBody.classList.add('hidden');
            detailEmpty.classList.remove('hidden');
            return;
        }
        detailEmpty.classList.add('hidden');
        detailBody.classList.remove('hidden');
        document.getElementById('d-id').textContent = String(ev.id);
        document.getElementById('d-type').textContent = ev.type || '';
        document.getElementById('d-severity').innerHTML = `<span class="badge ${severityClass(ev.severity)}">${escapeHtml(ev.severity)}</span>`;
        document.getElementById('d-status').innerHTML = `<span class="badge ${statusClass(ev.status)}">${escapeHtml(ev.status)}</span>`;
        document.getElementById('d-desc').textContent = ev.description || '';
        document.getElementById('d-explain').textContent = ev.explanation || '';
        document.getElementById('d-policy').textContent = ev.policy_reason || '';
        document.getElementById('d-rec').textContent = ev.recommended_action || '';

        const pending = ev.status === 'pending';
        detailActions.classList.toggle('hidden', !pending);
    }

    async function poll() {
        try {
            const res = await fetch('/api/events', { credentials: 'same-origin' });
            if (res.status === 401) {
                pollStatus.textContent = 'Session expired';
                window.location.href = '/';
                return;
            }
            if (!res.ok) throw new Error(String(res.status));
            const data = await res.json();
            lastEvents = data.events || [];
            setSummary(data.summary || {});
            renderLists(lastEvents);
            pollStatus.textContent = `Updated ${new Date().toLocaleTimeString()}`;
            if (selectedId != null && findEvent(selectedId)) {
                selectEvent(selectedId);
            } else if (selectedId != null) {
                selectedId = null;
                detailBody.classList.add('hidden');
                detailEmpty.classList.remove('hidden');
            }
        } catch (e) {
            pollStatus.textContent = 'Offline — retrying…';
            console.error(e);
        }
    }

    async function postDecision(decision) {
        if (selectedId == null) return;
        const res = await fetch('/api/decision', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ event_id: selectedId, decision }),
        });
        if (res.status === 401) {
            window.location.href = '/';
            return;
        }
        if (!res.ok) return;
        const data = await res.json();
        setSummary(data.summary || {});
        const evRes = await fetch('/api/events', { credentials: 'same-origin' });
        if (evRes.ok) {
            const evData = await evRes.json();
            lastEvents = evData.events || [];
            renderLists(lastEvents);
            selectEvent(selectedId);
        }
    }

    btnApprove.addEventListener('click', () => postDecision('approve'));
    btnBlock.addEventListener('click', () => postDecision('block'));

    function escapeHtml(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    if (authConfigured && !loggedIn) {
        window.location.href = '/';
        return;
    }

    poll();
    setInterval(poll, POLL_MS);
})();
