/* Session report page — loads /api/report, JSON download */

(function () {
    'use strict';

    const root = document.getElementById('report-root');
    if (!root) return;

    async function load() {
        const res = await fetch('/api/report');
        if (!res.ok) return;
        const data = await res.json();
        const s = data.summary || {};
        document.getElementById('r-allowed').textContent = s.allowed_actions ?? '—';
        document.getElementById('r-blocked').textContent = s.blocked_actions ?? '—';
        document.getElementById('r-pending').textContent = s.pending_review ?? '—';
        document.getElementById('r-generated').textContent = (data.generated_at || '').replace('T', ' ').slice(0, 19) || '—';

        const tbody = document.querySelector('#report-table tbody');
        tbody.innerHTML = '';
        (data.events || []).forEach((ev) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="mono">${ev.id}</td>
                <td class="mono">${escapeHtml((ev.timestamp || '').slice(0, 19))}</td>
                <td class="mono">${escapeHtml(ev.type)}</td>
                <td>${escapeHtml(ev.severity)}</td>
                <td>${escapeHtml(ev.status)}</td>
                <td>${escapeHtml(ev.description)}</td>`;
            tbody.appendChild(tr);
        });

        window.__reportPayload = data;
    }

    document.getElementById('btn-download-json').addEventListener('click', () => {
        const payload = window.__reportPayload;
        if (!payload) return;
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `agentguard-report-${(payload.generated_at || 'session').slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    });

    function escapeHtml(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    load();
})();
