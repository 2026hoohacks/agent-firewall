/* Legacy interceptor feed (served at /static/index.html) — SSE /api/events/stream */

(function () {
    'use strict';

    const API = '/api';
    const feedEl = document.getElementById('feed');
    if (!feedEl) return;

    const overlay = document.getElementById('block-overlay');
    const emptyState = document.getElementById('empty-state');
    const blockPath = document.getElementById('block-path');
    const blockExplanation = document.getElementById('block-explanation');
    const btnBlock = document.getElementById('btn-block');
    const btnAllow = document.getElementById('btn-allow');
    const seenEvents = new Set();

    function connectSSE() {
        const evtSource = new EventSource(`${API}/events/stream`);

        evtSource.onmessage = function (e) {
            if (e.data === 'keepalive') return;
            try {
                const event = JSON.parse(e.data);
                if (seenEvents.has(event.id)) return;
                seenEvents.add(event.id);
                renderEvent(event);
                if (event.status === 'blocked') {
                    showBlockCard(event);
                }
            } catch (err) {
                console.error('Error parsing SSE event:', err);
            }
        };

        evtSource.onerror = function (err) {
            console.error('SSE Error:', err);
            evtSource.close();
            setTimeout(connectSSE, 3000);
        };
    }

    function renderEvent(event) {
        if (emptyState) emptyState.remove();

        const time = new Date(event.timestamp * 1000).toLocaleTimeString();
        const isAllowed = event.status === 'allowed';
        const statusClass = isAllowed ? 'allowed' : 'blocked';
        const badgeLabel = isAllowed ? 'ALLOWED' : 'BLOCKED';
        const badgeClass = isAllowed ? 'badge-allowed' : 'badge-blocked';
        const detailText = isAllowed ? 'Read successful' : event.explanation;

        const item = document.createElement('div');
        item.className = `feed-item ${statusClass}`;
        const actionHtml = `read_file(<span style="color:var(--accent)">'${escHTML(event.path)}'</span>)`;

        item.innerHTML = `
            <div class="feed-item-left">
                <div class="feed-action">${actionHtml}</div>
                <div class="feed-detail">${escHTML(detailText)}</div>
            </div>
            <div class="feed-item-right">
                <span class="badge ${badgeClass}">${badgeLabel}</span>
                <span class="feed-time">${time}</span>
            </div>`;

        feedEl.insertBefore(item, feedEl.firstChild);
    }

    function showBlockCard(event) {
        blockPath.textContent = event.path;
        blockExplanation.textContent = event.explanation;
        overlay.classList.remove('hidden');
    }

    function hideBlockCard() {
        overlay.classList.add('hidden');
    }

    btnBlock.addEventListener('click', hideBlockCard);
    btnAllow.addEventListener('click', hideBlockCard);

    function escHTML(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    document.getElementById('btn-clear').addEventListener('click', async () => {
        try {
            await fetch(`${API}/events/clear`, { method: 'POST' });
            feedEl.innerHTML = '<div class="empty-state" id="empty-state">Waiting for agent to act...</div>';
            seenEvents.clear();
        } catch (e) {
            console.error('Failed to clear events:', e);
        }
    });

    connectSSE();
})();
