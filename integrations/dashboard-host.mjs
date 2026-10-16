/** Embed AgentShield without placing credentials in URLs, DOM attributes or storage. */
export function mountAgentShield({ container, url, token, theme = 'dark', onStatus = () => {}, timeoutMs = 10000 }) {
    const endpoint = new URL(url);
    if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]', 'localhost'].includes(endpoint.hostname)
        || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) {
        throw new Error('AgentShield requires an exact local HTTP origin');
    }
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('Invalid integration credential');
    if (!['light', 'dark'].includes(theme)) throw new Error('Invalid theme');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Invalid connection timeout');
    const protocol = 'agentshield.dashboard.v1';
    const iframe = document.createElement('iframe');
    iframe.title = 'AgentShield service protection';
    iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    iframe.referrerPolicy = 'no-referrer';
    iframe.src = `${endpoint.origin}/embed`;
    iframe.style.width = '100%';
    iframe.style.height = '100%';
    iframe.style.border = '0';
    let nonce, disposed = false, settled = false;
    let resolveReady, rejectReady;
    const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
    const post = (type, fields = {}) => iframe.contentWindow?.postMessage({ protocol, type, nonce, ...fields }, endpoint.origin);
    const notify = (state) => { try { onStatus(state); } catch { /* Host callbacks cannot break cleanup. */ } };
    const cleanup = () => {
        if (disposed) return;
        post('disconnect');
        disposed = true;
        token = '';
        clearTimeout(timer);
        window.removeEventListener('message', receive);
        iframe.remove();
    };
    const fail = (code) => {
        cleanup();
        if (!settled) { settled = true; rejectReady(new Error(code)); }
        notify({ state: 'disconnected', code });
    };
    function receive(event) {
        const data = event.data;
        if (disposed || event.origin !== endpoint.origin || event.source !== iframe.contentWindow
            || !data || data.protocol !== protocol) return;
        if (data.type === 'ready' && !nonce && typeof data.nonce === 'string' && data.nonce.length <= 100) {
            nonce = data.nonce;
            post('connect', { token, theme });
            token = '';
        } else if (data.nonce === nonce && data.type === 'connected' && !settled) {
            if (!Array.isArray(data.capabilities) || !data.capabilities.includes('observe')) return fail('invalid_manifest');
            settled = true;
            clearTimeout(timer);
            const result = { capabilities: data.capabilities, protection: data.protection };
            resolveReady(result);
            notify({ state: 'connected', ...result });
        } else if (data.nonce === nonce && data.type === 'error') {
            fail('connection_failed');
        }
    }
    const timer = setTimeout(() => fail('connection_timeout'), timeoutMs);
    window.addEventListener('message', receive);
    container.append(iframe);
    notify({ state: 'connecting' });
    return {
        ready,
        setTheme(next) {
            if (!['light', 'dark'].includes(next)) throw new Error('Invalid theme');
            theme = next;
            if (!disposed && nonce) post('theme', { theme });
        },
        dispose() { fail('disposed'); },
    };
}
