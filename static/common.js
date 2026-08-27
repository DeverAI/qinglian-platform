// common.js — 前端公共工具：API、认证、模块开关、mini Markdown、设备指纹

const API_BASE = '/api';
const API_TIMEOUT_MS = 15000;
let refreshPromise = null;

// 主题在脚本解析时立即生效，尽量减少页面完成渲染后的明暗闪烁。
const THEME_STORAGE_KEY = 'ui_theme';
const THEME_ORDER = ['system', 'light', 'dark'];

function getThemePreference() {
  const value = localStorage.getItem(THEME_STORAGE_KEY);
  return THEME_ORDER.includes(value) ? value : 'system';
}

function applyTheme(preference = getThemePreference()) {
  const root = document.documentElement;
  if (preference === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', preference);
  root.style.colorScheme = preference === 'system' ? 'light dark' : preference;
  return preference;
}

function themeLabel(preference) {
  return preference === 'dark' ? '暗黑' : (preference === 'light' ? '浅色' : '跟随系统');
}

function updateThemeControl(button, preference = getThemePreference()) {
  if (!button) return;
  const dark = preference === 'dark' || (
    preference === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  button.dataset.theme = preference;
  button.setAttribute('aria-label', `当前为${themeLabel(preference)}主题，点击切换`);
  button.setAttribute('title', `主题：${themeLabel(preference)}`);
  button.setAttribute('aria-pressed', dark ? 'true' : 'false');
  button.innerHTML = dark
    ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.6 15.7A9 9 0 0 1 8.3 3.4 9 9 0 1 0 20.6 15.7Z"/></svg><span>暗黑</span>'
    : '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"/></svg><span>' + (preference === 'system' ? '自动' : '浅色') + '</span>';
}

function ensureThemeControl() {
  if (document.getElementById('themeToggle')) return;
  const nav = document.querySelector('nav');
  if (!nav) return;
  const button = document.createElement('button');
  button.id = 'themeToggle';
  button.type = 'button';
  button.className = 'theme-toggle';
  const userArea = document.getElementById('nav-user');
  const target = userArea && userArea.parentElement === nav ? userArea : null;
  if (target) nav.insertBefore(button, target);
  else {
    const links = document.getElementById('navLinks') || nav;
    const nestedUser = links.querySelector('#nav-user');
    if (nestedUser) links.insertBefore(button, nestedUser); else links.appendChild(button);
  }
  updateThemeControl(button);
  button.addEventListener('click', () => {
    const current = getThemePreference();
    const next = THEME_ORDER[(THEME_ORDER.indexOf(current) + 1) % THEME_ORDER.length];
    localStorage.setItem(THEME_STORAGE_KEY, next);
    applyTheme(next);
    updateThemeControl(button, next);
  });
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  media.addEventListener?.('change', () => {
    if (getThemePreference() === 'system') updateThemeControl(button, 'system');
  });
}

function normalizeNavigation() {
  const nav = document.querySelector('nav');
  if (!nav) return;
  let links = nav.querySelector(':scope > .nav-links');
  let toggle = nav.querySelector(':scope > .nav-toggle');
  if (!links) {
    links = document.createElement('div');
    links.className = 'nav-links';
    links.id = 'navLinks';
    const brand = nav.querySelector(':scope > .nav-brand') || nav.querySelector(':scope > a');
    [...nav.children].filter(child => child !== brand).forEach(child => links.appendChild(child));
    toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'nav-toggle';
    toggle.id = 'navToggle';
    toggle.setAttribute('aria-label', '打开主菜单');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    nav.append(toggle, links);
  }
  if (toggle && !toggle.dataset.navigationReady) {
    toggle.dataset.navigationReady = '1';
    toggle.setAttribute('aria-controls', links.id || 'navLinks');
    toggle.addEventListener('click', () => {
      const opening = !links.classList.contains('open');
      links.classList.toggle('open', opening);
      toggle.setAttribute('aria-expanded', String(opening));
      toggle.setAttribute('aria-label', opening ? '关闭主菜单' : '打开主菜单');
    });
    links.addEventListener('click', event => {
      if (!event.target.closest('a') || !links.classList.contains('open')) return;
      links.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
      toggle.setAttribute('aria-label', '打开主菜单');
    });
  }
}

applyTheme();

function getToken() { return localStorage.getItem('access_token') || ''; }
function setToken(token) { localStorage.setItem('access_token', token); }
function getRefreshToken() { return localStorage.getItem('refresh_token') || ''; }
function setRefreshToken(token) { localStorage.setItem('refresh_token', token); }
function getCsrf() { return localStorage.getItem('csrf_token') || ''; }
function setCsrf(token) { localStorage.setItem('csrf_token', token); }
// SID 会话密钥：每次登录/注册/刷新签发，用于鼠标握手校验（反爬虫/反盗号第二道防线）
function getSid() { return localStorage.getItem('sid') || ''; }
function setSid(sid) { if (sid) localStorage.setItem('sid', sid); else localStorage.removeItem('sid'); }
function getUser() { try { return JSON.parse(localStorage.getItem('user') || 'null'); } catch { return null; } }
function setUser(user) { localStorage.setItem('user', JSON.stringify(user)); }
function clearAuth() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('csrf_token');
  localStorage.removeItem('sid');
  localStorage.removeItem('user');
  clearTwoFaToken();
}

// ---- 风控 2FA 令牌管理（5 分钟复用窗口，与后端 is_2fa_verified 对齐） ----
const TWO_FA_MAX_AGE_MS = 5 * 60 * 1000;
function getTwoFaToken() {
  const token = sessionStorage.getItem('two_fa_token');
  const ts = parseInt(sessionStorage.getItem('two_fa_ts') || '0', 10);
  if (!token || !ts) return null;
  if (Date.now() - ts > TWO_FA_MAX_AGE) { clearTwoFaToken(); return null; }
  return token;
}
function setTwoFaToken(token) {
  sessionStorage.setItem('two_fa_token', token);
  sessionStorage.setItem('two_fa_ts', String(Date.now()));
}
function clearTwoFaToken() {
  sessionStorage.removeItem('two_fa_token');
  sessionStorage.removeItem('two_fa_ts');
}

function authHeaders(mutating = false) {
  const h = { 'Authorization': 'Bearer ' + getToken() };
  if (mutating) h['X-CSRF-Token'] = getCsrf();
  const sid = getSid();
  if (sid) h['X-SID'] = sid;
  const tfa = getTwoFaToken();
  if (tfa) h['X-2FA-Token'] = tfa;
  return h;
}

async function api(path, options = {}) {
  const url = API_BASE + path;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);
  const requestOptions = { ...options, signal: options.signal || controller.signal };
  delete requestOptions._retry;
  delete requestOptions._retry2fa;
  let res;
  let data;
  try {
    res = await fetch(url, requestOptions);
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return { code: res.status || 500, message: '服务器响应格式异常', data: null };
    }
    data = await res.json();
  } catch (error) {
    const timedOut = error && error.name === 'AbortError';
    return { code: timedOut ? 4080 : 5000, message: timedOut ? '请求超时，请稍后重试' : '网络连接失败，请检查网络', data: null };
  } finally {
    clearTimeout(timeout);
  }
  if (data.code === 4010 && getRefreshToken() && !options._retry) {
    const refreshed = await refreshToken();
    if (refreshed) {
      options._retry = true;
      options.headers = { ...options.headers, 'Authorization': 'Bearer ' + getToken() };
      if (options.headers['X-CSRF-Token']) options.headers['X-CSRF-Token'] = getCsrf();
      const sid = getSid();
      if (sid) options.headers['X-SID'] = sid;
      return api(path, options);
    }
  }
  // 鼠标握手失败：显示验证遮罩（请移动鼠标）
  if (data.code === 4033 && typeof handshakeManager !== 'undefined') {
    handshakeManager.showOverlay();
  }
  // 会话密钥被轮换：触发安全提醒并强制登出
  if (data.code === 4034 && typeof handshakeManager !== 'undefined') {
    handshakeManager.handleRotation(data.message);
  }
  // 风控 2FA：高危操作或异常 IP 触发二次验证，验证通过后自动重试原请求
  if (data.code === 4035 && data.data && data.data.challenge_token && !options._retry2fa && !path.startsWith('/risk/2fa/') && typeof twoFaManager !== 'undefined') {
    const verified = await twoFaManager.challenge(data.data, path);
    if (verified) {
      options._retry2fa = true;
      options.headers = { ...options.headers, ...authHeaders(options.headers && 'X-CSRF-Token' in options.headers) };
      return api(path, options);
    }
  }
  // IP 已被风控封禁（禁止访问后台管理台）
  if (data.code === 4036 && typeof twoFaManager !== 'undefined') {
    twoFaManager.showBanMessage(data.message);
  }
  // 异常 IP 操作已拦截（未配置 2FA 邮件）
  if (data.code === 4037 && typeof twoFaManager !== 'undefined') {
    twoFaManager.showSuspiciousBlock(data.message, data.data);
  }
  return data;
}

async function refreshToken() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    try {
      const r = await fetch(API_BASE + '/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: getRefreshToken() }),
      });
      const data = await r.json();
      if (data.code === 0) {
        setToken(data.data.access_token);
        setRefreshToken(data.data.refresh_token);
        setCsrf(data.data.csrf_token);
        if (data.data.sid) setSid(data.data.sid);
        setUser(data.data.user);
        return true;
      }
    } catch (_) {
      // 统一按续期失败退出，避免页面保留半失效会话。
    }
    clearAuth();
    return false;
  })();
  try { return await refreshPromise; } finally { refreshPromise = null; }
}

async function getJson(path) { return api(path, { headers: authHeaders() }); }
async function postJson(path, body, mutating = true) {
  return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders(mutating) }, body: JSON.stringify(body) });
}
async function postForm(path, formData, mutating = true) {
  return api(path, { method: 'POST', headers: authHeaders(mutating), body: formData });
}
async function putJson(path, body, mutating = true) {
  return api(path, { method: 'PUT', headers: { 'Content-Type': 'application/json', ...authHeaders(mutating) }, body: JSON.stringify(body) });
}
async function deleteJson(path, mutating = true) {
  return api(path, { method: 'DELETE', headers: authHeaders(mutating) });
}

function renderPagination(containerId, page, limit, total, callback) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const totalPages = Math.ceil(total / limit) || 1;
  if (totalPages <= 1) { container.innerHTML = ''; return; }
  const pages = new Set([1, totalPages]);
  for (let i = Math.max(1, page - 2); i <= Math.min(totalPages, page + 2); i++) pages.add(i);
  let last = 0;
  let html = '';
  [...pages].sort((a, b) => a - b).forEach(i => {
    if (last && i - last > 1) html += '<span class="pagination-gap" aria-hidden="true">…</span>';
    html += `<button class="${i === page ? 'active' : ''}" data-page="${i}" aria-label="第 ${i} 页" ${i === page ? 'aria-current="page"' : ''}>${i}</button>`;
    last = i;
  });
  container.innerHTML = html;
  container.querySelectorAll('button').forEach(b => {
    b.addEventListener('click', () => callback(parseInt(b.dataset.page)));
  });
}

async function requireAuth() {
  if (!getToken()) { location.href = '/login.html'; return false; }
  const data = await getJson('/auth/me');
  if (data.code !== 0) { clearAuth(); location.href = '/login.html'; return false; }
  setUser(data.data);
  return true;
}

function updateNav() {
  const user = getUser();
  const el = document.getElementById('nav-user');
  if (!el) return;
  if (user) {
    let html = `<span>${escapeHtml(user.nickname)}</span>`;
    if (user.role !== 'user') html += ` <span class="badge">${user.role}</span>`;
    html += ` <a href="/profile.html">主页</a> <a href="#" id="logout">退出</a>`;
    if (['admin','sysadmin'].includes(user.role)) html += ` <a href="/admin.html">管理后台</a>`;
    el.innerHTML = html;
    document.getElementById('logout').addEventListener('click', async (e) => {
      e.preventDefault();
      await postJson('/auth/logout', {});
      clearAuth();
      location.href = '/';
    });
  } else {
    el.innerHTML = `<a href="/login.html">登录</a> <a href="/register.html">注册</a>`;
  }
}

async function applyModuleSwitches() {
  const data = await getJson('/config/modules');
  if (data.code !== 0) return;
  const m = data.data;
  document.querySelectorAll('[data-module]').forEach(el => {
    const mod = el.dataset.module;
    if (!m[mod]) el.style.display = 'none';
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function safeExternalUrl(value) {
  try {
    const url = new URL(String(value || ''), location.origin);
    return (url.protocol === 'http:' || url.protocol === 'https:') ? url.href : '#';
  } catch (_) { return '#'; }
}

function showToast(message, type = 'info') {
  let region = document.getElementById('toast-region');
  if (!region) {
    region = document.createElement('div');
    region.id = 'toast-region';
    region.className = 'toast-region';
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', 'polite');
    document.body.appendChild(region);
  }
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = String(message || '操作完成');
  region.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 200);
  }, 3200);
}

function renderMarkdown(text) {
  if (!text) return '';
  let html = escapeHtml(text);
  // 代码块
  html = html.replace(/```([\s\S]*?)```/g, (_, code) => `<pre><code>${code}</code></pre>`);
  // 行内代码
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  // 链接（仅 http/https）
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  // 粗体/斜体
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  // 标题
  html = html.replace(/^### (.*)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.*)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.*)$/gm, '<h1>$1</h1>');
  // 引用
  html = html.replace(/^&gt; (.*)$/gm, '<blockquote>$1</blockquote>');
  // 列表
  html = html.replace(/^- (.*)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
  // 换行
  html = html.replace(/\n/g, '<br>');
  return html;
}

function deviceFingerprint() {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillText('fp', 2, 2);
  const canvasFp = canvas.toDataURL().slice(-16);
  const parts = [canvasFp, screen.width, screen.height, screen.colorDepth, Intl.DateTimeFormat().resolvedOptions().timeZone];
  let hash = 0;
  const str = parts.join('|');
  for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash |= 0; }
  return String(hash);
}

function formatTime(t) { return t ? t.replace('T', ' ').slice(0, 16) : ''; }

function qs(name) { return new URLSearchParams(location.search).get(name); }

// ===================== 模态框（替代 alert / confirm / prompt） =====================

function showModal(title, bodyHTML, actions) {
  // actions: [{ text, type, onClick }]  type: 'primary'|'secondary'|'danger'
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', title || '对话框');
    const box = document.createElement('div');
    box.className = 'modal-box';
    let html = '';
    if (title) html += `<h3>${escapeHtml(title)}</h3>`;
    html += `<div class="modal-body">${bodyHTML || ''}</div>`;
    html += '<div class="modal-actions">';
    const acts = actions && actions.length ? actions : [{ text: '确定', type: 'primary' }];
    acts.forEach((a, i) => {
      const cls = a.type === 'danger' ? 'danger' : (a.type === 'secondary' ? 'secondary' : '');
      html += `<button class="modal-btn ${cls}" data-idx="${i}">${escapeHtml(a.text)}</button>`;
    });
    html += '</div>';
    box.innerHTML = html;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('show'));
    function close(result) {
      overlay.classList.remove('show');
      setTimeout(() => overlay.remove(), 200);
      resolve(result);
    }
    box.querySelectorAll('.modal-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.idx);
        const act = acts[idx];
        if (act.onClick) {
          const r = act.onClick(close);
          if (r !== undefined) close(r);
        } else {
          close(idx);
        }
      });
    });
    overlay.addEventListener('click', e => {
      if (e.target === overlay && (!actions || !actions.some(a => a.blockClose))) close(-1);
    });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') {
        document.removeEventListener('keydown', esc);
        close(-1);
      }
    });
  });
}

function confirmDialog(message, title) {
  return showModal(title || '确认操作', `<p>${escapeHtml(message)}</p>`, [
    { text: '取消', type: 'secondary' },
    { text: '确定', type: 'primary' },
  ]).then(idx => idx === 1);
}

function promptDialog(message, defaultValue, title) {
  const inputId = 'modal-prompt-input';
  return showModal(title || '输入', `<p>${escapeHtml(message)}</p><input id="${inputId}" class="modal-input" value="${escapeHtml(defaultValue || '')}" autocomplete="off">`, [
    { text: '取消', type: 'secondary' },
    { text: '确定', type: 'primary', onClick: close => {
      const input = document.getElementById(inputId);
      close(input ? input.value : '');
    }},
  ]);
}

function alertDialog(message, title) {
  return showModal(title || '提示', `<p>${escapeHtml(message)}</p>`, [
    { text: '知道了', type: 'primary' },
  ]);
}

// ===================== 鼠标握手机制（HandshakeManager） =====================

class HandshakeManager {
  constructor() {
    this.heartbeatInterval = 15000;  // 15 秒发送一次心跳
    this.overlayId = 'handshake-overlay';
    this._lastMove = 0;
    this._timer = null;
    this._overlayEl = null;
    this._throttleMs = 2000;  // 鼠标移动事件节流间隔
    this._active = false;
  }

  init() {
    if (this._active) return;
    this._active = true;
    // 监听鼠标 / 触摸 / 指针移动
    const handler = this._onMove.bind(this);
    document.addEventListener('mousemove', handler, { passive: true });
    document.addEventListener('touchmove', handler, { passive: true });
    document.addEventListener('pointermove', handler, { passive: true });
    // 立即发送一次心跳
    this._sendHeartbeat();
    // 定时心跳
    this._timer = setInterval(() => this._sendHeartbeat(), this.heartbeatInterval);
    // 标签页切回前台 / 窗口获焦时立即补发心跳，避免后台节流导致 sid 超时
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') this._sendHeartbeat();
    });
    window.addEventListener('focus', () => this._sendHeartbeat());
  }

  _onMove(e) {
    const now = Date.now();
    if (now - this._lastMove < this._throttleMs) return;
    this._lastMove = now;
    this._sendHeartbeat();
  }

  async _sendHeartbeat() {
    if (!getToken()) return;
    try {
      const r = await postJson('/auth/handshake', {}, false);
      if (r.code === 4010) return; // 由 api() 自动处理续期
      if (r.code === 4034) {
        this.handleRotation(r.message);
        return;
      }
      if (r.code === 0) {
        this.hideOverlay();
      }
    } catch (_) { /* 网络错误静默 */ }
  }

  // 会话密钥被轮换：弹出安全提醒并强制登出
  handleRotation(message) {
    if (this._rotationHandled) return;
    this._rotationHandled = true;
    // 隐藏鼠标遮罩（如有）
    this.hideOverlay();
    // 停止心跳
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
    this._active = false;
    // 清除认证状态
    clearAuth();
    // 弹出安全提醒模态框（阻止关闭，强制跳转登录页）
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', '安全提醒');
    const box = document.createElement('div');
    box.className = 'modal-box modal-security';
    box.innerHTML = `
      <div class="security-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M12 8v4"/>
          <path d="M12 16h.01"/>
        </svg>
      </div>
      <h3>安全提醒：会话密钥已轮换</h3>
      <div class="modal-body">
        <p>${escapeHtml(message || '检测到异常会话活动，会话密钥已自动轮换。')}</p>
        <p class="muted">这可能是由于：</p>
        <ul>
          <li>您的账号被盗用，他人正在使用爬虫程序访问；</li>
          <li>您的会话令牌泄露，被用于自动化请求。</li>
        </ul>
        <p class="muted">为保护账号安全，系统已强制注销当前会话。请重新登录；如非本人操作，请立即修改密码并检查账号安全设置。</p>
      </div>
      <div class="modal-actions">
        <button class="modal-btn" id="security-redirect">前往登录</button>
      </div>`;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add('show'));
    document.getElementById('security-redirect').addEventListener('click', () => {
      overlay.classList.remove('show');
      setTimeout(() => { overlay.remove(); location.href = '/login.html'; }, 200);
    });
  }

  showOverlay() {
    let el = document.getElementById(this.overlayId);
    if (!el) {
      el = document.createElement('div');
      el.id = this.overlayId;
      el.className = 'handshake-overlay';
      el.innerHTML = `
        <svg class="handshake-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 11V6a2 2 0 0 0-4 0v5"/>
          <path d="M14 10V4a2 2 0 0 0-4 0v6"/>
          <path d="M10 10.5V6a2 2 0 0 0-4 0v8"/>
          <path d="M18 8a2 2 0 1 1 4 0v6a8 8 0 0 1-8 8h-2c-2.8 0-4.5-.86-5.99-2.34l-3.6-3.6a2 2 0 0 1 2.83-2.82L7 15"/>
        </svg>
        <h2>请移动鼠标验证身份</h2>
        <p>检测到您一段时间未活动，为防止自动化爬虫，请移动鼠标以验证您是真人。验证后将自动恢复操作权限。</p>
      `;
      document.body.appendChild(el);
    }
    el.classList.add('show');
  }

  hideOverlay() {
    const el = document.getElementById(this.overlayId);
    if (el) el.classList.remove('show');
  }

  // 检查握手状态（用于发言前预检）
  async checkStatus() {
    if (!getToken()) return true;
    try {
      const r = await getJson('/auth/handshake/status');
      if (r.code === 0 && r.data && !r.data.active) {
        this.showOverlay();
        return false;
      }
      return true;
    } catch (_) { return true; }
  }

  // 拦截 API 返回的握手错误（4033=请移动鼠标 / 4034=会话密钥已轮换）
  handleApiError(code, message) {
    if (code === 4033) {
      this.showOverlay();
      return true;
    }
    if (code === 4034) {
      this.handleRotation(message);
      return true;
    }
    return false;
  }
}

const handshakeManager = new HandshakeManager();

// ===================== 风控 2FA 管理（高危操作/异常 IP 触发） =====================

class TwoFaManager {
  constructor() {
    this._modal = null;
    this._pending = null;
  }

  /** 弹出 2FA 验证模态框，返回 Promise<boolean>（true=已验证可重试） */
  challenge(challengeData, originalPath) {
    return new Promise((resolve) => {
      this._pending = { ...challengeData, originalPath, resolve };
      this._showModal();
    });
  }

  _showModal() {
    this._closeModal();
    const d = this._pending;
    if (!d) return;
    const isLocal = d.sent_via === 'local' || d.sent_via === 'local_email_failed';
    const codeHtml = isLocal
      ? `<div class="two-fa-code-display" title="服务器本地访问，验证码已自动生成">${escapeHtml(d.code || '')}</div>
         <p class="muted">（服务器本地访问，验证码已自动生成，直接点击验证即可）</p>`
      : `<p class="muted">验证码已发送至管理员邮箱，请查收后输入。</p>`;
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('role', 'alertdialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', '风控二次验证');
    overlay.innerHTML = `
      <div class="modal-box modal-security">
        <div class="security-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <h3>风控二次验证</h3>
        <div class="modal-body">
          <p>${escapeHtml(d.reason || '检测到高危操作或异常 IP，需要二次验证。')}</p>
          ${codeHtml}
        </div>
        <div class="modal-input">
          <input id="two-fa-code-input" type="text" inputmode="numeric" maxlength="10"
                 placeholder="请输入 6 位验证码" value="${isLocal ? escapeHtml(d.code || '') : ''}" autocomplete="one-time-code">
        </div>
        <p id="two-fa-error" class="two-fa-error" role="alert"></p>
        <div class="modal-actions">
          <button class="modal-btn secondary" id="two-fa-cancel">取消</button>
          <button class="modal-btn" id="two-fa-submit">验证</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    this._modal = overlay;
    requestAnimationFrame(() => overlay.classList.add('show'));
    const codeInput = overlay.querySelector('#two-fa-code-input');
    const errorEl = overlay.querySelector('#two-fa-error');
    const submitBtn = overlay.querySelector('#two-fa-submit');
    const cancelBtn = overlay.querySelector('#two-fa-cancel');
    codeInput.focus();
    codeInput.select();
    codeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') submitBtn.click(); });
    submitBtn.addEventListener('click', async () => {
      const code = codeInput.value.trim();
      if (!code) { errorEl.textContent = '请输入验证码'; return; }
      submitBtn.disabled = true;
      submitBtn.textContent = '验证中...';
      try {
        const r = await postJson('/risk/2fa/verify', { challenge_token: d.challenge_token, code });
        if (r.code === 0 && r.data && r.data.verified) {
          setTwoFaToken(d.challenge_token);
          showToast('验证通过，正在重试操作...', 'success');
          this._closeModal();
          d.resolve(true);
        } else if (r.data && r.data.banned) {
          errorEl.textContent = r.data.message || '验证失败次数过多，IP 已被封禁';
          submitBtn.textContent = '已封禁';
          submitBtn.disabled = true;
          cancelBtn.textContent = '关闭';
          setTimeout(() => { this._closeModal(); d.resolve(false); }, 4000);
        } else {
          errorEl.textContent = (r.data && r.data.message) || r.message || '验证失败';
          submitBtn.disabled = false;
          submitBtn.textContent = '验证';
          codeInput.focus();
          codeInput.select();
        }
      } catch (e) {
        errorEl.textContent = '网络错误，请重试';
        submitBtn.disabled = false;
        submitBtn.textContent = '验证';
      }
    });
    cancelBtn.addEventListener('click', () => { this._closeModal(); d.resolve(false); });
  }

  _closeModal() {
    if (this._modal) {
      const m = this._modal;
      m.classList.remove('show');
      setTimeout(() => m.remove(), 200);
      this._modal = null;
    }
    this._pending = null;
  }

  showBanMessage(message) {
    showToast(message || '该 IP 已被风控封禁，禁止访问后台管理台', 'error');
  }

  showSuspiciousBlock(message, data) {
    showToast(message || '异常 IP 操作已拦截', 'error');
  }
}

const twoFaManager = new TwoFaManager();

// ===================== 首页：每日简报与系统通知 =====================

const NOTIFY_ICON_SVG = {
  system: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>',
  daily_briefing: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 17h3l2-4V7H5v6h3l-2 4zm8 0h3l2-4V7h-6v6h3l-2 4z"/></svg>',
  task: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-7 0c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm-2 14l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>',
  post: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>',
  email: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>',
  board: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>',
  root: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>',
  point: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4-6.2-4.6L5.8 21.3 8.2 13.9 2 9.4h7.6z"/></svg>',
};

const NOTIFY_TYPE_LABEL = {
  system: '系统',
  daily_briefing: '简报',
  task: '任务',
  post: '帖子',
  email: '邮件',
  board: '板块',
  root: '公告',
  point: '积分',
};

async function loadBriefing() {
  const textEl = document.getElementById('briefingText');
  const srcEl = document.getElementById('briefingSource');
  const kindEl = document.getElementById('briefingKind');
  if (!textEl) return;
  try {
    const r = await getJson('/notify/briefing');
    if (r.code !== 0 || !r.data) {
      textEl.textContent = '暂无简报内容。';
      return;
    }
    const d = r.data;
    textEl.textContent = d.summary || '';
    textEl.classList.remove('anim-fade');
    void textEl.offsetWidth;  // 触发重绘以重启动画
    textEl.classList.add('anim-fade');
    if (srcEl) {
      let html = '';
      if (d.source) html += '—— ' + escapeHtml(d.source);
      if (d.source_url) {
        html += ` <a href="${escapeHtml(safeExternalUrl(d.source_url))}" target="_blank" rel="noopener noreferrer">查看原文</a>`;
      }
      srcEl.innerHTML = html;
    }
    if (kindEl) {
      const kind = d.kind || 'fallback';
      kindEl.textContent = kind === 'policy' ? '新政策' : (kind === 'history' ? '历史上的今天' : '社区导览');
      kindEl.className = 'quote-kind ' + kind;
    }
  } catch (e) {
    textEl.textContent = '简报加载失败，请稍后刷新。';
  }
}

async function loadNotifyMessages() {
  const listEl = document.getElementById('notifyList');
  const badgeEl = document.getElementById('notifyBadge');
  const cardEl = document.getElementById('notifyCard');
  if (!listEl) return;
  try {
    const r = await getJson('/notify/messages?limit=20');
    if (r.code !== 0 || !r.data) return;
    const items = r.data.items || [];
    const unread = r.data.unread || 0;
    if (badgeEl) {
      badgeEl.textContent = String(unread);
      badgeEl.style.display = unread > 0 ? 'inline-block' : 'none';
    }
    if (!items.length) {
      listEl.innerHTML = '<div class="notify-empty">暂无通知</div>';
      return;
    }
    listEl.innerHTML = items.map(m => {
      const type = m.type || 'system';
      const iconSvg = NOTIFY_ICON_SVG[type] || NOTIFY_ICON_SVG.system;
      const typeLabel = NOTIFY_TYPE_LABEL[type] || '系统';
      const cls = m.is_read ? 'notify-item' : 'notify-item unread';
      return `<li class="${cls}">
        <span class="notify-icon ${type}" title="${escapeHtml(typeLabel)}">${iconSvg}</span>
        <div class="notify-body">
          <div class="notify-title">${escapeHtml(m.title)}</div>
          ${m.content ? `<div class="notify-content">${escapeHtml(m.content)}</div>` : ''}
          <div class="notify-time">${formatTime(m.created_at)}</div>
        </div>
        <button class="notify-del" data-id="${m.id}" title="删除" aria-label="删除通知">&times;</button>
      </li>`;
    }).join('');
    listEl.querySelectorAll('.notify-del').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const r = await deleteJson('/notify/messages/' + id);
        if (r.code === 0) loadNotifyMessages();
      });
    });
  } catch (e) {
    listEl.innerHTML = '<div class="notify-empty">通知加载失败</div>';
  }
}

async function markAllNotifyRead() {
  const r = await postJson('/notify/messages/read', {});
  if (r.code === 0) loadNotifyMessages();
}

async function clearAllNotify() {
  if (!await confirmDialog('确认清空全部通知？')) return;
  const r = await deleteJson('/notify/messages');
  if (r.code === 0) loadNotifyMessages();
}

// ============ 首页消息流 ============
async function loadFeed(tab) {
  const listEl = document.getElementById('feedList');
  if (!listEl) return;
  listEl.setAttribute('aria-busy', 'true');
  listEl.innerHTML = '<li class="feed-empty"><span class="spin"></span> 加载中</li>';
  try {
    const r = await getJson('/feed?tab=' + encodeURIComponent(tab || 'all') + '&limit=20');
    if (r.code !== 0 || !r.data) {
      listEl.innerHTML = '<li class="feed-empty">加载失败</li>';
      listEl.setAttribute('aria-busy', 'false'); return;
    }
    const items = r.data.items || [];
    if (!items.length) {
      listEl.innerHTML = '<li class="feed-empty">暂无动态</li>';
      listEl.setAttribute('aria-busy', 'false'); return;
    }
    listEl.innerHTML = items.map(function(it) {
      var src = it.source;
      var icon = '', label = '', link = '';
      if (src === 'task') {
        icon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="var(--primary)"><path d="M19 3h-4.18C14.4 1.84 13.3 1 12 1c-1.3 0-2.4.84-2.82 2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>';
        label = '任务';
        link = '/tasks.html?id=' + it.id;
      } else if (src === 'post') {
        icon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="var(--primary)"><path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>';
        label = '帖子';
        link = '/post.html?id=' + it.id;
      } else if (src === 'news') {
        icon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="var(--primary)"><path d="M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 0h6v6h-6v-6z"/></svg>';
        label = '新闻';
        link = safeExternalUrl(it.source_url);
      }
      var title = escapeHtml(it.title || '');
      var sub = '';
      if (src === 'news') {
        sub = '<div class="feed-abstract">' + escapeHtml(it.abstract || '') + '</div>' +
              '<div class="feed-meta"><span>' + escapeHtml(it.source_name || '') + '</span>' +
              '<a href="' + escapeHtml(safeExternalUrl(it.source_url)) + '" target="_blank" rel="noopener noreferrer">阅读原文</a></div>';
      } else {
        sub = '<div class="feed-meta"><span class="feed-tag">' + label + '</span>' +
              '<span>' + formatTime(it.created_at || it.updated_at || it.collected_at) + '</span></div>';
      }
      var titleHtml = src === 'news'
        ? '<div class="feed-title">' + title + '</div>'
        : '<a class="feed-title" href="' + link + '">' + title + '</a>';
      return '<li class="feed-item feed-' + src + '">' + icon + '<div class="feed-body">' + titleHtml + sub + '</div></li>';
    }).join('');
  } catch (e) {
    listEl.innerHTML = '<li class="feed-empty">动态加载失败</li>';
  } finally {
    listEl.setAttribute('aria-busy', 'false');
  }
}

function switchFeedTab(tab, btnEl) {
  // 切换 Tab 样式
  var tabs = document.querySelectorAll('.feed-tab');
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.remove('active');
    tabs[i].setAttribute('aria-selected', 'false');
  }
  if (btnEl) { btnEl.classList.add('active'); btnEl.setAttribute('aria-selected', 'true'); }
  loadFeed(tab);
}

// ============ 新闻栏 ============
async function loadNews() {
  const listEl = document.getElementById('newsList');
  if (!listEl) return;
  try {
    const r = await getJson('/news?limit=10');
    if (r.code !== 0 || !r.data) return;
    const items = r.data.items || [];
    if (!items.length) {
      listEl.innerHTML = '<div class="muted" style="padding:.8rem 0">今日暂无新闻更新</div>';
      return;
    }
    listEl.innerHTML = items.map(function(n) {
      return '<div class="news-item">' +
        '<a class="news-title" href="' + escapeHtml(safeExternalUrl(n.source_url)) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(n.title) + '</a>' +
        '<div class="news-abstract">' + escapeHtml(n.abstract || '') + '</div>' +
        '<div class="news-meta"><span>' + escapeHtml(n.source_name || '') + '</span>' +
        '<span>' + formatTime(n.published_at || n.collected_at) + '</span></div>' +
        '</div>';
    }).join('');
  } catch (e) {
    listEl.innerHTML = '<div class="muted">新闻加载失败</div>';
  }
}

// ============ 条文背诵游戏 ============
async function loadQuizQuestion() {
  const qEl = document.getElementById('quizQuestion');
  const fbEl = document.getElementById('quizFeedback');
  if (!qEl) return;
  if (fbEl) fbEl.innerHTML = '';
  qEl.innerHTML = '<div class="quiz-loading"><span class="spin"></span> 加载题目...</div>';
  try {
    const r = await getJson('/quiz/question');
    if (r.code !== 0) {
      qEl.innerHTML = '<div class="quiz-empty">' + escapeHtml(r.message || '暂无题目') + '</div>';
      return;
    }
    const q = r.data;
    window._currentQ = q;
    var optsHtml = q.options.map(function(opt, i) {
      return '<button class="quiz-option" onclick="submitQuizAnswer(' + i + ')" data-idx="' + i + '">' +
        '<span class="opt-letter">' + String.fromCharCode(65 + i) + '</span>' +
        '<span class="opt-text">' + escapeHtml(opt) + '</span></button>';
    }).join('');
    qEl.innerHTML = '<div class="quiz-blank">' + escapeHtml(q.blank_text) + '</div>' +
      '<div class="quiz-options">' + optsHtml + '</div>';
    // 更新状态
    loadQuizToday();
  } catch (e) {
    qEl.innerHTML = '<div class="quiz-empty">题目加载失败</div>';
  }
}

async function submitQuizAnswer(idx) {
  var q = window._currentQ;
  if (!q) return;
  var opts = document.querySelectorAll('.quiz-option');
  for (var i = 0; i < opts.length; i++) opts[i].disabled = true;
  try {
    const r = await postJson('/quiz/answer', { question_id: q.question_id, option_index: idx });
    const fbEl = document.getElementById('quizFeedback');
    if (r.code !== 0) {
      if (fbEl) fbEl.innerHTML = '<div class="quiz-feedback fail">' + escapeHtml(r.message) + '</div>';
      return;
    }
    var d = r.data;
    // 标记正误
    if (opts[idx]) opts[idx].classList.add(d.is_correct ? 'correct' : 'wrong');
    if (!d.is_correct && opts[d.answer_index]) opts[d.answer_index].classList.add('correct');
    var msg = d.is_correct
      ? '回答正确' + (d.points_delta > 0 ? '（+' + d.points_delta + ' 积分）' : (d.message || ''))
      : '回答错误，正确答案是 ' + String.fromCharCode(65 + d.answer_index);
    if (fbEl) fbEl.innerHTML = '<div class="quiz-feedback ' + (d.is_correct ? 'ok' : 'fail') + '">' + msg + '</div>';
    loadQuizToday();
  } catch (e) {
    const fbEl = document.getElementById('quizFeedback');
    if (fbEl) fbEl.innerHTML = '<div class="quiz-feedback fail">提交失败</div>';
  }
}

async function loadQuizToday() {
  const el = document.getElementById('quizToday');
  if (!el) return;
  try {
    const r = await getJson('/quiz/today');
    if (r.code !== 0) return;
    var d = r.data;
    el.innerHTML = '今日已答 ' + d.today_answered + '/' + d.daily_limit +
      ' 题，答对 ' + d.today_correct + ' 题（+' + d.today_correct + ' 积分），剩余 ' + d.remaining + ' 题';
  } catch (e) {}
}

// 页面加载时更新导航与模块开关
document.addEventListener('DOMContentLoaded', () => {
  normalizeNavigation();
  ensureThemeControl();
  updateNav();
  applyModuleSwitches();
  // 已登录用户启动鼠标握手机制
  if (getToken()) handshakeManager.init();
  const currentPath = location.pathname === '/index.html' ? '/' : location.pathname;
  document.querySelectorAll('nav a[href]').forEach(link => {
    const linkPath = new URL(link.href, location.origin).pathname;
    if (linkPath === currentPath) link.setAttribute('aria-current', 'page');
  });
  document.querySelectorAll('a[target="_blank"]').forEach(link => link.setAttribute('rel', 'noopener noreferrer'));
  document.querySelectorAll('table').forEach(table => {
    if (!table.parentElement.classList.contains('table-scroll')) {
      const wrapper = document.createElement('div');
      wrapper.className = 'table-scroll';
      wrapper.setAttribute('role', 'region');
      wrapper.setAttribute('aria-label', '可横向滚动的数据表');
      wrapper.tabIndex = 0;
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  });
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', () => {
      const button = form.querySelector('button[type="submit"], input[type="submit"]');
      if (!button || button.disabled) return;
      button.dataset.originalText = button.value || button.textContent;
      button.disabled = true;
      if (button.tagName === 'INPUT') button.value = '处理中…'; else button.textContent = '处理中…';
      setTimeout(() => {
        if (!button.isConnected) return;
        button.disabled = false;
        if (button.tagName === 'INPUT') button.value = button.dataset.originalText; else button.textContent = button.dataset.originalText;
      }, 1800);
    });
  });
});
