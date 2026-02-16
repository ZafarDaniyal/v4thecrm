const state = {
  user: null,
  month: currentMonth(),
  agents: [],
};

const loginView = document.getElementById('loginView');
const appView = document.getElementById('appView');
const loginError = document.getElementById('loginError');
const welcomeText = document.getElementById('welcomeText');
const modeText = document.getElementById('modeText');
const monthFilter = document.getElementById('monthFilter');
const saleMessage = document.getElementById('saleMessage');
const salesTableBody = document.getElementById('salesTableBody');
const leaderboardCards = document.getElementById('leaderboardCards');
const competitionModeText = document.getElementById('competitionModeText');
const ownerTabBtn = document.getElementById('ownerTabBtn');
const metricCards = document.getElementById('metricCards');
const ownerTableBody = document.getElementById('ownerTableBody');
const uploadMessage = document.getElementById('uploadMessage');
const settingsMessage = document.getElementById('settingsMessage');
const salespersonSelect = document.getElementById('salespersonSelect');
const agentSelectWrap = document.getElementById('agentSelectWrap');
const agentNameFields = document.getElementById('agentNameFields');

const fmtMoney = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 2,
});

function currentMonth() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function clearMessages() {
  loginError.textContent = '';
  saleMessage.textContent = '';
  uploadMessage.textContent = '';
  settingsMessage.textContent = '';
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  const isJson = options.body && !(options.body instanceof FormData);
  const response = await fetch(path, {
    method: options.method || 'GET',
    credentials: 'include',
    headers: isJson ? { 'Content-Type': 'application/json', ...headers } : headers,
    body: options.body,
  });

  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json')
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const errorMsg = typeof payload === 'string' ? payload : payload.error || 'Request failed';
    throw new Error(errorMsg);
  }

  return payload;
}

function setActiveTab(tabName) {
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });

  document.querySelectorAll('.tab-content').forEach((section) => {
    section.classList.toggle('hidden', section.id !== `tab-${tabName}`);
  });
}

function renderSales(rows) {
  salesTableBody.innerHTML = '';
  if (!rows.length) {
    salesTableBody.innerHTML = '<tr><td colspan="10" class="muted">No sales for this month.</td></tr>';
    return;
  }

  rows.forEach((row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${row.date_sold || ''}</td>
      <td>${row.salesperson || ''}</td>
      <td>${row.customer_name || ''}</td>
      <td>${row.phone || ''}</td>
      <td>${row.address || ''}</td>
      <td>${row.policy_type || ''}</td>
      <td>${row.carrier || ''}</td>
      <td>${fmtMoney.format(row.premium_amount || 0)}</td>
      <td>${fmtMoney.format(row.agent_commission_amount || 0)}</td>
      <td>${fmtMoney.format(row.agency_commission_amount || 0)}</td>
    `;
    salesTableBody.appendChild(tr);
  });
}

function renderLeaderboard(payload) {
  leaderboardCards.innerHTML = '';
  const rows = payload.leaderboard || [];

  competitionModeText.textContent = payload.competition_mode
    ? 'Competition mode is ON: salespeople can compare totals.'
    : 'Competition mode is OFF: each salesperson sees only their own totals.';

  if (!rows.length) {
    leaderboardCards.innerHTML = '<div class="card">No leaderboard data for this month.</div>';
    return;
  }

  rows.forEach((row, index) => {
    const card = document.createElement('article');
    card.className = 'card';
    card.innerHTML = `
      <div class="label">#${index + 1} ${row.display_name}</div>
      <div class="value">${fmtMoney.format(row.premium_total)}</div>
      <div class="muted">Deals: ${row.deals}</div>
      <div class="muted">Agent Comm: ${fmtMoney.format(row.agent_commission_total)}</div>
      <div class="muted">Agency Comm: ${fmtMoney.format(row.agency_commission_total)}</div>
    `;
    leaderboardCards.appendChild(card);
  });
}

function renderOwnerMetrics(payload) {
  const summary = payload.summary;
  metricCards.innerHTML = '';

  const items = [
    ['Total Deals', `${summary.deals}`],
    ['Total Premium', fmtMoney.format(summary.premium_total)],
    ['Agent Commissions', fmtMoney.format(summary.agent_commission_total)],
    ['Agency Commissions', fmtMoney.format(summary.agency_commission_total)],
  ];

  items.forEach(([label, value]) => {
    const card = document.createElement('article');
    card.className = 'card';
    card.innerHTML = `<div class="label">${label}</div><div class="value">${value}</div>`;
    metricCards.appendChild(card);
  });

  ownerTableBody.innerHTML = '';
  payload.by_agent.forEach((row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${row.display_name}</td>
      <td>${row.deals}</td>
      <td>${fmtMoney.format(row.premium_total)}</td>
      <td>${fmtMoney.format(row.agent_commission_total)}</td>
      <td>${fmtMoney.format(row.agency_commission_total)}</td>
    `;
    ownerTableBody.appendChild(tr);
  });
}

function applySettings(settings) {
  document.getElementById('competitionMode').checked = Boolean(settings.competition_mode);
  document.getElementById('defaultAgentRate').value = settings.default_agent_commission_rate ?? 10;
  document.getElementById('defaultAgencyRate').value = settings.default_agency_commission_rate ?? 18;

  state.agents = settings.agents || [];
  salespersonSelect.innerHTML = '';
  agentNameFields.innerHTML = '';
  state.agents.forEach((agent) => {
    const option = document.createElement('option');
    option.value = String(agent.id);
    option.textContent = agent.display_name;
    salespersonSelect.appendChild(option);

    const wrap = document.createElement('label');
    wrap.innerHTML = `
      ${agent.username}
      <input data-agent-id="${agent.id}" value="${agent.display_name}" />
    `;
    agentNameFields.appendChild(wrap);
  });
}

async function loadSalesAndLeaderboard() {
  const [salesPayload, leaderboardPayload] = await Promise.all([
    api(`/api/sales?month=${encodeURIComponent(state.month)}`),
    api(`/api/leaderboard?month=${encodeURIComponent(state.month)}`),
  ]);

  renderSales(salesPayload.sales || []);
  renderLeaderboard(leaderboardPayload);
}

async function loadOwnerData() {
  const [metrics, settings] = await Promise.all([
    api(`/api/metrics?month=${encodeURIComponent(state.month)}`),
    api('/api/settings'),
  ]);
  renderOwnerMetrics(metrics);
  applySettings(settings);
}

async function refreshAll() {
  clearMessages();
  await loadSalesAndLeaderboard();
  if (state.user.role === 'owner') {
    await loadOwnerData();
  }
}

function setLoggedInUI() {
  loginView.classList.add('hidden');
  appView.classList.remove('hidden');

  welcomeText.textContent = `Welcome, ${state.user.display_name}`;
  modeText.textContent =
    state.user.role === 'owner'
      ? 'Owner mode: hidden sheet and full analytics enabled.'
      : 'Sales mode: add your deals and track monthly progress.';

  monthFilter.value = state.month;
  document.getElementById('dateSold').value = todayISO();

  const owner = state.user.role === 'owner';
  ownerTabBtn.classList.toggle('hidden', !owner);
  agentSelectWrap.classList.toggle('hidden', !owner);

  if (!owner) {
    salespersonSelect.innerHTML = '';
  }

  setActiveTab('entry');
}

function setLoggedOutUI() {
  state.user = null;
  loginView.classList.remove('hidden');
  appView.classList.add('hidden');
}

async function handleLogin(event) {
  event.preventDefault();
  clearMessages();

  const username = document.getElementById('username').value.trim();
  const passcode = document.getElementById('passcode').value;

  try {
    const payload = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, passcode }),
    });
    state.user = payload.user;
    setLoggedInUI();
    await refreshAll();
  } catch (err) {
    loginError.textContent = err.message;
  }
}

async function handleLogout() {
  try {
    await api('/api/logout', { method: 'POST', body: '{}' });
  } finally {
    setLoggedOutUI();
  }
}

async function handleSaleSubmit(event) {
  event.preventDefault();
  saleMessage.textContent = '';

  const payload = {
    customer_name: document.getElementById('customerName').value.trim(),
    phone: document.getElementById('phone').value.trim(),
    address: document.getElementById('address').value.trim(),
    date_sold: document.getElementById('dateSold').value,
    policy_type: document.getElementById('policyType').value.trim(),
    carrier: document.getElementById('carrier').value.trim(),
    premium_amount: Number(document.getElementById('premiumAmount').value),
    agent_commission_rate: Number(document.getElementById('agentRate').value || 0),
    agency_commission_rate: Number(document.getElementById('agencyRate').value || 0),
    notes: document.getElementById('notes').value.trim(),
  };

  if (state.user.role === 'owner' && salespersonSelect.value) {
    payload.salesperson_id = Number(salespersonSelect.value);
  }

  if (!payload.agent_commission_rate) {
    delete payload.agent_commission_rate;
  }
  if (!payload.agency_commission_rate) {
    delete payload.agency_commission_rate;
  }

  try {
    await api('/api/sales', { method: 'POST', body: JSON.stringify(payload) });
    saleMessage.textContent = 'Sale saved successfully.';
    document.getElementById('saleForm').reset();
    document.getElementById('dateSold').value = todayISO();
    await refreshAll();
  } catch (err) {
    saleMessage.textContent = err.message;
  }
}

async function handleUpload() {
  uploadMessage.textContent = '';
  const input = document.getElementById('csvFile');
  if (!input.files || !input.files[0]) {
    uploadMessage.textContent = 'Choose a CSV file first.';
    return;
  }

  try {
    const csvText = await input.files[0].text();
    const payload = await api('/api/upload', {
      method: 'POST',
      body: JSON.stringify({ csvText }),
    });
    uploadMessage.textContent = `Imported ${payload.created} sale rows.`;
    input.value = '';
    await refreshAll();
  } catch (err) {
    uploadMessage.textContent = err.message;
  }
}

async function handleSaveSettings(event) {
  event.preventDefault();
  settingsMessage.textContent = '';

  const payload = {
    competition_mode: document.getElementById('competitionMode').checked,
    default_agent_commission_rate: Number(document.getElementById('defaultAgentRate').value),
    default_agency_commission_rate: Number(document.getElementById('defaultAgencyRate').value),
    agents: Array.from(agentNameFields.querySelectorAll('input')).map((input) => ({
      id: Number(input.dataset.agentId),
      display_name: input.value.trim(),
    })),
  };

  try {
    await api('/api/settings', { method: 'POST', body: JSON.stringify(payload) });
    settingsMessage.textContent = 'Settings saved.';
    await refreshAll();
  } catch (err) {
    settingsMessage.textContent = err.message;
  }
}

function bindEvents() {
  document.getElementById('loginForm').addEventListener('submit', handleLogin);
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);
  document.getElementById('saleForm').addEventListener('submit', handleSaleSubmit);
  document.getElementById('refreshBtn').addEventListener('click', refreshAll);
  document.getElementById('uploadBtn').addEventListener('click', handleUpload);
  document.getElementById('settingsForm').addEventListener('submit', handleSaveSettings);

  document.getElementById('exportBtn').addEventListener('click', () => {
    window.location.href = `/api/export?month=${encodeURIComponent(state.month)}`;
  });

  monthFilter.addEventListener('change', async () => {
    state.month = monthFilter.value || currentMonth();
    await refreshAll();
  });

  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      setActiveTab(btn.dataset.tab);
    });
  });
}

async function boot() {
  bindEvents();
  monthFilter.value = state.month;
  document.getElementById('dateSold').value = todayISO();

  try {
    const payload = await api('/api/me');
    state.user = payload.user;
    setLoggedInUI();
    await refreshAll();
  } catch (_err) {
    setLoggedOutUI();
  }
}

boot();
