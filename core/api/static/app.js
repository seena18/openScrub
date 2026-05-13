const apiBase = window.location.origin;
const accessStorageKey = "scrubber_access_token";
const refreshStorageKey = "scrubber_refresh_token";
const sessionUserStorageKey = "scrubber_session_user";
let webauthnCredentialCache = [];
let apiKeyCache = [];
let usersCache = [];
let auditItemsCache = [];
let auditNextCursor = null;
let profileCache = [];
let selectedProfileIdentifiersCache = [];

function accessToken() {
  return localStorage.getItem(accessStorageKey) || "";
}

function refreshToken() {
  return localStorage.getItem(refreshStorageKey) || "";
}

function sessionUser() {
  const raw = localStorage.getItem(sessionUserStorageKey);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

function token() {
  return accessToken();
}

function setToken(value) {
  if (value) localStorage.setItem(accessStorageKey, value);
  else localStorage.removeItem(accessStorageKey);
}

function setRefreshToken(value) {
  if (value) localStorage.setItem(refreshStorageKey, value);
  else localStorage.removeItem(refreshStorageKey);
}

function setSessionUser(value) {
  if (value) localStorage.setItem(sessionUserStorageKey, JSON.stringify(value));
  else localStorage.removeItem(sessionUserStorageKey);
}

function clearSession() {
  setToken("");
  setRefreshToken("");
  setSessionUser(null);
}

function applyAuthPayload(data) {
  setToken(data?.access_token || "");
  setRefreshToken(data?.refresh_token || "");
  if (data?.user) setSessionUser(data.user);
}

function hasPrivilegedRole(user) {
  const role = String(user?.role || "").toLowerCase();
  return role === "owner" || role === "admin" || role === "system";
}

function summarizeSession(user) {
  if (!user) return "No active session.";
  const role = user.role || "unknown";
  const email = user.email || "unknown";
  const mfa = user.mfa_enabled === true ? "mfa:on" : user.mfa_enabled === false ? "mfa:off" : "mfa:unknown";
  return `Signed in as ${email} (${role}, ${mfa})`;
}

function renderSessionState({
  authStatus,
  sessionStatus,
  profilesStatus,
  usersStatus,
  apiKeysStatus,
  auditStatus,
  profilesOut,
  usersOut,
  apiKeysOut,
  auditOut,
}) {
  const user = sessionUser();
  sessionStatus.className = "status info";
  sessionStatus.textContent = summarizeSession(user);

  if (!user) {
    profileCache = [];
    selectedProfileIdentifiersCache = [];
    renderProfilePicker([]);
    usersCache = [];
    renderUserPicker([]);
    apiKeyCache = [];
    renderApiKeyPicker([]);
    auditItemsCache = [];
    auditNextCursor = null;
    if (profilesOut) profilesOut.textContent = pretty({ status: "info", detail: "Login required." });
    if (usersOut) usersOut.textContent = pretty({ status: "info", detail: "Login required." });
    if (apiKeysOut) apiKeysOut.textContent = pretty({ status: "info", detail: "Login required." });
    if (auditOut) auditOut.textContent = pretty({ status: "info", detail: "Login required." });
    setStatus(authStatus, "info", "Login required.");
    return;
  }

  const role = String(user.role || "").toLowerCase();
  if (profilesStatus && !["owner", "admin", "operator", "system"].includes(role)) {
    setStatus(profilesStatus, "info", "Profile creation requires owner/admin/operator/system role.");
  }
  if (!hasPrivilegedRole(user)) {
    setStatus(usersStatus, "info", "Users panel requires owner/admin/system role.");
    setStatus(apiKeysStatus, "info", "API key panel requires owner/admin/system role.");
  }
  if (!["owner", "admin", "reviewer", "system"].includes(role)) {
    setStatus(auditStatus, "info", "Audit panel requires owner/admin/reviewer/system role.");
  }
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function errMessage(err, fallback = "Operation failed") {
  if (!err) return fallback;
  if (typeof err === "string") return err;
  if (err.body?.detail) return String(err.body.detail);
  if (err.message) return String(err.message);
  return fallback;
}

function setStatus(el, type, message) {
  el.className = `status ${type}`;
  el.textContent = message;
}

function clearStatus(el) {
  el.className = "status hidden";
  el.textContent = "";
}

function setBusy(button, busy, loadingText) {
  if (!button) return;
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.disabled = busy;
  if (busy && loadingText) button.textContent = loadingText;
  if (!busy) button.textContent = button.dataset.label;
}

async function runTask({ button, statusEl, loadingText, successText, task, outputEl, render }) {
  setBusy(button, true, loadingText);
  setStatus(statusEl, "loading", loadingText);
  try {
    const data = await task();
    if (render) render(data);
    if (outputEl && !render) outputEl.textContent = pretty(data);
    setStatus(statusEl, "success", successText);
    return data;
  } catch (err) {
    if (outputEl) outputEl.textContent = pretty(err);
    setStatus(statusEl, "error", errMessage(err));
    throw err;
  } finally {
    setBusy(button, false);
  }
}

async function requestApi(path, opts = {}) {
  const headers = opts.headers || {};
  if (token()) headers.Authorization = `Bearer ${token()}`;
  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const res = await fetch(`${apiBase}${path}`, { ...opts, headers });
  const text = await res.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch (_) {}
  if (!res.ok) {
    const err = { status: res.status, body };
    throw err;
  }
  return body;
}

async function refreshSessionToken() {
  const rt = refreshToken();
  if (!rt) throw { status: 401, body: { detail: "missing refresh token" } };
  const data = await requestApi("/v1/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: rt }),
  });
  applyAuthPayload(data);
  return data;
}

async function api(path, opts = {}) {
  try {
    return await requestApi(path, opts);
  } catch (err) {
    const status = Number(err?.status || 0);
    const canRetry = status === 401 && Boolean(refreshToken()) && path !== "/v1/auth/refresh";
    if (!canRetry) throw err;
    try {
      await refreshSessionToken();
      return await requestApi(path, opts);
    } catch (refreshErr) {
      clearSession();
      throw refreshErr;
    }
  }
}

function base64urlToArrayBuffer(value) {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) binary += String.fromCharCode(bytes[i]);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function creationOptionsToWebAuthn(options) {
  const out = JSON.parse(JSON.stringify(options));
  out.challenge = base64urlToArrayBuffer(out.challenge);
  if (out.user && out.user.id) out.user.id = base64urlToArrayBuffer(out.user.id);
  if (Array.isArray(out.excludeCredentials)) {
    out.excludeCredentials = out.excludeCredentials.map((c) => ({
      ...c,
      id: base64urlToArrayBuffer(c.id),
    }));
  }
  return out;
}

function requestOptionsToWebAuthn(options) {
  const out = JSON.parse(JSON.stringify(options));
  out.challenge = base64urlToArrayBuffer(out.challenge);
  if (Array.isArray(out.allowCredentials)) {
    out.allowCredentials = out.allowCredentials.map((c) => ({
      ...c,
      id: base64urlToArrayBuffer(c.id),
    }));
  }
  return out;
}

function registrationCredentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: arrayBufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: arrayBufferToBase64url(cred.response.clientDataJSON),
      attestationObject: arrayBufferToBase64url(cred.response.attestationObject),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

function authenticationCredentialToJSON(cred) {
  return {
    id: cred.id,
    rawId: arrayBufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: arrayBufferToBase64url(cred.response.clientDataJSON),
      authenticatorData: arrayBufferToBase64url(cred.response.authenticatorData),
      signature: arrayBufferToBase64url(cred.response.signature),
      userHandle: cred.response.userHandle
        ? arrayBufferToBase64url(cred.response.userHandle)
        : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

function getLoginFields() {
  return {
    email: document.getElementById("email").value.trim(),
    password: document.getElementById("password").value,
    mfaCode: document.getElementById("mfa_code").value.trim(),
  };
}

function summarizeCredential(item) {
  const nick = item.nickname || "unnamed";
  const tail = (item.credential_id || "").slice(-12);
  const used = item.last_used_at ? `last:${item.last_used_at}` : "never-used";
  return `${nick} • …${tail} • ${used}`;
}

function findSelectedCredential() {
  const selectedId = document.getElementById("webauthn_credential_select").value;
  return webauthnCredentialCache.find((x) => x.credential_id === selectedId) || null;
}

function summarizeApiKey(item) {
  const role = item.role || "unknown";
  const roleLower = String(role).toLowerCase();
  const isPrivileged = ["owner", "admin", "system"].includes(roleLower);
  const expiresAt = item.expires_at || "";
  const isExpired = Boolean(expiresAt && Date.parse(expiresAt) <= Date.now());
  const state = item.enabled ? (isExpired ? "expired" : "enabled") : "revoked";
  const expires = item.expires_at ? `exp:${item.expires_at}` : "no-expiry";
  const badges = [];
  if (isPrivileged) badges.push("PRIV");
  if (!item.enabled) badges.push("REVOKED");
  if (isExpired) badges.push("EXPIRED");
  const badgeText = badges.length ? ` [${badges.join("|")}]` : "";
  return `${item.name} • ${role} • ${state} • ${expires}${badgeText}`;
}

function summarizeUser(item) {
  const role = item.role || "unknown";
  const mfa = item.mfa_enabled ? "mfa:on" : "mfa:off";
  return `${item.email} • ${role} • ${mfa}`;
}

function summarizeProfile(item) {
  const status = item.status || "unknown";
  const region = item.region_code || "n/a";
  return `${item.display_name} • ${status} • ${region}`;
}

function renderProfilePicker(items) {
  const select = document.getElementById("profiles-select");
  if (!select) return;
  const current = select.value;
  select.innerHTML = "";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select profile…";
  select.appendChild(placeholder);

  for (const item of items || []) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.textContent = summarizeProfile(item);
    select.appendChild(opt);
  }

  if (current && items.some((x) => x.id === current)) {
    select.value = current;
  }
}

function findSelectedProfile() {
  const selectedId = document.getElementById("profiles-select").value;
  return profileCache.find((x) => x.id === selectedId) || null;
}

function renderUserPicker(items) {
  const select = document.getElementById("users-select");
  if (!select) return;
  const current = select.value;
  select.innerHTML = "";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select user…";
  select.appendChild(placeholder);

  for (const item of items || []) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.textContent = summarizeUser(item);
    select.appendChild(opt);
  }

  if (current && items.some((x) => x.id === current)) {
    select.value = current;
  }
}

function findSelectedUser() {
  const selectedId = document.getElementById("users-select").value;
  return usersCache.find((x) => x.id === selectedId) || null;
}

function renderApiKeyPicker(items) {
  const select = document.getElementById("api-key-select");
  const current = select.value;
  select.innerHTML = "";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select API key…";
  select.appendChild(placeholder);

  for (const item of items || []) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.textContent = summarizeApiKey(item);
    select.appendChild(opt);
  }

  if (current && items.some((x) => x.id === current)) {
    select.value = current;
  }
}

function findSelectedApiKey() {
  const selectedId = document.getElementById("api-key-select").value;
  return apiKeyCache.find((x) => x.id === selectedId) || null;
}

function parseApiKeyPrefixes(raw) {
  return String(raw || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function downloadTextFile(filename, content, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function buildApiKeyScopePreview({ role, prefixes, expiresAt, name, selected }) {
  const normalizedRole = String(role || "system").trim().toLowerCase();
  const normalizedPrefixes = (prefixes || []).map((x) => String(x).trim()).filter(Boolean);
  const warnings = [];
  if (["owner", "admin", "system"].includes(normalizedRole)) {
    warnings.push("Privileged role: treat as high-risk secret.");
  }
  if (normalizedPrefixes.length === 0) {
    warnings.push("No path scopes set: key can hit all allowed endpoints for its role.");
  }
  if (normalizedPrefixes.some((p) => p === "/v1" || p === "/")) {
    warnings.push("Very broad prefix detected.");
  }
  const exp = expiresAt ? Date.parse(expiresAt) : NaN;
  if (expiresAt && Number.isNaN(exp)) {
    warnings.push("Expires-at is not valid ISO-8601.");
  }
  if (expiresAt && !Number.isNaN(exp) && exp <= Date.now()) {
    warnings.push("Expires-at is in the past.");
  }
  return {
    name: name || selected?.name || null,
    role: normalizedRole,
    allowed_path_prefixes: normalizedPrefixes,
    expires_at: expiresAt || selected?.expires_at || null,
    selected_key_id: selected?.id || null,
    selected_key_state: selected
      ? {
          enabled: Boolean(selected.enabled),
          expires_at: selected.expires_at || null,
        }
      : null,
    warnings,
  };
}

function renderApiKeyScopePreview() {
  const out = document.getElementById("api-key-preview-output");
  if (!out) return;
  const selected = findSelectedApiKey();
  const name = document.getElementById("api-key-name").value.trim();
  const role = document.getElementById("api-key-role").value.trim();
  const prefixesRaw = document.getElementById("api-key-prefixes").value;
  const expiresAt = document.getElementById("api-key-expires-at").value.trim();
  const preview = buildApiKeyScopePreview({
    role: role || selected?.role || "system",
    prefixes: parseApiKeyPrefixes(prefixesRaw || (selected?.allowed_path_prefixes || []).join(",")),
    expiresAt,
    name,
    selected,
  });
  out.textContent = pretty(preview);
}

function requiredDangerPhrase(action, selected) {
  return `${action}:${selected?.name || "unknown"}`;
}

function requireDangerConfirm(action, selected, currentValue) {
  const expected = requiredDangerPhrase(action, selected);
  const actual = String(currentValue || "").trim();
  if (actual !== expected) {
    throw {
      status: 400,
      body: {
        detail: `confirmation mismatch; expected '${expected}'`,
      },
    };
  }
}

async function refreshApiKeys(apiKeysOut, { verbose = true } = {}) {
  const data = await api("/v1/api-keys");
  const items = data.items || [];
  apiKeyCache = items;
  renderApiKeyPicker(items);
  if (verbose) apiKeysOut.textContent = pretty(data);
  return data;
}

async function autoLoadApiKeysAfterAuth(apiKeysOut, apiKeysStatus) {
  try {
    const data = await refreshApiKeys(apiKeysOut, { verbose: false });
    if ((data.items || []).length > 0) {
      setStatus(apiKeysStatus, "success", "API keys auto-loaded after login.");
    } else {
      setStatus(apiKeysStatus, "info", "No API keys found.");
    }
  } catch (err) {
    const status = Number(err?.status || 0);
    if (status === 403) {
      setStatus(apiKeysStatus, "info", "API key panel requires owner/admin/system role.");
      return;
    }
    setStatus(apiKeysStatus, "error", errMessage(err, "Unable to auto-load API keys."));
  }
}

async function autoLoadProfilesAfterAuth(profilesOut, profilesStatus) {
  try {
    const data = await refreshProfiles(profilesOut, { verbose: false });
    if ((data.items || []).length > 0) {
      setStatus(profilesStatus, "success", "Profiles auto-loaded after login.");
    } else {
      setStatus(profilesStatus, "info", "No profiles found.");
    }
  } catch (err) {
    const status = Number(err?.status || 0);
    if (status === 403) {
      setStatus(profilesStatus, "info", "Profile panel requires owner/admin/operator/viewer/system role.");
      return;
    }
    setStatus(profilesStatus, "error", errMessage(err, "Unable to auto-load profiles."));
  }
}

async function refreshUsers(usersOut, { verbose = true } = {}) {
  const data = await api("/v1/users");
  const items = data.items || [];
  usersCache = items;
  renderUserPicker(items);
  if (verbose) usersOut.textContent = pretty(data);
  return data;
}

async function refreshProfiles(profilesOut, { verbose = true } = {}) {
  const data = await api("/v1/profiles");
  const items = data.items || [];
  profileCache = items;
  renderProfilePicker(items);
  if (verbose) {
    profilesOut.textContent = pretty({
      profiles: items,
      selected_profile_identifiers: selectedProfileIdentifiersCache,
    });
  }
  return data;
}

async function refreshSelectedProfileIdentifiers(profilesOut) {
  const selected = findSelectedProfile();
  if (!selected) {
    throw { status: 400, body: { detail: "select a profile first" } };
  }
  const data = await api(`/v1/profiles/${encodeURIComponent(selected.id)}/identifiers`);
  selectedProfileIdentifiersCache = data.items || [];
  profilesOut.textContent = pretty({
    selected_profile: selected,
    selected_profile_identifiers: selectedProfileIdentifiersCache,
  });
  return data;
}

function getAuditFilters() {
  const fromValue = document.getElementById("audit-filter-from").value.trim();
  const toValue = document.getElementById("audit-filter-to").value.trim();
  return {
    action: document.getElementById("audit-filter-action").value.trim().toLowerCase(),
    actor: document.getElementById("audit-filter-actor").value.trim().toLowerCase(),
    objectType: document.getElementById("audit-filter-object").value.trim().toLowerCase(),
    from: fromValue,
    to: toValue,
  };
}

function applyAuditFilters(items, filters) {
  const fromTs = filters.from ? Date.parse(filters.from) : NaN;
  const toTs = filters.to ? Date.parse(filters.to) : NaN;
  return (items || []).filter((item) => {
    const action = String(item.action || "").toLowerCase();
    const actor = String(item.actor_user_id || "").toLowerCase();
    const objectType = String(item.object_type || "").toLowerCase();
    const createdTs = Date.parse(String(item.created_at || ""));
    if (filters.action && !action.includes(filters.action)) return false;
    if (filters.actor && !actor.includes(filters.actor)) return false;
    if (filters.objectType && !objectType.includes(filters.objectType)) return false;
    if (!Number.isNaN(fromTs) && !Number.isNaN(createdTs) && createdTs < fromTs) return false;
    if (!Number.isNaN(toTs) && !Number.isNaN(createdTs) && createdTs > toTs) return false;
    return true;
  });
}

function getFilteredAuditItems() {
  return applyAuditFilters(auditItemsCache, getAuditFilters());
}

function csvEscape(value) {
  const raw = value == null ? "" : String(value);
  if (/[",\n]/.test(raw)) return `"${raw.replace(/"/g, "\"\"")}"`;
  return raw;
}

function auditsToCsv(items) {
  const headers = ["id", "created_at", "action", "actor_user_id", "object_type", "object_id", "payload_json"];
  const rows = [headers.join(",")];
  for (const item of items || []) {
    const row = [
      item.id,
      item.created_at,
      item.action,
      item.actor_user_id || "",
      item.object_type || "",
      item.object_id || "",
      JSON.stringify(item.payload || {}),
    ].map(csvEscape);
    rows.push(row.join(","));
  }
  return rows.join("\n");
}

function renderAuditOutput(auditOut, { items, nextCursor, filters }) {
  const filtered = applyAuditFilters(items, filters);
  auditOut.textContent = pretty({
    filters,
    count: filtered.length,
    total_loaded: (items || []).length,
    next_cursor: nextCursor,
    items: filtered,
  });
}

async function loadAuditPage(auditOut, { cursor = "", append = false } = {}) {
  const params = new URLSearchParams();
  params.set("limit", "100");
  if (cursor) params.set("cursor", cursor);
  const data = await api(`/v1/audit-log?${params.toString()}`);
  const pageItems = data.items || [];
  auditItemsCache = append ? [...auditItemsCache, ...pageItems] : pageItems;
  auditNextCursor = data.next_cursor || null;
  renderAuditOutput(auditOut, {
    items: auditItemsCache,
    nextCursor: auditNextCursor,
    filters: getAuditFilters(),
  });
  return data;
}

function renderCredentialPicker(items) {
  const select = document.getElementById("webauthn_credential_select");
  const current = select.value;
  select.innerHTML = "";

  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Select passkey…";
  select.appendChild(placeholder);

  for (const item of items || []) {
    const opt = document.createElement("option");
    opt.value = item.credential_id;
    opt.textContent = summarizeCredential(item);
    select.appendChild(opt);
  }

  if (current && items.some((x) => x.credential_id === current)) {
    select.value = current;
  }
}

async function refreshWebAuthnCredentials(webauthnOut, { verbose = true } = {}) {
  const data = await api("/v1/auth/mfa/webauthn/credentials");
  const items = data.items || [];
  webauthnCredentialCache = items;
  renderCredentialPicker(items);
  if (verbose) webauthnOut.textContent = pretty(data);
  return data;
}

async function copyText(value) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(value);
    return true;
  }
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(ta);
  return ok;
}

function bind() {
  const authOut = document.getElementById("auth-output");
  const mfaOut = document.getElementById("mfa-output");
  const webauthnOut = document.getElementById("webauthn-output");
  const profilesOut = document.getElementById("profiles-output");
  const usersOut = document.getElementById("users-output");
  const auditOut = document.getElementById("audit-output");
  const apiKeyPreviewOut = document.getElementById("api-key-preview-output");
  const apiKeysOut = document.getElementById("api-keys-output");

  const authStatus = document.getElementById("auth-status");
  const sessionStatus = document.getElementById("session-status");
  const mfaStatus = document.getElementById("mfa-status");
  const webauthnStatus = document.getElementById("webauthn-status");
  const profilesStatus = document.getElementById("profiles-status");
  const usersStatus = document.getElementById("users-status");
  const auditStatus = document.getElementById("audit-status");
  const apiKeysStatus = document.getElementById("api-keys-status");
  const safetyStatus = document.getElementById("safety-status");

  clearStatus(authStatus);
  clearStatus(mfaStatus);
  clearStatus(webauthnStatus);
  clearStatus(profilesStatus);
  clearStatus(usersStatus);
  clearStatus(auditStatus);
  clearStatus(apiKeysStatus);
  clearStatus(safetyStatus);
  renderSessionState({
    authStatus,
    sessionStatus,
    profilesStatus,
    usersStatus,
    apiKeysStatus,
    auditStatus,
    profilesOut,
    usersOut,
    apiKeysOut,
    auditOut,
  });

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = e.submitter || document.querySelector("#login-form button[type='submit']");
    const { email, password, mfaCode } = getLoginFields();
    const payload = { email, password };
    if (mfaCode) payload.mfa_code = mfaCode;
    await runTask({
      button,
      statusEl: authStatus,
      loadingText: "Logging in…",
      successText: "Logged in successfully.",
      outputEl: authOut,
      task: async () => {
        const data = await api("/v1/auth/login", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        applyAuthPayload(data);
        renderSessionState({
          authStatus,
          sessionStatus,
          profilesStatus,
          usersStatus,
          apiKeysStatus,
          auditStatus,
          profilesOut,
          usersOut,
          apiKeysOut,
          auditOut,
        });
        await autoLoadProfilesAfterAuth(profilesOut, profilesStatus);
        await autoLoadApiKeysAfterAuth(apiKeysOut, apiKeysStatus);
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("login-passkey-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      authOut.textContent = pretty({ error: "WebAuthn not supported in this browser." });
      setStatus(authStatus, "error", "WebAuthn is not supported in this browser.");
      return;
    }
    const { email, password } = getLoginFields();
    await runTask({
      button,
      statusEl: authStatus,
      loadingText: "Waiting for passkey assertion…",
      successText: "Passkey login successful.",
      outputEl: authOut,
      task: async () => {
        const start = await api("/v1/auth/mfa/webauthn/authenticate/start", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
        const requestOpts = requestOptionsToWebAuthn(start.public_key);
        const assertion = await navigator.credentials.get({ publicKey: requestOpts });
        if (!assertion) throw { status: 400, body: { detail: "No passkey assertion returned" } };
        const finish = await api("/v1/auth/mfa/webauthn/authenticate/finish", {
          method: "POST",
          body: JSON.stringify({
            email,
            challenge_id: start.challenge_id,
            credential: authenticationCredentialToJSON(assertion),
          }),
        });
        applyAuthPayload(finish);
        renderSessionState({
          authStatus,
          sessionStatus,
          profilesStatus,
          usersStatus,
          apiKeysStatus,
          auditStatus,
          profilesOut,
          usersOut,
          apiKeysOut,
          auditOut,
        });
        await autoLoadProfilesAfterAuth(profilesOut, profilesStatus);
        await autoLoadApiKeysAfterAuth(apiKeysOut, apiKeysStatus);
        return finish;
      },
    }).catch(() => {});
  });

  document.getElementById("logout-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const rt = refreshToken();
    if (rt) {
      await runTask({
        button,
        statusEl: authStatus,
        loadingText: "Logging out…",
        successText: "Logged out.",
        outputEl: authOut,
        task: async () => api("/v1/auth/logout", { method: "POST", body: JSON.stringify({ refresh_token: rt }) }),
      }).catch(() => {});
    }
    clearSession();
    usersCache = [];
    renderUserPicker([]);
    apiKeyCache = [];
    renderApiKeyPicker([]);
    document.getElementById("api-key-plaintext").value = "";
    document.getElementById("api-key-danger-confirm").value = "";
    apiKeyPreviewOut.textContent = pretty({ status: "info", detail: "Preview unavailable while logged out." });
    usersOut.textContent = pretty({ status: "ok", detail: "Cleared local user admin state." });
    apiKeysOut.textContent = pretty({ status: "ok", detail: "Cleared local API key UI state." });
    setStatus(apiKeysStatus, "info", "API key panel reset after logout.");
    authOut.textContent = "Logged out (local session cleared).";
    renderSessionState({
      authStatus,
      sessionStatus,
      profilesStatus,
      usersStatus,
      apiKeysStatus,
      auditStatus,
      profilesOut,
      usersOut,
      apiKeysOut,
      auditOut,
    });
  });

  document.getElementById("me-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: authStatus,
      loadingText: "Loading current session…",
      successText: "Session details refreshed.",
      outputEl: authOut,
      task: async () => {
        const data = await api("/v1/auth/me");
        setSessionUser(data);
        renderSessionState({
          authStatus,
          sessionStatus,
          profilesStatus,
          usersStatus,
          apiKeysStatus,
          auditStatus,
          profilesOut,
          usersOut,
          apiKeysOut,
          auditOut,
        });
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("mfa-status-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: mfaStatus,
      loadingText: "Loading MFA status…",
      successText: "MFA status loaded.",
      outputEl: mfaOut,
      task: async () => api("/v1/auth/mfa/totp/status"),
    }).catch(() => {});
  });

  document.getElementById("totp-setup-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: mfaStatus,
      loadingText: "Starting TOTP setup…",
      successText: "TOTP setup started.",
      outputEl: mfaOut,
      task: async () => api("/v1/auth/mfa/totp/setup", { method: "POST" }),
    }).catch(() => {});
  });

  document.getElementById("totp-verify-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const code = document.getElementById("totp_verify_code").value.trim();
    await runTask({
      button,
      statusEl: mfaStatus,
      loadingText: "Verifying TOTP setup…",
      successText: "TOTP verified and enabled.",
      outputEl: mfaOut,
      task: async () =>
        api("/v1/auth/mfa/totp/verify-setup", {
          method: "POST",
          body: JSON.stringify({ code }),
        }),
    }).catch(() => {});
  });

  document.getElementById("totp-disable-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const currentPassword = document.getElementById("totp_disable_password").value;
    const code = document.getElementById("totp_disable_code").value.trim();
    const payload = { current_password: currentPassword };
    if (code) payload.code = code;
    await runTask({
      button,
      statusEl: mfaStatus,
      loadingText: "Disabling TOTP…",
      successText: "TOTP disabled.",
      outputEl: mfaOut,
      task: async () =>
        api("/v1/auth/mfa/totp/disable", {
          method: "POST",
          body: JSON.stringify(payload),
        }),
    }).catch(() => {});
  });

  document.getElementById("webauthn-setup-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      webauthnOut.textContent = pretty({ error: "WebAuthn not supported in this browser." });
      setStatus(webauthnStatus, "error", "WebAuthn is not supported in this browser.");
      return;
    }
    const nickname = document.getElementById("webauthn_nickname").value.trim();
    await runTask({
      button,
      statusEl: webauthnStatus,
      loadingText: "Waiting for passkey creation…",
      successText: "Passkey enrolled.",
      outputEl: webauthnOut,
      task: async () => {
        const start = await api("/v1/auth/mfa/webauthn/setup", { method: "POST" });
        const createOpts = creationOptionsToWebAuthn(start.public_key);
        const credential = await navigator.credentials.create({ publicKey: createOpts });
        if (!credential) throw { status: 400, body: { detail: "No passkey credential returned" } };
        const finishPayload = {
          challenge_id: start.challenge_id,
          credential: registrationCredentialToJSON(credential),
        };
        if (nickname) finishPayload.nickname = nickname;
        const finish = await api("/v1/auth/mfa/webauthn/verify-setup", {
          method: "POST",
          body: JSON.stringify(finishPayload),
        });
        await refreshWebAuthnCredentials(webauthnOut, { verbose: false });
        return { start, finish };
      },
    }).catch(() => {});
  });

  document.getElementById("webauthn-list-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: webauthnStatus,
      loadingText: "Loading passkeys…",
      successText: "Passkeys loaded.",
      outputEl: webauthnOut,
      task: async () => refreshWebAuthnCredentials(webauthnOut),
    }).catch(() => {});
  });

  document.getElementById("webauthn-use-selected-btn").addEventListener("click", () => {
    const selected = findSelectedCredential();
    if (!selected) {
      webauthnOut.textContent = pretty({ status: "info", detail: "No passkey selected." });
      setStatus(webauthnStatus, "info", "No passkey selected.");
      return;
    }
    webauthnOut.textContent = pretty({
      status: "ok",
      credential_id: selected.credential_id,
      nickname: selected.nickname || null,
      last_used_at: selected.last_used_at || null,
    });
    setStatus(webauthnStatus, "success", "Passkey selected.");
  });

  document.getElementById("webauthn-copy-id-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedCredential();
    if (!selected) {
      webauthnOut.textContent = pretty({ status: "info", detail: "No passkey selected." });
      setStatus(webauthnStatus, "info", "Select a passkey before copying.");
      return;
    }
    setBusy(button, true, "Copying…");
    try {
      const ok = await copyText(selected.credential_id);
      if (!ok) throw new Error("Clipboard copy failed");
      setStatus(webauthnStatus, "success", "Selected passkey ID copied.");
      webauthnOut.textContent = pretty({ copied_credential_id: selected.credential_id });
    } catch (err) {
      setStatus(webauthnStatus, "error", errMessage(err, "Unable to copy credential ID."));
      webauthnOut.textContent = pretty({ error: errMessage(err) });
    } finally {
      setBusy(button, false);
    }
  });

  document.getElementById("webauthn-details-btn").addEventListener("click", () => {
    const selected = findSelectedCredential();
    if (!selected) {
      webauthnOut.textContent = pretty({ status: "info", detail: "No passkey selected." });
      setStatus(webauthnStatus, "info", "No passkey selected.");
      return;
    }
    webauthnOut.textContent = pretty(selected);
    setStatus(webauthnStatus, "success", "Showing selected passkey details.");
  });

  document.getElementById("webauthn-delete-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedCredential();
    const currentPassword = document.getElementById("webauthn_delete_password").value;
    if (!selected) {
      webauthnOut.textContent = pretty({ error: "Select a passkey first." });
      setStatus(webauthnStatus, "error", "Select a passkey to delete.");
      return;
    }
    await runTask({
      button,
      statusEl: webauthnStatus,
      loadingText: "Deleting selected passkey…",
      successText: "Passkey deleted.",
      outputEl: webauthnOut,
      task: async () => {
        const data = await api(
          `/v1/auth/mfa/webauthn/credentials/${encodeURIComponent(selected.credential_id)}`,
          {
            method: "DELETE",
            body: JSON.stringify({ current_password: currentPassword }),
          }
        );
        await refreshWebAuthnCredentials(webauthnOut, { verbose: false });
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("profiles-load-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: profilesStatus,
      loadingText: "Loading profiles…",
      successText: "Profiles loaded.",
      outputEl: profilesOut,
      task: async () => refreshProfiles(profilesOut),
    }).catch(() => {});
  });

  document.getElementById("profiles-show-btn").addEventListener("click", () => {
    const selected = findSelectedProfile();
    if (!selected) {
      profilesOut.textContent = pretty({ status: "info", detail: "No profile selected." });
      setStatus(profilesStatus, "info", "Select a profile.");
      return;
    }
    profilesOut.textContent = pretty({
      selected_profile: selected,
      selected_profile_identifiers: selectedProfileIdentifiersCache,
    });
    setStatus(profilesStatus, "success", "Showing selected profile.");
  });

  document.getElementById("profiles-select").addEventListener("change", () => {
    const selected = findSelectedProfile();
    if (!selected) {
      selectedProfileIdentifiersCache = [];
      return;
    }
    profilesOut.textContent = pretty({
      selected_profile: selected,
      selected_profile_identifiers: selectedProfileIdentifiersCache,
    });
  });

  document.getElementById("profile-create-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const displayName = document.getElementById("profile-display-name").value.trim();
    const regionCode = document.getElementById("profile-region-code").value.trim();
    const ownerUserId = document.getElementById("profile-owner-user-id").value.trim();
    const payload = { display_name: displayName };
    if (regionCode) payload.region_code = regionCode;
    if (ownerUserId) payload.owner_user_id = ownerUserId;

    await runTask({
      button,
      statusEl: profilesStatus,
      loadingText: "Creating profile…",
      successText: "Profile created.",
      outputEl: profilesOut,
      task: async () => {
        const created = await api("/v1/profiles", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        document.getElementById("profile-display-name").value = "";
        document.getElementById("profile-region-code").value = "";
        await refreshProfiles(profilesOut, { verbose: false });
        document.getElementById("profiles-select").value = created.id;
        selectedProfileIdentifiersCache = [];
        profilesOut.textContent = pretty({
          created_profile: created,
          selected_profile_identifiers: selectedProfileIdentifiersCache,
        });
        return created;
      },
    }).catch(() => {});
  });

  document.getElementById("identifiers-load-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: profilesStatus,
      loadingText: "Loading identifiers…",
      successText: "Identifiers loaded.",
      outputEl: profilesOut,
      task: async () => refreshSelectedProfileIdentifiers(profilesOut),
    }).catch(() => {});
  });

  document.getElementById("identifier-create-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedProfile();
    if (!selected) {
      profilesOut.textContent = pretty({ error: "Select a profile first." });
      setStatus(profilesStatus, "error", "Select a profile to add identifier.");
      return;
    }
    const idType = document.getElementById("identifier-id-type").value.trim();
    const value = document.getElementById("identifier-value").value.trim();
    const isPrimary = document.getElementById("identifier-is-primary").checked;
    const payload = {
      profile_id: selected.id,
      id_type: idType,
      value,
      is_primary: isPrimary,
    };

    await runTask({
      button,
      statusEl: profilesStatus,
      loadingText: "Creating identifier…",
      successText: "Identifier created.",
      outputEl: profilesOut,
      task: async () => {
        const created = await api("/v1/identifiers", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        document.getElementById("identifier-value").value = "";
        document.getElementById("identifier-is-primary").checked = false;
        await refreshSelectedProfileIdentifiers(profilesOut);
        return created;
      },
    }).catch(() => {});
  });

  document.getElementById("users-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: usersStatus,
      loadingText: "Loading users…",
      successText: "Users loaded.",
      outputEl: usersOut,
      task: async () => refreshUsers(usersOut),
    }).catch(() => {});
  });

  document.getElementById("users-show-btn").addEventListener("click", () => {
    const selected = findSelectedUser();
    if (!selected) {
      usersOut.textContent = pretty({ status: "info", detail: "No user selected." });
      setStatus(usersStatus, "info", "Select a user.");
      return;
    }
    usersOut.textContent = pretty(selected);
    setStatus(usersStatus, "success", "Showing selected user.");
  });

  document.getElementById("users-select").addEventListener("change", () => {
    const selected = findSelectedUser();
    if (!selected) return;
    document.getElementById("users-role-select").value = selected.role || "viewer";
    document.getElementById("users-mfa-select").value = selected.mfa_enabled ? "true" : "false";
  });

  document.getElementById("users-role-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedUser();
    if (!selected) {
      usersOut.textContent = pretty({ error: "Select a user first." });
      setStatus(usersStatus, "error", "Select a user to change role.");
      return;
    }
    const role = document.getElementById("users-role-select").value.trim();
    await runTask({
      button,
      statusEl: usersStatus,
      loadingText: "Updating user role…",
      successText: "User role updated.",
      outputEl: usersOut,
      task: async () => {
        const data = await api(`/v1/users/${encodeURIComponent(selected.id)}/role`, {
          method: "PATCH",
          body: JSON.stringify({ role }),
        });
        await refreshUsers(usersOut, { verbose: false });
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("users-mfa-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedUser();
    if (!selected) {
      usersOut.textContent = pretty({ error: "Select a user first." });
      setStatus(usersStatus, "error", "Select a user to set MFA state.");
      return;
    }
    const mfaEnabled = document.getElementById("users-mfa-select").value === "true";
    await runTask({
      button,
      statusEl: usersStatus,
      loadingText: "Updating user MFA state…",
      successText: "User MFA state updated.",
      outputEl: usersOut,
      task: async () => {
        const data = await api(`/v1/users/${encodeURIComponent(selected.id)}/mfa`, {
          method: "PATCH",
          body: JSON.stringify({ mfa_enabled: mfaEnabled }),
        });
        await refreshUsers(usersOut, { verbose: false });
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("users-delete-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedUser();
    if (!selected) {
      usersOut.textContent = pretty({ error: "Select a user first." });
      setStatus(usersStatus, "error", "Select a user to delete.");
      return;
    }
    const confirmValue = document.getElementById("users-delete-confirm").value.trim().toLowerCase();
    if (!confirmValue || confirmValue !== String(selected.email || "").toLowerCase()) {
      usersOut.textContent = pretty({
        error: "Delete confirmation mismatch",
        expected: selected.email,
        hint: "Type the selected email exactly",
      });
      setStatus(usersStatus, "error", "Type selected email in confirmation field before delete.");
      return;
    }
    await runTask({
      button,
      statusEl: usersStatus,
      loadingText: "Deleting user…",
      successText: "User deleted.",
      outputEl: usersOut,
      task: async () => {
        const data = await api(`/v1/users/${encodeURIComponent(selected.id)}`, { method: "DELETE" });
        document.getElementById("users-delete-confirm").value = "";
        await refreshUsers(usersOut, { verbose: false });
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("audit-load-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: auditStatus,
      loadingText: "Loading audit log…",
      successText: "Audit log loaded.",
      outputEl: auditOut,
      task: async () => loadAuditPage(auditOut, { cursor: "", append: false }),
    }).catch(() => {});
  });

  document.getElementById("audit-next-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    if (!auditNextCursor) {
      auditOut.textContent = pretty({
        status: "info",
        detail: "No next page cursor. Load audit log first or you reached the end.",
      });
      setStatus(auditStatus, "info", "No next page available.");
      return;
    }
    await runTask({
      button,
      statusEl: auditStatus,
      loadingText: "Loading next audit page…",
      successText: "Next audit page loaded.",
      outputEl: auditOut,
      task: async () => loadAuditPage(auditOut, { cursor: auditNextCursor, append: true }),
    }).catch(() => {});
  });

  document.getElementById("audit-apply-filter-btn").addEventListener("click", () => {
    const filters = getAuditFilters();
    const fromTs = filters.from ? Date.parse(filters.from) : NaN;
    const toTs = filters.to ? Date.parse(filters.to) : NaN;
    if (!Number.isNaN(fromTs) && !Number.isNaN(toTs) && fromTs > toTs) {
      setStatus(auditStatus, "error", "Invalid range: 'from' is later than 'to'.");
      return;
    }
    renderAuditOutput(auditOut, {
      items: auditItemsCache,
      nextCursor: auditNextCursor,
      filters,
    });
    setStatus(auditStatus, "success", "Audit filters applied.");
  });

  document.getElementById("audit-reset-btn").addEventListener("click", () => {
    document.getElementById("audit-filter-action").value = "";
    document.getElementById("audit-filter-actor").value = "";
    document.getElementById("audit-filter-object").value = "";
    document.getElementById("audit-filter-from").value = "";
    document.getElementById("audit-filter-to").value = "";
    auditItemsCache = [];
    auditNextCursor = null;
    auditOut.textContent = pretty({ status: "ok", detail: "Audit view reset." });
    setStatus(auditStatus, "info", "Audit view reset.");
  });

  document.getElementById("audit-export-json-btn").addEventListener("click", () => {
    const filtered = getFilteredAuditItems();
    const payload = {
      exported_at: new Date().toISOString(),
      filters: getAuditFilters(),
      count: filtered.length,
      items: filtered,
    };
    downloadTextFile(`audit-export-${Date.now()}.json`, `${pretty(payload)}\n`, "application/json;charset=utf-8");
    setStatus(auditStatus, "success", `Exported ${filtered.length} audit rows as JSON.`);
  });

  document.getElementById("audit-export-csv-btn").addEventListener("click", () => {
    const filtered = getFilteredAuditItems();
    downloadTextFile(`audit-export-${Date.now()}.csv`, `${auditsToCsv(filtered)}\n`, "text/csv;charset=utf-8");
    setStatus(auditStatus, "success", `Exported ${filtered.length} audit rows as CSV.`);
  });

  document.getElementById("api-keys-load-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: apiKeysStatus,
      loadingText: "Loading API keys…",
      successText: "API keys loaded.",
      outputEl: apiKeysOut,
      task: async () => refreshApiKeys(apiKeysOut),
    }).catch(() => {});
  });

  document.getElementById("api-key-details-btn").addEventListener("click", () => {
    const selected = findSelectedApiKey();
    if (!selected) {
      apiKeysOut.textContent = pretty({ status: "info", detail: "No API key selected." });
      setStatus(apiKeysStatus, "info", "No API key selected.");
      return;
    }
    apiKeysOut.textContent = pretty({
      ...selected,
      danger_confirm_rotate: requiredDangerPhrase("rotate", selected),
      danger_confirm_revoke: requiredDangerPhrase("revoke", selected),
    });
    setStatus(apiKeysStatus, "success", "Showing selected API key details.");
  });

  document.getElementById("api-key-preview-btn").addEventListener("click", () => {
    renderApiKeyScopePreview();
    setStatus(apiKeysStatus, "success", "API key scope preview updated.");
  });

  document.getElementById("api-key-select").addEventListener("change", () => {
    const selected = findSelectedApiKey();
    if (!selected) return;
    document.getElementById("api-key-role").value = selected.role || "system";
    document.getElementById("api-key-prefixes").value = (selected.allowed_path_prefixes || []).join(",");
    document.getElementById("api-key-expires-at").value = selected.expires_at || "";
    renderApiKeyScopePreview();
  });

  for (const id of ["api-key-name", "api-key-role", "api-key-prefixes", "api-key-expires-at"]) {
    document.getElementById(id).addEventListener("input", () => renderApiKeyScopePreview());
  }

  document.getElementById("api-key-create-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const name = document.getElementById("api-key-name").value.trim();
    const role = document.getElementById("api-key-role").value.trim();
    const prefixesRaw = document.getElementById("api-key-prefixes").value;
    const expiresAt = document.getElementById("api-key-expires-at").value.trim();
    const payload = {
      name,
      role,
      allowed_path_prefixes: parseApiKeyPrefixes(prefixesRaw),
    };
    if (expiresAt) payload.expires_at = expiresAt;

    await runTask({
      button,
      statusEl: apiKeysStatus,
      loadingText: "Creating API key…",
      successText: "API key created (plaintext shown once).",
      outputEl: apiKeysOut,
      task: async () => {
        const data = await api("/v1/api-keys", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        const plainEl = document.getElementById("api-key-plaintext");
        plainEl.value = data.api_key || "";
        document.getElementById("api-key-danger-confirm").value = "";
        await refreshApiKeys(apiKeysOut, { verbose: false });
        renderApiKeyScopePreview();
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("api-key-rotate-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedApiKey();
    if (!selected) {
      apiKeysOut.textContent = pretty({ error: "Select an API key first." });
      setStatus(apiKeysStatus, "error", "Select an API key to rotate.");
      return;
    }
    try {
      requireDangerConfirm("rotate", selected, document.getElementById("api-key-danger-confirm").value);
    } catch (err) {
      apiKeysOut.textContent = pretty(err);
      setStatus(apiKeysStatus, "error", errMessage(err));
      return;
    }

    await runTask({
      button,
      statusEl: apiKeysStatus,
      loadingText: "Rotating API key…",
      successText: "API key rotated (new plaintext shown once).",
      outputEl: apiKeysOut,
      task: async () => {
        const data = await api(`/v1/api-keys/${encodeURIComponent(selected.id)}/rotate`, {
          method: "POST",
        });
        const plainEl = document.getElementById("api-key-plaintext");
        plainEl.value = data.api_key || "";
        document.getElementById("api-key-danger-confirm").value = "";
        await refreshApiKeys(apiKeysOut, { verbose: false });
        renderApiKeyScopePreview();
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("api-key-revoke-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedApiKey();
    if (!selected) {
      apiKeysOut.textContent = pretty({ error: "Select an API key first." });
      setStatus(apiKeysStatus, "error", "Select an API key to revoke.");
      return;
    }
    try {
      requireDangerConfirm("revoke", selected, document.getElementById("api-key-danger-confirm").value);
    } catch (err) {
      apiKeysOut.textContent = pretty(err);
      setStatus(apiKeysStatus, "error", errMessage(err));
      return;
    }

    await runTask({
      button,
      statusEl: apiKeysStatus,
      loadingText: "Revoking API key…",
      successText: "API key revoked.",
      outputEl: apiKeysOut,
      task: async () => {
        const data = await api(`/v1/api-keys/${encodeURIComponent(selected.id)}/revoke`, {
          method: "POST",
        });
        document.getElementById("api-key-danger-confirm").value = "";
        await refreshApiKeys(apiKeysOut, { verbose: false });
        renderApiKeyScopePreview();
        return data;
      },
    }).catch(() => {});
  });

  document.getElementById("api-key-copy-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const plainEl = document.getElementById("api-key-plaintext");
    const keyValue = plainEl.value.trim();
    if (!keyValue) {
      apiKeysOut.textContent = pretty({ status: "info", detail: "No plaintext key available to copy." });
      setStatus(apiKeysStatus, "info", "No plaintext key available to copy.");
      return;
    }
    setBusy(button, true, "Copying…");
    try {
      const ok = await copyText(keyValue);
      if (!ok) throw new Error("Clipboard copy failed");
      setStatus(apiKeysStatus, "success", "API key copied to clipboard.");
      apiKeysOut.textContent = pretty({ copied: true, key_preview: `${keyValue.slice(0, 10)}...` });
    } catch (err) {
      setStatus(apiKeysStatus, "error", errMessage(err, "Unable to copy API key."));
      apiKeysOut.textContent = pretty({ error: errMessage(err) });
    } finally {
      setBusy(button, false);
    }
  });

  document.getElementById("api-key-copy-curl-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    const selected = findSelectedApiKey();
    const keyValue = document.getElementById("api-key-plaintext").value.trim();
    if (!keyValue) {
      apiKeysOut.textContent = pretty({
        error: "No plaintext key available.",
        hint: "Create or rotate a key first, then copy curl.",
      });
      setStatus(apiKeysStatus, "error", "No plaintext key available to build curl example.");
      return;
    }
    const path = selected?.allowed_path_prefixes?.[0] || "/v1/version";
    const curlCmd = `curl -H "Authorization: Bearer ${keyValue}" "${apiBase}${path}"`;
    setBusy(button, true, "Copying…");
    try {
      const ok = await copyText(curlCmd);
      if (!ok) throw new Error("Clipboard copy failed");
      apiKeysOut.textContent = pretty({
        copied: true,
        curl_example: curlCmd,
      });
      setStatus(apiKeysStatus, "success", "Curl example copied.");
    } catch (err) {
      apiKeysOut.textContent = pretty({ error: errMessage(err) });
      setStatus(apiKeysStatus, "error", errMessage(err, "Unable to copy curl example."));
    } finally {
      setBusy(button, false);
    }
  });

  document.getElementById("clear-sensitive-btn").addEventListener("click", () => {
    document.getElementById("api-key-plaintext").value = "";
    document.getElementById("api-key-danger-confirm").value = "";
    document.getElementById("totp_verify_code").value = "";
    document.getElementById("totp_disable_password").value = "";
    document.getElementById("totp_disable_code").value = "";
    document.getElementById("webauthn_delete_password").value = "";
    document.getElementById("users-delete-confirm").value = "";
    document.getElementById("profile-display-name").value = "";
    document.getElementById("profile-region-code").value = "";
    document.getElementById("profile-owner-user-id").value = "";
    document.getElementById("identifier-value").value = "";
    document.getElementById("identifier-is-primary").checked = false;

    auditItemsCache = [];
    auditNextCursor = null;
    selectedProfileIdentifiersCache = [];
    document.getElementById("audit-filter-action").value = "";
    document.getElementById("audit-filter-actor").value = "";
    document.getElementById("audit-filter-object").value = "";
    document.getElementById("audit-filter-from").value = "";
    document.getElementById("audit-filter-to").value = "";

    mfaOut.textContent = pretty({ status: "ok", detail: "MFA form inputs cleared." });
    webauthnOut.textContent = pretty({ status: "ok", detail: "WebAuthn sensitive inputs cleared." });
    profilesOut.textContent = pretty({ status: "ok", detail: "Profile/identifier form inputs and selected identifier cache cleared." });
    auditOut.textContent = pretty({ status: "ok", detail: "Audit cache + filters cleared from UI state." });
    apiKeysOut.textContent = pretty({ status: "ok", detail: "API key plaintext and danger confirm cleared." });
    apiKeyPreviewOut.textContent = pretty({ status: "ok", detail: "Preview remains available; sensitive fields cleared." });
    setStatus(safetyStatus, "success", "Sensitive UI fields and local caches cleared.");
  });

  if (token()) {
    api("/v1/auth/me")
      .then(async (me) => {
        setSessionUser(me);
        authOut.textContent = pretty(me);
        setStatus(authStatus, "success", "Session restored from local token.");
        renderSessionState({
          authStatus,
          sessionStatus,
          profilesStatus,
          usersStatus,
          apiKeysStatus,
          auditStatus,
          profilesOut,
          usersOut,
          apiKeysOut,
          auditOut,
        });
        await autoLoadProfilesAfterAuth(profilesOut, profilesStatus);
      })
      .catch(() => {
        clearSession();
        renderSessionState({
          authStatus,
          sessionStatus,
          profilesStatus,
          usersStatus,
          apiKeysStatus,
          auditStatus,
          profilesOut,
          usersOut,
          apiKeysOut,
          auditOut,
        });
      });
  }

  renderApiKeyScopePreview();
}

bind();
