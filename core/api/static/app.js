const apiBase = window.location.origin;
const storageKey = "scrubber_access_token";
let webauthnCredentialCache = [];
let apiKeyCache = [];

function token() {
  return localStorage.getItem(storageKey) || "";
}

function setToken(value) {
  if (value) localStorage.setItem(storageKey, value);
  else localStorage.removeItem(storageKey);
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

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (token()) headers.Authorization = `Bearer ${token()}`;
  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  const res = await fetch(`${apiBase}${path}`, { ...opts, headers });
  const text = await res.text();
  let body = text;
  try {
    body = JSON.parse(text);
  } catch (_) {}
  if (!res.ok) throw { status: res.status, body };
  return body;
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
  const state = item.enabled ? "enabled" : "revoked";
  const expires = item.expires_at ? `exp:${item.expires_at}` : "no-expiry";
  return `${item.name} • ${role} • ${state} • ${expires}`;
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
  const usersOut = document.getElementById("users-output");
  const apiKeysOut = document.getElementById("api-keys-output");

  const authStatus = document.getElementById("auth-status");
  const mfaStatus = document.getElementById("mfa-status");
  const webauthnStatus = document.getElementById("webauthn-status");
  const usersStatus = document.getElementById("users-status");
  const apiKeysStatus = document.getElementById("api-keys-status");

  clearStatus(authStatus);
  clearStatus(mfaStatus);
  clearStatus(webauthnStatus);
  clearStatus(usersStatus);
  clearStatus(apiKeysStatus);

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
        setToken(data.access_token || "");
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
        setToken(finish.access_token || "");
        await autoLoadApiKeysAfterAuth(apiKeysOut, apiKeysStatus);
        return finish;
      },
    }).catch(() => {});
  });

  document.getElementById("logout-btn").addEventListener("click", () => {
    setToken("");
    apiKeyCache = [];
    renderApiKeyPicker([]);
    document.getElementById("api-key-plaintext").value = "";
    apiKeysOut.textContent = pretty({ status: "ok", detail: "Cleared local API key UI state." });
    setStatus(apiKeysStatus, "info", "API key panel reset after logout.");
    authOut.textContent = "Logged out locally (token cleared).";
    setStatus(authStatus, "info", "Local token cleared.");
  });

  document.getElementById("me-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: authStatus,
      loadingText: "Loading current session…",
      successText: "Session details refreshed.",
      outputEl: authOut,
      task: async () => api("/v1/auth/me"),
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

  document.getElementById("users-btn").addEventListener("click", async (e) => {
    const button = e.currentTarget;
    await runTask({
      button,
      statusEl: usersStatus,
      loadingText: "Loading users…",
      successText: "Users loaded.",
      outputEl: usersOut,
      task: async () => api("/v1/users"),
    }).catch(() => {});
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
    apiKeysOut.textContent = pretty(selected);
    setStatus(apiKeysStatus, "success", "Showing selected API key details.");
  });

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
        await refreshApiKeys(apiKeysOut, { verbose: false });
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
        await refreshApiKeys(apiKeysOut, { verbose: false });
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
        await refreshApiKeys(apiKeysOut, { verbose: false });
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
}

bind();
