/*
 * Live demo client for the auth-service. Every call here is a genuine, same-origin HTTP request to
 * the running Spring Boot service — there is no mocking. The page is served BY the service, so the
 * page origin equals the WebAuthn relying-party origin and passkeys work without any cross-origin
 * gymnastics.
 */
/* =========================================================================
 *  EDIT ME — where your portfolio lives.
 *  Set this to your portfolio's URL (e.g. "https://kaushalbhatt.dev") so the
 *  "Back to portfolio" link in the footer actually goes there. Leave it as ""
 *  and that link falls back to the referring page, or is hidden entirely
 *  rather than pointing nowhere.
 * ========================================================================= */
var PORTFOLIO_URL = "";
/* ======================================================================== */

(function () {
  "use strict";

  var state = { token: null, email: null, hasPasskey: false };

  // ---- base64url helpers (WebAuthn buffers <-> the service's base64url-no-pad wire format) ----
  function b64urlToBytes(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function bytesToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // ---- tiny DOM + JSON-highlight helpers ----
  function $(id) { return document.getElementById(id); }

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function highlightJson(obj) {
    var json = JSON.stringify(obj, null, 2);
    return escapeHtml(json)
      .replace(/&quot;([^&]+)&quot;(\s*:)/g, '<span class="json-key">"$1"</span>$2')
      .replace(/:\s&quot;([^&]*)&quot;/g, ': <span class="json-str">"$1"</span>')
      .replace(/:\s(-?\d+\.?\d*)/g, ': <span class="json-num">$1</span>')
      .replace(/:\s(true|false|null)/g, ': <span class="json-bool">$1</span>');
  }

  // ---- rate-limit badge ----
  function updateRateBadge(headers) {
    var remaining = headers.get("X-RateLimit-Remaining");
    var limit = headers.get("X-RateLimit-Limit");
    if (remaining === null || limit === null) return;
    var badge = $("ratelimit-badge");
    badge.textContent = remaining + " / " + limit + " left today";
    badge.className = "pill " + (remaining === "0" ? "pill-danger" : (parseInt(remaining, 10) <= 1 ? "pill-warn" : "pill-muted"));
  }

  // ---- the one network primitive ----
  async function api(path, method, body, token) {
    var headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (token) headers["Authorization"] = "Bearer " + token;

    var res = await fetch(path, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined
    });
    updateRateBadge(res.headers);

    var text = await res.text();
    var data = null;
    if (text) { try { data = JSON.parse(text); } catch (e) { data = text; } }

    return {
      ok: res.ok,
      status: res.status,
      statusText: res.statusText,
      rateLimited: res.status === 429,
      request: { method: method, path: path, body: body || null },
      data: data
    };
  }

  // ---- render a step's request/response panel ----
  function renderIO(elId, result, okMessage) {
    var el = $(elId);
    el.hidden = false;
    var codeClass = result.ok ? "code-ok" : "code-err";
    var dotClass = result.ok ? "dot-ok" : "dot-err";
    var msg = result.ok
      ? okMessage
      : (result.data && result.data.message) || (result.data && result.data.error) || result.statusText || "Request failed";

    el.innerHTML =
      '<div class="io-status">' +
        '<span class="dot ' + dotClass + '"></span>' +
        '<span class="method">' + result.request.method + " " + escapeHtml(result.request.path) + '</span>' +
        '<span class="' + codeClass + '">→ ' + result.status + " " + escapeHtml(result.statusText) + '</span>' +
      '</div>' +
      '<div class="io-msg ' + (result.ok ? "" : "err") + '">' + escapeHtml(msg) + '</div>' +
      (result.request.body
        ? '<details class="io-block"><summary>request body</summary><pre>' + highlightJson(result.request.body) + '</pre></details>'
        : "") +
      (result.data
        ? '<details class="io-block" open><summary>response body</summary><pre>' +
            (typeof result.data === "string" ? escapeHtml(result.data) : highlightJson(result.data)) +
          '</pre></details>'
        : "");
  }

  function setDone(stepNum) {
    var step = document.querySelector('.step[data-step="' + stepNum + '"]');
    if (step) step.setAttribute("data-done", "true");
  }

  async function withLoading(btn, fn) {
    btn.classList.add("loading");
    btn.disabled = true;
    try { return await fn(); }
    finally { btn.classList.remove("loading"); btn.disabled = false; }
  }

  function requireCreds() {
    var email = $("email").value.trim();
    var password = $("password").value;
    if (!email || !password) {
      alert("Enter an email and password in step 1 first.");
      return null;
    }
    return { email: email, password: password };
  }

  // ---- JWT decode (display only — the SERVER is what actually verifies the signature) ----
  function decodeJwt(token) {
    var parts = token.split(".");
    if (parts.length !== 3) return null;
    try {
      return {
        header: JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]))),
        payload: JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])))
      };
    } catch (e) { return null; }
  }

  function afterLogin(result) {
    if (!result.ok || !result.data || !result.data.accessToken) return;
    state.token = result.data.accessToken;
    var decoded = decodeJwt(state.token);
    if (decoded) {
      $("token-view").hidden = false;
      $("jwt-header").innerHTML = highlightJson(decoded.header);
      $("jwt-payload").innerHTML = highlightJson(withReadableTimes(decoded.payload));
    }
    $("btn-passkey-register").disabled = false;
    $("hint-passkey-register").textContent = "";
    $("btn-protected").disabled = false;
    $("hint-protected").textContent = "";
  }

  function withReadableTimes(payload) {
    var copy = Object.assign({}, payload);
    ["iat", "exp", "nbf"].forEach(function (k) {
      if (typeof copy[k] === "number") copy[k + " (readable)"] = new Date(copy[k] * 1000).toISOString();
    });
    return copy;
  }

  // ---------- STEP 1: register ----------
  $("btn-register").addEventListener("click", function () {
    var creds = requireCreds();
    if (!creds) return;
    withLoading(this, async function () {
      var result = await api("/auth/register", "POST", creds, null);
      state.email = creds.email;
      renderIO("io-register", result, "Account created (HTTP 201). You can now log in.");
      if (result.ok) setDone(1);
    });
  });

  // ---------- STEP 2: password login ----------
  $("btn-login").addEventListener("click", function () {
    var creds = requireCreds();
    if (!creds) return;
    withLoading(this, async function () {
      var result = await api("/auth/login", "POST", creds, null);
      state.email = creds.email;
      renderIO("io-login", result, "Logged in. Access + refresh tokens issued; access token decoded below.");
      if (result.ok) { setDone(2); afterLogin(result); }
    });
  });

  // ---------- STEP 3: register a passkey ----------
  $("btn-passkey-register").addEventListener("click", function () {
    if (!state.token) { alert("Log in (step 2) first."); return; }
    withLoading(this, async function () {
      var init = await api("/passkey/register/init", "POST", null, state.token);
      if (!init.ok) { renderIO("io-passkey-register", init, ""); return; }

      var opt = init.data;
      var publicKey = {
        challenge: b64urlToBytes(opt.challenge),
        rp: { id: opt.rpId, name: opt.rpName },
        user: {
          id: new TextEncoder().encode(opt.userId),
          name: opt.userName,
          displayName: opt.userName
        },
        pubKeyCredParams: opt.pubKeyCredParams.map(function (p) { return { type: p.type, alg: p.alg }; }),
        timeout: opt.timeoutMillis,
        // "required", not "preferred": the server validates with
        // userVerificationRequired=true, so an authenticator that satisfied only user
        // PRESENCE would produce a credential the server then rejects. Asking for it up
        // front makes the authenticator actually verify the user (biometric or PIN).
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        attestation: "none"
      };

      var cred;
      try {
        cred = await navigator.credentials.create({ publicKey: publicKey });
      } catch (e) {
        renderIO("io-passkey-register",
          { ok: false, status: 0, statusText: "cancelled", request: { method: "WebAuthn", path: "navigator.credentials.create()", body: null }, data: { message: browserAuthnError(e) } }, "");
        return;
      }

      var body = {
        challenge: opt.challenge,
        credentialId: bytesToB64url(cred.rawId),
        attestationObject: bytesToB64url(cred.response.attestationObject),
        clientDataJSON: bytesToB64url(cred.response.clientDataJSON)
      };
      var complete = await api("/passkey/register/complete", "POST", body, state.token);
      renderIO("io-passkey-register", complete, "Passkey registered and bound to your account. Now try logging in with it.");
      if (complete.ok) {
        state.hasPasskey = true;
        setDone(3);
        $("btn-passkey-login").disabled = false;
        $("hint-passkey-login").textContent = "";
      }
    });
  });

  // ---------- STEP 4: passkey login ----------
  $("btn-passkey-login").addEventListener("click", function () {
    var email = (state.email || $("email").value.trim());
    if (!email) { alert("Enter your email in step 1."); return; }
    withLoading(this, async function () {
      var init = await api("/passkey/login/init", "POST", { email: email }, null);
      if (!init.ok) { renderIO("io-passkey-login", init, ""); return; }

      var opt = init.data;
      var publicKey = {
        challenge: b64urlToBytes(opt.challenge),
        rpId: opt.rpId,
        allowCredentials: (opt.allowCredentialIds || []).map(function (id) {
          return { type: "public-key", id: b64urlToBytes(id) };
        }),
        timeout: opt.timeoutMillis,
        // Must match the registration ceremony and the server's AuthenticationParameters,
        // which also require user verification.
        userVerification: "required"
      };

      var assertion;
      try {
        assertion = await navigator.credentials.get({ publicKey: publicKey });
      } catch (e) {
        renderIO("io-passkey-login",
          { ok: false, status: 0, statusText: "cancelled", request: { method: "WebAuthn", path: "navigator.credentials.get()", body: null }, data: { message: browserAuthnError(e) } }, "");
        return;
      }

      var body = {
        challenge: opt.challenge,
        credentialId: bytesToB64url(assertion.rawId),
        authenticatorData: bytesToB64url(assertion.response.authenticatorData),
        clientDataJSON: bytesToB64url(assertion.response.clientDataJSON),
        signature: bytesToB64url(assertion.response.signature)
      };
      var complete = await api("/passkey/login/complete", "POST", body, null);
      renderIO("io-passkey-login", complete, "Signed in with the passkey — no password. Fresh tokens issued.");
      if (complete.ok) { setDone(4); afterLogin(complete); }
    });
  });

  // ---------- STEP 5: protected call ----------
  $("btn-protected").addEventListener("click", function () {
    if (!state.token) { alert("Log in first to get a token."); return; }
    withLoading(this, async function () {
      var result = await api("/passkey", "GET", null, state.token);
      renderIO("io-protected", result,
        "Token verified by the JWT library (RS256 by kid against the live JWKS) before the handler ran. Here are your registered passkeys.");
      if (result.ok) setDone(5);
    });
  });

  function browserAuthnError(e) {
    if (e && e.name === "NotAllowedError") return "Passkey prompt was dismissed or timed out. Try again.";
    if (e && e.name === "InvalidStateError") return "This authenticator is already registered for this account.";
    return "WebAuthn error: " + (e && (e.message || e.name) || "unknown");
  }

  // Back-to-portfolio link. Prefer the configured URL; otherwise fall back to the referrer, but
  // only when the visitor actually arrived from a DIFFERENT origin — a same-origin referrer is
  // this demo itself, and linking back to it just reloads the page the visitor is already on.
  // With neither available the link is hidden rather than left pointing nowhere.
  var back = $("back-to-portfolio");
  if (back) {
    var target = "";
    if (PORTFOLIO_URL) {
      target = PORTFOLIO_URL;
    } else if (document.referrer) {
      try {
        if (new URL(document.referrer).origin !== location.origin) target = document.referrer;
      } catch (e) { /* an unparseable referrer is simply no referrer */ }
    }
    if (target) {
      back.setAttribute("href", target);
    } else {
      // Hide the link and the separator text that introduces it.
      var wrapper = back.parentNode;
      if (wrapper) wrapper.textContent = "Built by Kaushal Bhatt";
    }
  }
})();
