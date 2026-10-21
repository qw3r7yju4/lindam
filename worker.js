import { DurableObject } from "cloudflare:workers";

const AUTH_PASSWORD_ITERATIONS = 100000;
const AUTH_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_MFA_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const AUTH_SESSION_COOKIE = "linda_portal_session";
const CLIENT_SESSION_COOKIE = "linda_client_session";
const APPOINTMENT_TIME_ZONE = "America/New_York";

export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.activeMfaChallenges = new Set();
    this.activeOneTimeTokens = new Set();
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong"),
    );
  }

  async fetch(request) {
    const url = new URL(request.url);

    // Internal Durable Object storage API for Linda's Clinician Portal
    if (url.pathname.startsWith("/internal/")) {
      return this.handleInternalStorage(request, url);
    }

    // Standard WebRTC WebSocket Signaling
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const clientName = url.searchParams.get("name") || "Connected Participant";

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    const clientId = crypto.randomUUID();

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ clientId, clientName });

    const existing = this.ctx.getWebSockets().filter((ws) => ws !== server);
    const existingPeers = [];

    for (const peer of existing) {
      const peerAttachment = peer.deserializeAttachment();
      if (peerAttachment?.clientId) {
        existingPeers.push({
          peerId: peerAttachment.clientId,
          name: peerAttachment.clientName || "Connected Participant",
        });
      }
      peer.send(
        JSON.stringify({
          type: "peer-joined",
          peerId: clientId,
          name: clientName,
        }),
      );
    }

    server.send(
      JSON.stringify({
        type: "connected",
        peerId: clientId,
        peerCount: existing.length,
        peers: existingPeers,
      }),
    );

    return new Response(null, { status: 101, webSocket: client });
  }

  async getSessionUser(sessionToken) {
    if (typeof sessionToken !== "string" || !/^[a-f0-9]{64}$/i.test(sessionToken)) return null;
    const sessionHash = await hashSessionToken(sessionToken);
    const key = `auth:session:${sessionHash}`;
    const session = await this.ctx.storage.get(key);
    if (!session || session.expiresAt <= Date.now()) {
      if (session) await this.ctx.storage.delete(key);
      return null;
    }
    const users = (await this.ctx.storage.get("auth:users")) || [];
    const user = users.find((item) => item.id === session.userId && item.active);
    if (!user || !isValidEmail(user.email)) {
      await this.ctx.storage.delete(key);
      return null;
    }
    return user;
  }

  async handleInternalStorage(request, url) {
    const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };

    if (url.pathname === "/internal/auth/login" && request.method === "POST") {
      const body = await request.json();
      const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";
      const rateLimitKey = `auth:login:${body.clientIp || "unknown"}`;
      const rateLimit = (await this.ctx.storage.get(rateLimitKey)) || { count: 0, windowStartedAt: Date.now() };
      if (Date.now() - rateLimit.windowStartedAt > 15 * 60 * 1000) {
        rateLimit.count = 0;
        rateLimit.windowStartedAt = Date.now();
      }
      if (rateLimit.count >= 10) {
        return new Response(JSON.stringify({ error: "Too many login attempts. Try again in 15 minutes." }), {
          status: 429,
          headers: jsonHeaders,
        });
      }

      let users = (await this.ctx.storage.get("auth:users")) || [];
      let bootstrappedUser = false;
      if (users.length === 0) {
        if (body.expectedRole === "client") {
          return new Response(JSON.stringify({ error: "Invalid email or password." }), {
            status: 401,
            headers: jsonHeaders,
          });
        }
        const bootstrapUsername = typeof body.bootstrapUsername === "string"
          ? body.bootstrapUsername.trim().toLowerCase()
          : "";
        const bootstrapPassword = typeof body.bootstrapPassword === "string" ? body.bootstrapPassword : "";
        if (!bootstrapUsername || bootstrapPassword.length < 12 || bootstrapPassword.length > 256) {
          return new Response(JSON.stringify({
            error: "Portal setup is incomplete. Configure the ADMIN_BOOTSTRAP_USERNAME and ADMIN_BOOTSTRAP_PASSWORD secrets.",
          }), { status: 503, headers: jsonHeaders });
        }
        if (!/^[a-z0-9._-]{3,32}$/.test(bootstrapUsername) || username !== bootstrapUsername || password !== bootstrapPassword) {
          await hashPortalPassword(password.slice(0, 256), new Uint8Array(16), AUTH_PASSWORD_ITERATIONS);
          rateLimit.count += 1;
          await this.ctx.storage.put(rateLimitKey, rateLimit);
          return new Response(JSON.stringify({ error: "Invalid username or password." }), {
            status: 401,
            headers: jsonHeaders,
          });
        }

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const bootstrapEmail = typeof body.bootstrapEmail === "string"
          ? body.bootstrapEmail.trim().toLowerCase()
          : "";
        const suppliedBootstrapEmail = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const adminEmail = isValidEmail(bootstrapEmail) ? bootstrapEmail : suppliedBootstrapEmail;
        const admin = {
          id: crypto.randomUUID(),
          username: bootstrapUsername,
          displayName: "Portal Administrator",
          email: adminEmail,
          mfaMethod: "none",
          role: "admin",
          active: true,
          createdAt: new Date().toISOString(),
          salt: bytesToHex(salt),
          passwordHash: await hashPortalPassword(bootstrapPassword, salt, AUTH_PASSWORD_ITERATIONS),
          passwordIterations: AUTH_PASSWORD_ITERATIONS,
        };
        users = [admin];
        bootstrappedUser = true;
      }

      const matchingUsers = users.filter((item) =>
        item.active && (item.username === username || item.email?.toLowerCase() === username) &&
        (body.expectedRole === "client" ? item.role === "client" :
          body.expectedRole === "portal" ? ["admin", "staff"].includes(item.role) : true)
      );
      const user = matchingUsers.length === 1 ? matchingUsers[0] : null;
      const salt = user ? hexToBytes(user.salt) : new Uint8Array(16);
      const iterations = user?.passwordIterations || AUTH_PASSWORD_ITERATIONS;
      const passwordHash = bootstrappedUser
        ? user.passwordHash
        : await hashPortalPassword(password.slice(0, 256), salt, iterations);
      if (!user || password.length > 256 || !constantTimeEqual(passwordHash, user.passwordHash)) {
        rateLimit.count += 1;
        await this.ctx.storage.put(rateLimitKey, rateLimit);
        return new Response(JSON.stringify({ error: "Invalid username or password." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }

      const suppliedEmail = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      if (!isValidEmail(user.email) && !isValidEmail(suppliedEmail)) {
        return new Response(JSON.stringify({ error: "A valid email address is required for every portal account. Enter your email to continue." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      if (bootstrappedUser) {
        user.email = user.email || suppliedEmail;
        await this.ctx.storage.put("auth:users", users);
      }

      const mfaMethod = getPortalMfaMethod(user);
      if (mfaMethod === "none") {
        if (!user.email) {
          user.email = suppliedEmail;
          await this.ctx.storage.put("auth:users", users);
        }
        await this.ctx.storage.delete(rateLimitKey);
        const sessionToken = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
        const sessionHash = await hashSessionToken(sessionToken);
        const expiresAt = Date.now() + AUTH_SESSION_TTL_MS;
        await this.ctx.storage.put(`auth:session:${sessionHash}`, { userId: user.id, expiresAt });
        return new Response(JSON.stringify({
          sessionToken,
          expiresAt,
          user: publicPortalUser(user),
        }), { headers: jsonHeaders });
      }

      rateLimit.count += 1;
      await this.ctx.storage.put(rateLimitKey, rateLimit);
      if (mfaMethod === "authenticator" && !user.email) {
        user.email = suppliedEmail;
        await this.ctx.storage.put("auth:users", users);
      }
      const challengeId = crypto.randomUUID();
      const challengeCode = mfaMethod === "email"
        ? String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0")
        : "";
      const challenge = {
        userId: user.id,
        method: mfaMethod,
        expiresAt: Date.now() + AUTH_MFA_CHALLENGE_TTL_MS,
        attempts: 0,
        rateLimitKey,
      };
      const challengeEmail = isValidEmail(user.email) ? user.email : suppliedEmail;
      if (challengeCode) {
        challenge.codeHash = await hashMfaCode(challengeId, challengeCode);
      }
      if (mfaMethod === "email" && !isValidEmail(user.email)) {
        challenge.pendingEmail = suppliedEmail;
      }
      await this.ctx.storage.put(`auth:challenge:${challengeId}`, challenge);
      return new Response(JSON.stringify({
        challengeId,
        challengeCode,
        method: mfaMethod,
        maskedEmail: mfaMethod === "email" ? maskEmail(challengeEmail) : null,
        email: mfaMethod === "email" ? challengeEmail : null,
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/client-signup/request" && request.method === "POST") {
      const body = await request.json();
      const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
      const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const password = typeof body.password === "string" ? body.password : "";
      if (displayName.length < 2 || displayName.length > 80 ||
        !/^[a-z0-9._-]{3,32}$/.test(username) || !isValidEmail(email) ||
        password.length < 12 || password.length > 256) {
        return new Response(JSON.stringify({ error: "Enter a name, valid email and username, and password of 12-256 characters." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const ip = typeof body.clientIp === "string" ? body.clientIp : "unknown";
      const rateLimitKey = `auth:client-signup:rate:${ip}`;
      const rate = (await this.ctx.storage.get(rateLimitKey)) || { count: 0, windowStartedAt: Date.now() };
      if (Date.now() - rate.windowStartedAt > 60 * 60 * 1000) {
        rate.count = 0;
        rate.windowStartedAt = Date.now();
      }
      if (rate.count >= 5) {
        return new Response(JSON.stringify({ error: "Too many signup requests. Try again later." }), {
          status: 429,
          headers: jsonHeaders,
        });
      }
      rate.count += 1;
      await this.ctx.storage.put(rateLimitKey, rate);
      const users = (await this.ctx.storage.get("auth:users")) || [];
      if (users.some((user) => user.username === username || user.email?.toLowerCase() === email)) {
        return new Response(JSON.stringify({ error: "An account already uses that username or email. Sign in or request a password reset." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      if (users.length >= 1000) {
        return new Response(JSON.stringify({ error: "Online registration is temporarily unavailable. Contact the practice." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const pendingKey = `auth:client-signup:pending:${await hashSessionToken(email)}`;
      const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      await this.ctx.storage.put(pendingKey, {
        displayName,
        username,
        email,
        salt: bytesToHex(salt),
        passwordHash: await hashPortalPassword(password, salt, AUTH_PASSWORD_ITERATIONS),
        passwordIterations: AUTH_PASSWORD_ITERATIONS,
        codeHash: await hashMfaCode(email, code),
        expiresAt: Date.now() + AUTH_MFA_CHALLENGE_TTL_MS,
        attempts: 0,
      });
      return new Response(JSON.stringify({ ok: true, code, email }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/client-signup/verify" && request.method === "POST") {
      const body = await request.json();
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
        return new Response(JSON.stringify({ error: "Enter the email address and six-digit verification code." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const key = `auth:client-signup:pending:${await hashSessionToken(email)}`;
      const pending = await this.ctx.storage.get(key);
      if (!pending || pending.expiresAt <= Date.now() || pending.attempts >= 5) {
        if (pending) await this.ctx.storage.delete(key);
        return new Response(JSON.stringify({ error: "The verification code expired. Start signup again." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      if (!constantTimeEqual(await hashMfaCode(email, code), pending.codeHash)) {
        pending.attempts += 1;
        if (pending.attempts >= 5) await this.ctx.storage.delete(key);
        else await this.ctx.storage.put(key, pending);
        return new Response(JSON.stringify({ error: "Invalid verification code." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const users = (await this.ctx.storage.get("auth:users")) || [];
      if (users.some((user) => user.username === pending.username || user.email?.toLowerCase() === email)) {
        await this.ctx.storage.delete(key);
        return new Response(JSON.stringify({ error: "An account already uses that username or email. Sign in or request a password reset." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      if (users.length >= 1000) {
        await this.ctx.storage.delete(key);
        return new Response(JSON.stringify({ error: "Online registration is temporarily unavailable. Contact the practice." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const user = {
        id: crypto.randomUUID(),
        username: pending.username,
        displayName: pending.displayName,
        email,
        role: "client",
        mfaMethod: "none",
        active: true,
        createdAt: new Date().toISOString(),
        salt: pending.salt,
        passwordHash: pending.passwordHash,
        passwordIterations: pending.passwordIterations,
      };
      users.push(user);
      await this.ctx.storage.put("auth:users", users);
      await this.ctx.storage.delete(key);
      const sessionToken = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const sessionHash = await hashSessionToken(sessionToken);
      const expiresAt = Date.now() + AUTH_SESSION_TTL_MS;
      await this.ctx.storage.put(`auth:session:${sessionHash}`, { userId: user.id, expiresAt });
      return new Response(JSON.stringify({ sessionToken, expiresAt, user: publicPortalUser(user) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/cancel-mfa" && request.method === "POST") {
      const { challengeId } = await request.json();
      if (typeof challengeId === "string") await this.ctx.storage.delete(`auth:challenge:${challengeId}`);
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/verify-mfa" && request.method === "POST") {
      const body = await request.json();
      const challengeId = typeof body.challengeId === "string" ? body.challengeId : "";
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (!/^[0-9a-f-]{36}$/i.test(challengeId) || code.length > 12) {
        return new Response(JSON.stringify({ error: "Invalid or expired verification code." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const challengeKey = `auth:challenge:${challengeId}`;
      const challenge = await this.ctx.storage.get(challengeKey);
      if (!challenge || challenge.expiresAt <= Date.now() || challenge.attempts >= 5) {
        if (challenge) await this.ctx.storage.delete(challengeKey);
        return new Response(JSON.stringify({ error: "This verification code expired. Sign in again to request a new one." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      if (this.activeMfaChallenges.has(challengeId)) {
        return new Response(JSON.stringify({ error: "Code verification is already in progress." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      this.activeMfaChallenges.add(challengeId);
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const user = users.find((item) => item.id === challenge.userId && item.active);
      let valid = false;
      let verifiedTotpStep = null;
      if (user && challenge.method === "email" && /^\d{6}$/.test(code)) {
        valid = constantTimeEqual(await hashMfaCode(challengeId, code), challenge.codeHash);
      } else if (user && challenge.method === "authenticator" && user.totpSecret) {
        verifiedTotpStep = await verifyTotp(user.totpSecret, code);
        valid = verifiedTotpStep !== null && verifiedTotpStep > (user.totpLastUsedStep ?? -1);
      }
      if (!valid || !user) {
        challenge.attempts += 1;
        const throttle = challenge.rateLimitKey
          ? await this.ctx.storage.get(challenge.rateLimitKey)
          : null;
        if (throttle) {
          if (Date.now() - throttle.windowStartedAt > 15 * 60 * 1000) {
            throttle.count = 0;
            throttle.windowStartedAt = Date.now();
          }
          throttle.count += 1;
          await this.ctx.storage.put(challenge.rateLimitKey, throttle);
        }
        if (challenge.attempts >= 5 || throttle?.count >= 10) await this.ctx.storage.delete(challengeKey);
        else await this.ctx.storage.put(challengeKey, challenge);
        this.activeMfaChallenges.delete(challengeId);
        return new Response(JSON.stringify({ error: "Invalid verification code." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }

      if (challenge.pendingEmail) {
        user.email = challenge.pendingEmail;
      }
      if (verifiedTotpStep !== null) user.totpLastUsedStep = verifiedTotpStep;
      if (challenge.pendingEmail || verifiedTotpStep !== null) await this.ctx.storage.put("auth:users", users);
      this.activeMfaChallenges.delete(challengeId);
      await this.ctx.storage.delete(challengeKey);
      if (challenge.rateLimitKey) await this.ctx.storage.delete(challenge.rateLimitKey);
      const sessionToken = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const sessionHash = await hashSessionToken(sessionToken);
      const expiresAt = Date.now() + AUTH_SESSION_TTL_MS;
      await this.ctx.storage.put(`auth:session:${sessionHash}`, {
        userId: user.id,
        expiresAt,
      });
      return new Response(JSON.stringify({
        sessionToken,
        expiresAt,
        user: publicPortalUser(user),
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/setup" && request.method === "POST") {
      const { sessionToken } = await request.json();
      const user = await this.getSessionUser(sessionToken);
      if (!user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const target = users.find((item) => item.id === user.id);
      target.pendingTotpSecret = secret;
      target.pendingTotpExpiresAt = Date.now() + 10 * 60 * 1000;
      target.pendingTotpAttempts = 0;
      await this.ctx.storage.put("auth:users", users);
      const issuer = "Linda Milewski Portal";
      const label = `${issuer}:${user.username}`;
      const otpauthUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
      return new Response(JSON.stringify({ secret, otpauthUri }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/verify-setup" && request.method === "POST") {
      const { sessionToken, code } = await request.json();
      const user = await this.getSessionUser(sessionToken);
      if (!user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const target = users.find((item) => item.id === user.id);
      const verifiedStep = target?.pendingTotpSecret
        ? await verifyTotp(target.pendingTotpSecret, typeof code === "string" ? code.trim() : "")
        : null;
      if (!target?.pendingTotpSecret || target.pendingTotpExpiresAt <= Date.now() ||
        target.pendingTotpAttempts >= 5 || verifiedStep === null) {
        if (target?.pendingTotpSecret && verifiedStep === null) {
          target.pendingTotpAttempts += 1;
          if (target.pendingTotpAttempts >= 5) {
            delete target.pendingTotpSecret;
            delete target.pendingTotpExpiresAt;
            delete target.pendingTotpAttempts;
          }
          await this.ctx.storage.put("auth:users", users);
        }
        return new Response(JSON.stringify({ error: "Invalid code or authenticator setup expired. Start setup again." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      target.totpSecret = target.pendingTotpSecret;
      target.mfaMethod = "authenticator";
      target.totpLastUsedStep = verifiedStep;
      delete target.pendingTotpSecret;
      delete target.pendingTotpExpiresAt;
      delete target.pendingTotpAttempts;
      await this.ctx.storage.put("auth:users", users);
      return new Response(JSON.stringify({ ok: true, user: publicPortalUser(target) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/email/start" && request.method === "POST") {
      const body = await request.json();
      const user = await this.getSessionUser(body.sessionToken);
      if (!user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : user.email;
      if (!isValidEmail(email)) {
        return new Response(JSON.stringify({ error: "Enter a valid email address." }), { status: 400, headers: jsonHeaders });
      }
      const key = `auth:mfa-email:${user.id}`;
      const existing = await this.ctx.storage.get(key);
      if (existing?.resendAfter > Date.now()) {
        return new Response(JSON.stringify({ error: "Wait before requesting another email code." }), {
          status: 429,
          headers: jsonHeaders,
        });
      }
      const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
      await this.ctx.storage.put(key, {
        email,
        codeHash: await hashMfaCode(user.id, code),
        expiresAt: Date.now() + AUTH_MFA_CHALLENGE_TTL_MS,
        resendAfter: Date.now() + 60 * 1000,
        attempts: 0,
      });
      return new Response(JSON.stringify({ code, email, maskedEmail: maskEmail(email) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/email/cancel" && request.method === "POST") {
      const { sessionToken } = await request.json();
      const user = await this.getSessionUser(sessionToken);
      if (user) await this.ctx.storage.delete(`auth:mfa-email:${user.id}`);
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/email/verify" && request.method === "POST") {
      const body = await request.json();
      const user = await this.getSessionUser(body.sessionToken);
      if (!user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const key = `auth:mfa-email:${user.id}`;
      const pending = await this.ctx.storage.get(key);
      const code = typeof body.code === "string" ? body.code.trim() : "";
      if (!pending || pending.expiresAt <= Date.now() || pending.attempts >= 5) {
        if (pending) await this.ctx.storage.delete(key);
        return new Response(JSON.stringify({ error: "Email verification expired. Request a new code." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      if (!/^\d{6}$/.test(code) || !constantTimeEqual(await hashMfaCode(user.id, code), pending.codeHash)) {
        pending.attempts += 1;
        if (pending.attempts >= 5) await this.ctx.storage.delete(key);
        else await this.ctx.storage.put(key, pending);
        return new Response(JSON.stringify({ error: "Invalid email verification code." }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const target = users.find((item) => item.id === user.id && item.active);
      if (!target) return new Response(JSON.stringify({ error: "Account not found." }), { status: 404, headers: jsonHeaders });
      target.email = pending.email;
      target.mfaMethod = "email";
      await this.ctx.storage.put("auth:users", users);
      await this.ctx.storage.delete(key);
      return new Response(JSON.stringify({ ok: true, user: publicPortalUser(target) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/mfa/disable" && request.method === "POST") {
      const body = await request.json();
      const actor = await this.getSessionUser(body.sessionToken);
      if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const password = typeof body.password === "string" ? body.password : "";
      const passwordHash = await hashPortalPassword(password.slice(0, 256), hexToBytes(actor.salt), actor.passwordIterations);
      if (password.length > 256 || !constantTimeEqual(passwordHash, actor.passwordHash)) {
        return new Response(JSON.stringify({ error: "Current password is incorrect." }), { status: 400, headers: jsonHeaders });
      }
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const target = users.find((item) => item.id === actor.id && item.active);
      target.mfaMethod = "none";
      delete target.pendingTotpSecret;
      delete target.pendingTotpExpiresAt;
      delete target.pendingTotpAttempts;
      await this.ctx.storage.put("auth:users", users);
      await this.ctx.storage.delete(`auth:mfa-email:${target.id}`);
      const currentSessionHash = await hashSessionToken(body.sessionToken);
      const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
      for (const [key, session] of sessions) {
        if (session.userId === target.id && key !== `auth:session:${currentSessionHash}`) {
          await this.ctx.storage.delete(key);
        }
      }
      return new Response(JSON.stringify({ ok: true, user: publicPortalUser(target) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/session" && request.method === "POST") {
      const { sessionToken } = await request.json();
      const user = await this.getSessionUser(sessionToken);
      if (!user) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      return new Response(JSON.stringify({ user: publicPortalUser(user) }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/account-email" && request.method === "POST") {
      const body = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid email update request." }), { status: 400, headers: jsonHeaders });
      }
      const actor = await this.getSessionUser(body.sessionToken);
      if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const targetId = typeof body.userId === "string" ? body.userId : "";
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const target = users.find((item) => item.id === targetId && item.active);
      if (!target || !isValidEmail(email)) {
        return new Response(JSON.stringify({ error: target ? "Enter a valid email address." : "Account not found." }), {
          status: target ? 400 : 404,
          headers: jsonHeaders,
        });
      }
      if (users.some((item) => item.id !== target.id && item.email?.toLowerCase() === email)) {
        return new Response(JSON.stringify({ error: "That email address is already assigned to another account." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      if (target.email?.toLowerCase() === email) {
        return new Response(JSON.stringify({ ok: true, unchanged: true }), { headers: jsonHeaders });
      }
      const rateKey = `auth:email-change:rate:${actor.id}`;
      const rate = (await this.ctx.storage.get(rateKey)) || { count: 0, windowStartedAt: Date.now() };
      if (Date.now() - rate.windowStartedAt > 60 * 60 * 1000) {
        rate.count = 0;
        rate.windowStartedAt = Date.now();
      }
      if (rate.count >= 5) {
        return new Response(JSON.stringify({ error: "Too many email change requests. Try again later." }), {
          status: 429,
          headers: jsonHeaders,
        });
      }
      rate.count += 1;
      await this.ctx.storage.put(rateKey, rate);
      const pending = await this.ctx.storage.list({ prefix: "auth:email-change:token:" });
      for (const [key, change] of pending) {
        if (change.userId === target.id) await this.ctx.storage.delete(key);
      }
      const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      await this.ctx.storage.put(`auth:email-change:token:${await hashSessionToken(token)}`, {
        userId: target.id,
        email,
        currentEmail: target.email,
        expiresAt: Date.now() + 30 * 60 * 1000,
      });
      return new Response(JSON.stringify({
        ok: true,
        token,
        verificationEmail: target.email,
        displayName: target.displayName,
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/account-email/complete" && request.method === "POST") {
      const body = await request.json();
      const token = typeof body?.token === "string" ? body.token : "";
      if (!/^[a-f0-9]{64}$/i.test(token)) {
        return new Response(JSON.stringify({ error: "This email confirmation link is invalid or expired." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const tokenHash = await hashSessionToken(token);
      if (this.activeOneTimeTokens.has(tokenHash)) {
        return new Response(JSON.stringify({ error: "This email confirmation link is already being used." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      this.activeOneTimeTokens.add(tokenHash);
      try {
        const key = `auth:email-change:token:${tokenHash}`;
        const change = await this.ctx.storage.get(key);
        if (!change || change.expiresAt <= Date.now()) {
          if (change) await this.ctx.storage.delete(key);
          return new Response(JSON.stringify({ error: "This email confirmation link is invalid or expired." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const users = (await this.ctx.storage.get("auth:users")) || [];
        const target = users.find((item) => item.id === change.userId && item.active);
        if (!target || target.email?.toLowerCase() !== change.currentEmail?.toLowerCase() ||
          !isValidEmail(change.email) ||
          users.some((item) => item.id !== change.userId && item.email?.toLowerCase() === change.email)) {
          await this.ctx.storage.delete(key);
          return new Response(JSON.stringify({ error: "That email address can no longer be assigned. Request a new change." }), {
            status: 409,
            headers: jsonHeaders,
          });
        }
        target.email = change.email;
        await this.ctx.storage.put("auth:users", users);
        const pending = await this.ctx.storage.list({ prefix: "auth:email-change:token:" });
        for (const [pendingKey, item] of pending) {
          if (item.userId === target.id) await this.ctx.storage.delete(pendingKey);
        }
        const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
        for (const [sessionKey, session] of sessions) {
          if (session.userId === target.id) await this.ctx.storage.delete(sessionKey);
        }
        const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
        for (const [challengeKey, challenge] of challenges) {
          if (challenge.userId === target.id) await this.ctx.storage.delete(challengeKey);
        }
        await this.ctx.storage.delete(`auth:mfa-email:${target.id}`);
        return new Response(JSON.stringify({ ok: true, user: publicPortalUser(target) }), { headers: jsonHeaders });
      } finally {
        this.activeOneTimeTokens.delete(tokenHash);
      }
    }

    if (url.pathname === "/internal/auth/account-email/cancel" && request.method === "POST") {
      const body = await request.json();
      if (typeof body?.token === "string" && /^[a-f0-9]{64}$/i.test(body.token)) {
        await this.ctx.storage.delete(`auth:email-change:token:${await hashSessionToken(body.token)}`);
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/directory" && request.method === "POST") {
      const body = await request.json();
      const actor = await this.getSessionUser(body.sessionToken);
      if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const users = (await this.ctx.storage.get("auth:users")) || [];
      return new Response(JSON.stringify({
        users: users.filter((user) => user.active).map(({ id, username, displayName, email, role }) =>
          ({ id, username, displayName, email: email || "", role })
        ),
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/password-reset/create" && request.method === "POST") {
      const body = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid password reset request." }), { status: 400, headers: jsonHeaders });
      }
      const actor = body.sessionToken ? await this.getSessionUser(body.sessionToken) : null;
      if (body.sessionToken && !actor) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      const resetLimitKey = `auth:password-reset:rate:${body.clientIp || "unknown"}`;
      const rateLimit = (await this.ctx.storage.get(resetLimitKey)) || { count: 0, windowStartedAt: Date.now() };
      if (Date.now() - rateLimit.windowStartedAt > 60 * 60 * 1000) {
        rateLimit.count = 0;
        rateLimit.windowStartedAt = Date.now();
      }
      if (rateLimit.count >= 10) {
        return new Response(JSON.stringify({ error: "Too many reset requests. Try again later." }), {
          status: 429,
          headers: jsonHeaders,
        });
      }
      rateLimit.count += 1;
      await this.ctx.storage.put(resetLimitKey, rateLimit);
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const requestedEmail = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      const target = actor
        ? users.find((item) => item.active && (item.id === body.userId ||
          (!body.userId && item.email?.toLowerCase() === requestedEmail)))
        : users.find((item) => item.active && item.email?.toLowerCase() === requestedEmail);
      if (!target || !isValidEmail(target.email)) {
        if (actor) {
          return new Response(JSON.stringify({ error: target ? "The account has no valid email address." : "Account not found." }), {
            status: target ? 400 : 404,
            headers: jsonHeaders,
          });
        }
        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      }
      const resets = await this.ctx.storage.list({ prefix: "auth:password-reset:token:" });
      for (const [key, reset] of resets) {
        if (reset.userId === target.id) await this.ctx.storage.delete(key);
      }
      const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const tokenHash = await hashSessionToken(token);
      await this.ctx.storage.put(`auth:password-reset:token:${tokenHash}`, {
        userId: target.id,
        expiresAt: Date.now() + 30 * 60 * 1000,
      });
      return new Response(JSON.stringify({
        ok: true,
        token,
        email: target.email,
        displayName: target.displayName,
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/password-reset/complete" && request.method === "POST") {
      const body = await request.json();
      const token = typeof body?.token === "string" ? body.token : "";
      const password = typeof body?.password === "string" ? body.password : "";
      if (!/^[a-f0-9]{64}$/i.test(token) || password.length < 12 || password.length > 256) {
        return new Response(JSON.stringify({ error: "Use a valid reset link and a password of 12-256 characters." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const tokenHash = await hashSessionToken(token);
      if (this.activeOneTimeTokens.has(tokenHash)) {
        return new Response(JSON.stringify({ error: "This password reset link is already being used." }), {
          status: 409,
          headers: jsonHeaders,
        });
      }
      this.activeOneTimeTokens.add(tokenHash);
      try {
        const key = `auth:password-reset:token:${tokenHash}`;
        const reset = await this.ctx.storage.get(key);
        if (!reset || reset.expiresAt <= Date.now()) {
          if (reset) await this.ctx.storage.delete(key);
          return new Response(JSON.stringify({ error: "This password reset link is invalid or expired. Request a new one." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const users = (await this.ctx.storage.get("auth:users")) || [];
        const target = users.find((item) => item.id === reset.userId && item.active);
        if (!target) {
          await this.ctx.storage.delete(key);
          return new Response(JSON.stringify({ error: "This password reset link is invalid or expired. Request a new one." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        target.salt = bytesToHex(salt);
        target.passwordHash = await hashPortalPassword(password, salt, AUTH_PASSWORD_ITERATIONS);
        target.passwordIterations = AUTH_PASSWORD_ITERATIONS;
        await this.ctx.storage.put("auth:users", users);
        const resets = await this.ctx.storage.list({ prefix: "auth:password-reset:token:" });
        for (const [resetKey, item] of resets) {
          if (item.userId === target.id) await this.ctx.storage.delete(resetKey);
        }
        const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
        for (const [sessionKey, session] of sessions) {
          if (session.userId === target.id) await this.ctx.storage.delete(sessionKey);
        }
        const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
        for (const [challengeKey, challenge] of challenges) {
          if (challenge.userId === target.id) await this.ctx.storage.delete(challengeKey);
        }
        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      } finally {
        this.activeOneTimeTokens.delete(tokenHash);
      }
    }

    if (url.pathname === "/internal/auth/password-reset/cancel" && request.method === "POST") {
      const body = await request.json();
      if (typeof body?.token === "string" && /^[a-f0-9]{64}$/i.test(body.token)) {
        await this.ctx.storage.delete(`auth:password-reset:token:${await hashSessionToken(body.token)}`);
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/availability") {
      const schedules = (await this.ctx.storage.get("availability")) || {};
      if (request.method === "GET") {
        const users = (await this.ctx.storage.get("auth:users")) || [];
        return new Response(JSON.stringify({
          schedules: users.filter((user) => user.active).map((user) => ({
            userId: user.id,
            displayName: user.displayName,
            email: user.email,
            weekdays: schedules[user.id]?.weekdays || {},
            exceptions: schedules[user.id]?.exceptions || [],
          })),
        }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const body = await request.json();
        const actor = await this.getSessionUser(body.sessionToken);
        if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
        if (!isValidAvailability(body.availability)) {
          return new Response(JSON.stringify({ error: "Availability contains an invalid day, time range, or exception." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        schedules[actor.id] = body.availability;
        await this.ctx.storage.put("availability", schedules);
        return new Response(JSON.stringify({ ok: true, availability: schedules[actor.id] }), { headers: jsonHeaders });
      }
    }

    if (url.pathname === "/internal/client-availability" && request.method === "GET") {
      const date = url.searchParams.get("date") || "";
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return new Response(JSON.stringify({ error: "Choose an appointment date." }), { status: 400, headers: jsonHeaders });
      }
      const [year, month, day] = date.split("-").map(Number);
      if (new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) !== date) {
        return new Response(JSON.stringify({ error: "Choose a valid appointment date." }), { status: 400, headers: jsonHeaders });
      }
      const easternParts = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
        timeZone: APPOINTMENT_TIME_ZONE,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).formatToParts(new Date()).filter((part) => part.type !== "literal")
        .map((part) => [part.type, part.value]));
      const easternDate = `${easternParts.year}-${easternParts.month}-${easternParts.day}`;
      const requestedDay = Date.UTC(year, month - 1, day);
      const today = Date.UTC(...easternDate.split("-").map(Number).map((value, index) =>
        index === 1 ? value - 1 : value
      ));
      if (requestedDay < today || requestedDay > today + 90 * 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: "Choose a date within the next 90 days." }), { status: 400, headers: jsonHeaders });
      }
      const schedules = (await this.ctx.storage.get("availability")) || {};
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      const weekday = String(new Date(Date.UTC(year, month - 1, day)).getUTCDay());
      const services = [
        { name: "Free 15-Minute Consultation", duration: 15 },
        { name: "Individual Psychotherapy", duration: 50 },
        { name: "Anxiety & Burnout Recovery", duration: 50 },
        { name: "Life Transitions & Relationships", duration: 50 },
      ];
      const requestedService = url.searchParams.get("service") || "Individual Psychotherapy";
      const selectedService = services.find((service) => service.name === requestedService);
      if (!selectedService) {
        return new Response(JSON.stringify({ error: "Choose a valid appointment type." }), { status: 400, headers: jsonHeaders });
      }
      const clinicians = users.filter((user) => user.active && ["admin", "staff"].includes(user.role) &&
        isValidEmail(user.email) && isValidAvailability(schedules[user.id])).map((user) => {
        const schedule = schedules[user.id];
        const exception = schedule.exceptions?.find((item) => item.date === date);
        const intervals = exception ? exception.intervals : schedule.weekdays?.[weekday] || [];
        const slots = new Set();
        for (const interval of intervals) {
            const toMinutes = (time) => Number(time.slice(0, 2)) * 60 + Number(time.slice(3));
            const intervalStart = toMinutes(interval.start);
            const intervalEnd = toMinutes(interval.end);
            for (let start = Math.ceil(intervalStart / 15) * 15;
              start + selectedService.duration <= intervalEnd; start += 15) {
              if (start <= 23 * 60 + 59) {
                const time = `${String(Math.floor(start / 60)).padStart(2, "0")}:${String(start % 60).padStart(2, "0")}`;
                const reason = getAppointmentAvailabilityError({
                  hostUserId: user.id,
                  date,
                  time,
                  timeZone: APPOINTMENT_TIME_ZONE,
                  duration: selectedService.duration,
                }, schedule, appointments);
                if (!reason) slots.add(time);
              }
            }
        }
        return {
          id: user.id,
          name: user.displayName,
          services,
          slots: [...slots].sort(),
        };
      }).filter((clinician) => clinician.slots.length > 0);
      return new Response(JSON.stringify({ date, clinicians }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/client/appointments") {
      const body = request.method === "POST" ? await request.json() : {};
      const sessionToken = request.method === "POST"
        ? body.sessionToken
        : request.headers.get("X-Client-Session");
      const client = await this.getSessionUser(sessionToken);
      if (!client || client.role !== "client") {
        return new Response(JSON.stringify({ error: "Client account sign-in required." }), { status: 401, headers: jsonHeaders });
      }
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      if (request.method === "GET") {
        const userAppointments = appointments.filter((appointment) => appointment.clientUserId === client.id)
          .map(({ id, clientName, date, time, timeZone, duration, service, status, roomCode }) =>
            ({ id, clientName, date, time, timeZone, duration, service, status, roomCode })
          );
        return new Response(JSON.stringify({ appointments: userAppointments }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const service = ["Free 15-Minute Consultation", "Individual Psychotherapy",
          "Anxiety & Burnout Recovery", "Life Transitions & Relationships"].includes(body.service)
          ? body.service
          : "";
        const duration = service === "Free 15-Minute Consultation" ? 15 : 50;
        const appointment = {
          id: crypto.randomUUID(),
          clientUserId: client.id,
          clientName: client.displayName,
          clientEmail: client.email,
          hostUserId: typeof body.hostUserId === "string" ? body.hostUserId : "",
          date: typeof body.date === "string" ? body.date : "",
          time: typeof body.time === "string" ? body.time : "",
          timeZone: APPOINTMENT_TIME_ZONE,
          duration,
          service,
          roomCode: `LINDA-${100 + crypto.getRandomValues(new Uint32Array(1))[0] % 900}`,
          reminderEnabled: true,
          status: "Awaiting Confirmation",
          notes: "",
        };
        if (!service) {
          return new Response(JSON.stringify({ error: "Choose a valid appointment type." }), { status: 400, headers: jsonHeaders });
        }
        const users = (await this.ctx.storage.get("auth:users")) || [];
        const host = users.find((user) => user.id === appointment.hostUserId && user.active &&
          ["admin", "staff"].includes(user.role) && isValidEmail(user.email));
        const schedules = (await this.ctx.storage.get("availability")) || {};
        const reason = getAppointmentAvailabilityError(appointment, schedules[appointment.hostUserId], appointments);
        if (!host || reason) {
          return new Response(JSON.stringify({ error: !host ? "That clinician is no longer available. Choose another time." : reason }), {
            status: 409,
            headers: jsonHeaders,
          });
        }
        if (appointments.some((item) => item.roomCode === appointment.roomCode)) {
          appointment.roomCode = `LINDA-${Math.floor(100 + Math.random() * 900)}`;
        }
        appointments.push(appointment);
        await this.ctx.storage.put("appointments", appointments);
        return new Response(JSON.stringify({
          appointment: {
            id: appointment.id,
            date: appointment.date,
            time: appointment.time,
            timeZone: appointment.timeZone,
            duration: appointment.duration,
            service: appointment.service,
            status: appointment.status,
          },
          host: { displayName: host.displayName, email: host.email },
        }), { status: 201, headers: jsonHeaders });
      }
    }

    if (url.pathname === "/internal/auth/change-password" && request.method === "POST") {
      const { sessionToken, currentPassword, newPassword } = await request.json();
      const actor = await this.getSessionUser(sessionToken);
      if (!actor) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      if (typeof newPassword !== "string" || newPassword.length < 12 || newPassword.length > 256) {
        return new Response(JSON.stringify({ error: "New passwords must be 12-256 characters long." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const currentHash = await hashPortalPassword(
        typeof currentPassword === "string" ? currentPassword : "",
        hexToBytes(actor.salt),
        actor.passwordIterations,
      );
      if (!constantTimeEqual(currentHash, actor.passwordHash)) {
        return new Response(JSON.stringify({ error: "Current password is incorrect." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }

      const users = (await this.ctx.storage.get("auth:users")) || [];
      const user = users.find((item) => item.id === actor.id);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      user.salt = bytesToHex(salt);
      user.passwordHash = await hashPortalPassword(newPassword, salt, AUTH_PASSWORD_ITERATIONS);
      user.passwordIterations = AUTH_PASSWORD_ITERATIONS;
      await this.ctx.storage.put("auth:users", users);

      const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
      for (const [key, session] of sessions) {
        if (session.userId === user.id) await this.ctx.storage.delete(key);
      }
      const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
      for (const [key, challenge] of challenges) {
        if (challenge.userId === user.id) await this.ctx.storage.delete(key);
      }
      const newSessionToken = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const sessionHash = await hashSessionToken(newSessionToken);
      const expiresAt = Date.now() + AUTH_SESSION_TTL_MS;
      await this.ctx.storage.put(`auth:session:${sessionHash}`, { userId: user.id, expiresAt });
      return new Response(JSON.stringify({
        sessionToken: newSessionToken,
        user: publicPortalUser(user),
      }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/logout" && request.method === "POST") {
      const { sessionToken } = await request.json();
      if (typeof sessionToken === "string" && sessionToken) {
        const sessionHash = await hashSessionToken(sessionToken);
        await this.ctx.storage.delete(`auth:session:${sessionHash}`);
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/auth/users") {
      const body = request.method === "GET"
        ? { sessionToken: request.headers.get("X-Portal-Session") }
        : await request.json();
      const actor = await this.getSessionUser(body.sessionToken);
      if (!actor || !["admin", "staff"].includes(actor.role)) {
        return new Response(JSON.stringify({ error: "Clinician account access required." }), {
          status: actor ? 403 : 401,
          headers: jsonHeaders,
        });
      }

      const users = (await this.ctx.storage.get("auth:users")) || [];
      if (request.method === "GET") {
        const visibleUsers = users.filter((user) => user.active && (actor.role === "admin" || user.role === "client"));
        return new Response(JSON.stringify({ users: visibleUsers.map(publicPortalUser) }), {
          headers: jsonHeaders,
        });
      }

      if (request.method === "POST") {
        const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
        const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
        const password = typeof body.password === "string" ? body.password : "";
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
        const role = body.role;
        if (!/^[a-z0-9._-]{3,32}$/.test(username) || !displayName || displayName.length > 80 ||
          !isValidEmail(email) || password.length < 12 || password.length > 256 ||
          !["admin", "staff", "client"].includes(role) || (actor.role === "staff" && role !== "client")) {
          return new Response(JSON.stringify({
            error: actor.role === "staff"
              ? "Staff accounts can create appointment client accounts only."
              : "Enter a valid email, 3-32 character username, display name, password of at least 12 characters, and valid role.",
          }), { status: 400, headers: jsonHeaders });
        }
        if (users.some((item) => item.username === username || item.email?.toLowerCase() === email)) {
          return new Response(JSON.stringify({ error: "That username or email address is already in use." }), {
            status: 409,
            headers: jsonHeaders,
          });
        }
        if (users.length >= 1000) {
          return new Response(JSON.stringify({ error: "The account limit has been reached." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const user = {
          id: crypto.randomUUID(),
          username,
          displayName,
          email,
          role,
          mfaMethod: "none",
          active: true,
          createdAt: new Date().toISOString(),
          salt: bytesToHex(salt),
          passwordHash: await hashPortalPassword(password, salt, AUTH_PASSWORD_ITERATIONS),
          passwordIterations: AUTH_PASSWORD_ITERATIONS,
        };
        users.push(user);
        await this.ctx.storage.put("auth:users", users);
        return new Response(JSON.stringify({ user: publicPortalUser(user) }), { status: 201, headers: jsonHeaders });
      }

      if (request.method === "PATCH") {
        const id = url.searchParams.get("id");
        const target = users.find((item) => item.id === id && item.active);
        if (!target) {
          return new Response(JSON.stringify({ error: "Select another active account to reset." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        if (actor.role === "staff" && target.role !== "client") {
          return new Response(JSON.stringify({ error: "Staff can manage appointment client accounts only." }), {
            status: 403,
            headers: jsonHeaders,
          });
        }
        if (body.action === "reset-mfa") {
          const email = target.email;
          if (typeof body.email === "string" && body.email.trim().toLowerCase() !== email?.toLowerCase()) {
            return new Response(JSON.stringify({ error: "Email changes require confirmation from the current account email." }), {
              status: 400,
              headers: jsonHeaders,
            });
          }
          if (!isValidEmail(email)) {
            return new Response(JSON.stringify({ error: "Enter a valid email address." }), {
              status: 400,
              headers: jsonHeaders,
            });
          }
          if (users.some((item) => item.id !== target.id && item.email?.toLowerCase() === email)) {
            return new Response(JSON.stringify({ error: "That email address is already assigned to another account." }), {
              status: 409,
              headers: jsonHeaders,
            });
          }
          target.email = email;
          target.mfaMethod = "email";
          delete target.totpSecret;
          delete target.totpLastUsedStep;
          delete target.pendingTotpSecret;
          delete target.pendingTotpExpiresAt;
          delete target.pendingTotpAttempts;
          await this.ctx.storage.put("auth:users", users);
          const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
          for (const [key, session] of sessions) {
            if (session.userId === target.id) await this.ctx.storage.delete(key);
          }
          const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
          for (const [key, challenge] of challenges) {
            if (challenge.userId === target.id) await this.ctx.storage.delete(key);
          }
          return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
        }
        if (body.action === "update-email") {
          return new Response(JSON.stringify({ error: "Email changes require confirmation from the current account email." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        if (body.action === "disable-mfa") {
          if (target.id === actor.id) {
            return new Response(JSON.stringify({ error: "Use Security & MFA to turn off your own MFA." }), {
              status: 400,
              headers: jsonHeaders,
            });
          }
          target.mfaMethod = "none";
          delete target.pendingTotpSecret;
          delete target.pendingTotpExpiresAt;
          delete target.pendingTotpAttempts;
          await this.ctx.storage.put("auth:users", users);
          const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
          for (const [key, session] of sessions) {
            if (session.userId === target.id) await this.ctx.storage.delete(key);
          }
          const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
          for (const [key, challenge] of challenges) {
            if (challenge.userId === target.id) await this.ctx.storage.delete(key);
          }
          await this.ctx.storage.delete(`auth:mfa-email:${target.id}`);
          return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
        }
        if (target.id === actor.id) {
          return new Response(JSON.stringify({ error: "You cannot reset your own password here." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        if (typeof body.password !== "string" || body.password.length < 12 || body.password.length > 256) {
          return new Response(JSON.stringify({ error: "Temporary passwords must be 12-256 characters long." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        target.salt = bytesToHex(salt);
        target.passwordHash = await hashPortalPassword(body.password, salt, AUTH_PASSWORD_ITERATIONS);
        target.passwordIterations = AUTH_PASSWORD_ITERATIONS;
        await this.ctx.storage.put("auth:users", users);
        const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
        for (const [key, session] of sessions) {
          if (session.userId === target.id) await this.ctx.storage.delete(key);
        }
        const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
        for (const [key, challenge] of challenges) {
          if (challenge.userId === target.id) await this.ctx.storage.delete(key);
        }
        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      }

      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        const target = users.find((item) => item.id === id && item.active);
        if (!target) {
          return new Response(JSON.stringify({ error: "Account not found." }), { status: 404, headers: jsonHeaders });
        }
        if (actor.role === "staff" && target.role !== "client") {
          return new Response(JSON.stringify({ error: "Staff can manage appointment client accounts only." }), {
            status: 403,
            headers: jsonHeaders,
          });
        }
        if (target.id === actor.id) {
          return new Response(JSON.stringify({ error: "You cannot deactivate your own account." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        if (target.role === "admin" && users.filter((item) => item.active && item.role === "admin").length <= 1) {
          return new Response(JSON.stringify({ error: "At least one active administrator is required." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        target.active = false;
        await this.ctx.storage.put("auth:users", users);
        const sessions = await this.ctx.storage.list({ prefix: "auth:session:" });
        for (const [key, session] of sessions) {
          if (session.userId === target.id) await this.ctx.storage.delete(key);
        }
        const challenges = await this.ctx.storage.list({ prefix: "auth:challenge:" });
        for (const [key, challenge] of challenges) {
          if (challenge.userId === target.id) await this.ctx.storage.delete(key);
        }
        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      }
    }

    if (url.pathname === "/internal/reminder-recipients" && request.method === "GET") {
      const users = (await this.ctx.storage.get("auth:users")) || [];
      const recipients = users
        .filter((user) => user.active && ["admin", "staff"].includes(user.role) && isValidEmail(user.email))
        .map((user) => ({ id: user.id, displayName: user.displayName }));
      return new Response(JSON.stringify({ recipients }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/reminders/claim" && request.method === "POST") {
      const body = await request.json();
      const now = Number(body.now);
      if (!Number.isFinite(now)) {
        return new Response(JSON.stringify({ error: "A valid reminder time is required." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const claims = await this.ctx.storage.transaction(async (transaction) => {
        const appointments = (await transaction.get("appointments")) || [];
        const users = (await transaction.get("auth:users")) || [];
        const claimsToSend = [];
        for (const appointment of appointments) {
          if (appointment.reminderEnabled === false ||
            ["Completed", "Reschedule Requested"].includes(appointment.status) ||
            appointment.reminderClaim?.expiresAt > now) continue;
          const startsAt = getAppointmentStartTime(appointment);
          if (startsAt === null || startsAt <= now || startsAt - 30 * 60 * 1000 > now) continue;

          const host = users.find((user) => user.id === appointment.hostUserId && user.active && isValidEmail(user.email));
          if (!host || !isValidEmail(appointment.clientEmail)) continue;
          const state = appointment.reminderState || {};
          const targets = [];
          for (const [key, recipient] of [
            ["client", { email: appointment.clientEmail, name: appointment.clientName }],
            ["staff", { email: host?.email, name: host?.displayName }],
          ]) {
            if (!isValidEmail(recipient.email)) continue;
            const targetState = state[key] || {};
            if (targetState.sentAt || targetState.attempts >= 3 ||
              (targetState.nextAttemptAt && targetState.nextAttemptAt > now)) continue;
            targets.push({ key, email: recipient.email, name: recipient.name || "" });
          }
          if (targets.length === 0) continue;

          const claimToken = crypto.randomUUID();
          appointment.reminderClaim = { token: claimToken, expiresAt: now + 5 * 60 * 1000 };
          claimsToSend.push({
            id: appointment.id,
            claimToken,
            clientName: appointment.clientName,
            date: appointment.date,
            time: appointment.time,
            roomCode: appointment.roomCode,
            targets,
          });
          if (claimsToSend.length >= 10) break;
        }
        if (claimsToSend.length > 0) await transaction.put("appointments", appointments);
        return claimsToSend;
      });
      return new Response(JSON.stringify({ claims }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/reminders/complete" && request.method === "POST") {
      const body = await request.json();
      const { id, claimToken, recipient, sent } = body;
      if (typeof id !== "string" || typeof claimToken !== "string" ||
        !["client", "staff"].includes(recipient) || typeof sent !== "boolean") {
        return new Response(JSON.stringify({ error: "Invalid reminder completion request." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      const appointment = appointments.find((item) => item.id === id);
      if (!appointment || appointment.reminderClaim?.token !== claimToken) {
        return new Response(JSON.stringify({ error: "Reminder claim expired." }), { status: 409, headers: jsonHeaders });
      }
      appointment.reminderState ||= {};
      const state = appointment.reminderState[recipient] || { attempts: 0 };
      state.attempts = (state.attempts || 0) + 1;
      if (sent) {
        state.sentAt = new Date().toISOString();
        delete state.nextAttemptAt;
      } else {
        state.lastAttemptAt = new Date().toISOString();
        if (state.attempts < 3) state.nextAttemptAt = Date.now() + 5 * 60 * 1000;
      }
      appointment.reminderState[recipient] = state;
      await this.ctx.storage.put("appointments", appointments);
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/internal/reminders/release" && request.method === "POST") {
      const body = await request.json();
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      const appointment = appointments.find((item) => item.id === body.id);
      if (appointment?.reminderClaim?.token === body.claimToken) {
        delete appointment.reminderClaim;
        await this.ctx.storage.put("appointments", appointments);
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    // 1. Appointments CRUD
    if (url.pathname === "/internal/appointments") {
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      if (request.method === "GET") {
        return new Response(JSON.stringify({ appointments }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const body = await request.json();
        if (Array.isArray(body.appointments)) {
          const users = (await this.ctx.storage.get("auth:users")) || [];
          const invalidReminder = body.appointments.find((appointment) =>
            appointment.reminderEnabled === true && !isAppointmentReminderConfigured(appointment, users)
          );
          if (invalidReminder) {
            return new Response(JSON.stringify({
              error: "Each enabled appointment reminder needs a valid client email, active hosting staff member, and valid appointment time.",
            }), { status: 400, headers: jsonHeaders });
          }
          const mergedAppointments = body.appointments.map((item) => {
            const existing = appointments.find((appointment) => appointment.id === item.id);
            return mergeAppointmentReminderState(existing, item);
          });
          await this.ctx.storage.put("appointments", mergedAppointments);
          return new Response(JSON.stringify({ appointments: mergedAppointments }), { headers: jsonHeaders });
        }
        const item = body.appointment;
        if (item && isValidEmail(item.clientEmail)) {
          const existing = appointments.find((appointment) => appointment.id === item.id);
          const unchangedSlot = existing && existing.hostUserId === item.hostUserId &&
            existing.date === item.date && existing.time === item.time &&
            Number(existing.duration || 50) === Number(item.duration || 50);
          if (!unchangedSlot) {
            const schedules = (await this.ctx.storage.get("availability")) || {};
            const reason = getAppointmentAvailabilityError(item, schedules[item.hostUserId], appointments, item.id);
            if (reason) {
              return new Response(JSON.stringify({ error: reason }), { status: 400, headers: jsonHeaders });
            }
          }
        }
        if (item?.reminderEnabled === true) {
          const users = (await this.ctx.storage.get("auth:users")) || [];
          if (!isAppointmentReminderConfigured(item, users)) {
            return new Response(JSON.stringify({
              error: "An enabled reminder needs a valid client email, active hosting staff member, and valid appointment time.",
            }), { status: 400, headers: jsonHeaders });
          }
        }
        const idx = appointments.findIndex((a) => a.id === item.id);
        if (idx >= 0) {
          appointments[idx] = mergeAppointmentReminderState(appointments[idx], item);
        } else {
          appointments.push(item);
        }
        await this.ctx.storage.put("appointments", appointments);
        return new Response(JSON.stringify({ appointments }), { headers: jsonHeaders });
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        const appointment = appointments.find((item) => item.id === id);
        if (!appointment) {
          return new Response(JSON.stringify({ error: "Appointment not found." }), { status: 404, headers: jsonHeaders });
        }
        appointment.status = "Completed";
        appointment.completedAt ||= new Date().toISOString();
        appointment.reminderEnabled = false;
        delete appointment.reminderClaim;
        await this.ctx.storage.put("appointments", appointments);
        return new Response(JSON.stringify({ appointments }), { headers: jsonHeaders });
      }
    }

    // 2. Clinical Hours Tracker CRUD
    if (url.pathname === "/internal/hours") {
      const hours = (await this.ctx.storage.get("hours")) || [];
      if (request.method === "GET") {
        return new Response(JSON.stringify({ hours }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const body = await request.json();
        const entry = body.entry;
        const idx = hours.findIndex((h) => h.id === entry.id);
        if (idx >= 0) {
          hours[idx] = entry;
        } else {
          hours.unshift(entry);
        }
        await this.ctx.storage.put("hours", hours);
        return new Response(JSON.stringify({ hours }), { headers: jsonHeaders });
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        const filtered = hours.filter((h) => h.id !== id);
        await this.ctx.storage.put("hours", filtered);
        return new Response(JSON.stringify({ hours: filtered }), { headers: jsonHeaders });
      }
    }

    // 3. Emails Inbox & Sent Log CRUD
    if (url.pathname === "/internal/emails") {
      const emails = (await this.ctx.storage.get("emails")) || [];
      if (request.method === "GET") {
        return new Response(JSON.stringify({ emails }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const body = await request.json();
        const emailEntry = body.email;
        if (!emailEntry || typeof emailEntry.id !== "string") {
          return new Response(JSON.stringify({ error: "A valid email record is required." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const existingIndex = emails.findIndex((email) => email.id === emailEntry.id);
        if (existingIndex >= 0) {
          emails[existingIndex] = emailEntry;
        } else {
          emails.unshift(emailEntry);
        }
        // Keep latest 200 emails
        const trimmed = emails.slice(0, 200);
        await this.ctx.storage.put("emails", trimmed);
        return new Response(JSON.stringify({ emails: trimmed }), { headers: jsonHeaders });
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        if (!id) {
          return new Response(JSON.stringify({ error: "An email id is required." }), {
            status: 400,
            headers: jsonHeaders,
          });
        }
        const filtered = emails.filter((e) => e.id !== id);
        await this.ctx.storage.put("emails", filtered);
        return new Response(JSON.stringify({ emails: filtered }), { headers: jsonHeaders });
      }
    }

    // 4. Process Appointment Confirmation (from Inbound Email or 1-Click Link)
    if (url.pathname === "/internal/process-confirmation" && request.method === "POST") {
      const body = await request.json();
      const { appointmentId, roomCode, fromEmail, status, rawSubject, rawText, method } = body;

      const appointments = (await this.ctx.storage.get("appointments")) || [];
      const emails = (await this.ctx.storage.get("emails")) || [];

      let matchedAppt = null;

      // Match by Appointment ID first, then Room Code, then Client Email
      if (appointmentId) {
        matchedAppt = appointments.find((a) => a.id === appointmentId);
      }
      if (!matchedAppt && roomCode) {
        matchedAppt = appointments.find(
          (a) => (a.roomCode || "").toUpperCase() === roomCode.toUpperCase(),
        );
      }
      if (!matchedAppt && fromEmail) {
        const cleanFrom = fromEmail.toLowerCase().trim();
        matchedAppt = appointments.find(
          (a) => (a.clientEmail || "").toLowerCase().trim() === cleanFrom,
        );
      }

      if (matchedAppt) {
        matchedAppt.status = status || "Confirmed";
        matchedAppt.confirmedAt = new Date().toISOString();
        matchedAppt.confirmationMethod = method || "Email";
        await this.ctx.storage.put("appointments", appointments);
      }

      // Log into Linda's Portal Inbox
      const inboxEntry = {
        id: crypto.randomUUID(),
        direction: "inbound",
        timestamp: new Date().toISOString(),
        from: fromEmail || (matchedAppt ? matchedAppt.clientEmail || matchedAppt.clientName : "Client"),
        to: "Practice Inbox",
        subject: rawSubject || `Appointment ${status || "Confirmed"} (${matchedAppt ? matchedAppt.roomCode : "Link"})`,
        body: rawText || `Client ${status === "Reschedule Requested" ? "requested to reschedule" : "confirmed"} appointment via ${method || "Email"}.`,
        matchedAppointmentId: matchedAppt ? matchedAppt.id : null,
        matchedClientName: matchedAppt ? matchedAppt.clientName : null,
        resultingStatus: matchedAppt ? matchedAppt.status : null,
      };

      emails.unshift(inboxEntry);
      await this.ctx.storage.put("emails", emails.slice(0, 200));

      return new Response(
        JSON.stringify({
          ok: true,
          matched: Boolean(matchedAppt),
          appointment: matchedAppt,
        }),
        { headers: jsonHeaders },
      );
    }

    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: jsonHeaders });
  }

  async webSocketMessage(ws, message) {
    let data;
    try {
      data = JSON.parse(message);
    } catch {
      return;
    }

    const senderAttachment = ws.deserializeAttachment();
    const fromPeerId = senderAttachment?.clientId;
    const fromName = senderAttachment?.clientName || "Connected Participant";

    const outgoingPayload = JSON.stringify({
      ...data,
      fromPeerId,
      fromName,
    });

    const otherSockets = this.ctx.getWebSockets().filter((socket) => socket !== ws);

    if (data.targetPeerId) {
      for (const recipient of otherSockets) {
        const attachment = recipient.deserializeAttachment();
        if (attachment?.clientId === data.targetPeerId) {
          recipient.send(outgoingPayload);
          break;
        }
      }
    } else {
      for (const recipient of otherSockets) {
        recipient.send(outgoingPayload);
      }
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    try {
      ws.close(code, reason);
    } catch {
      // Ignore if already closed
    }
    const attachment = ws.deserializeAttachment();
    const clientId = attachment?.clientId;
    const recipients = this.ctx.getWebSockets().filter((socket) => socket !== ws);
    for (const recipient of recipients) {
      recipient.send(JSON.stringify({ type: "peer-left", peerId: clientId }));
    }
  }

  async webSocketError(ws, error) {
    console.error("WebSocket error in ChatRoom:", error);
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value) {
  if (typeof value !== "string" || !/^(?:[a-f0-9]{2})+$/i.test(value)) return new Uint8Array(16);
  return Uint8Array.from(value.match(/.{2}/g), (byte) => parseInt(byte, 16));
}

async function hashPortalPassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const digest = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt,
    iterations,
  }, key, 256);
  return bytesToHex(new Uint8Array(digest));
}

async function hashSessionToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return bytesToHex(new Uint8Array(digest));
}

async function hashMfaCode(challengeId, code) {
  return hashPortalPassword(
    `${challengeId}:${code}`,
    new TextEncoder().encode(challengeId),
    AUTH_PASSWORD_ITERATIONS,
  );
}

function isValidEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function maskEmail(email) {
  const [name, domain] = email.split("@");
  return `${name.slice(0, 1)}${"*".repeat(Math.max(2, name.length - 1))}@${domain}`;
}

function base32Encode(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const output = [];
  for (const character of value.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(character);
    if (index < 0) return null;
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function verifyTotp(secret, code) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return null;
  const keyBytes = base32Decode(secret);
  if (!keyBytes?.length) return null;
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const currentStep = Math.floor(Date.now() / 30000);
  for (let offset = -1; offset <= 1; offset++) {
    const counter = new DataView(new ArrayBuffer(8));
    counter.setBigUint64(0, BigInt(currentStep + offset));
    const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
    const position = digest[digest.length - 1] & 15;
    const binary = ((digest[position] & 127) << 24) |
      ((digest[position + 1] & 255) << 16) |
      ((digest[position + 2] & 255) << 8) |
      (digest[position + 3] & 255);
    const expected = String(binary % 1000000).padStart(6, "0");
    if (constantTimeEqual(code, expected)) return currentStep + offset;
  }
  return null;
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return difference === 0;
}

function getPortalMfaMethod(user) {
  if (user.mfaMethod === "none") return "none";
  if (user.mfaMethod === "authenticator" && user.totpSecret) return "authenticator";
  if (user.mfaMethod === "email") return "email";
  return "none";
}

function getAppointmentStartTime(appointment) {
  const dateMatch = typeof appointment.date === "string"
    ? appointment.date.match(/^(\d{4})-(\d{2})-(\d{2})$/)
    : null;
  const timeMatch = typeof appointment.time === "string"
    ? appointment.time.match(/^(\d{2}):(\d{2})$/)
    : null;
  const timeZone = appointment.timeZone || APPOINTMENT_TIME_ZONE;
  if (!dateMatch || !timeMatch) return null;
  const [year, month, day] = dateMatch.slice(1).map(Number);
  const [hour, minute] = timeMatch.slice(1).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) return null;

  const targetUtc = Date.UTC(year, month - 1, day, hour, minute);
  try {
    const formatter = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    });
    let candidate = targetUtc;
    for (let attempt = 0; attempt < 4; attempt++) {
      const parts = Object.fromEntries(formatter.formatToParts(new Date(candidate))
        .filter((part) => part.type !== "literal")
        .map((part) => [part.type, Number(part.value)]));
      const displayedUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
      const adjusted = candidate + targetUtc - displayedUtc;
      if (adjusted === candidate) break;
      candidate = adjusted;
    }

    const verified = Object.fromEntries(formatter.formatToParts(new Date(candidate))
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, Number(part.value)]));
    if (verified.year !== year || verified.month !== month || verified.day !== day ||
      verified.hour !== hour || verified.minute !== minute) return null;
    return candidate;
  } catch {
    return null;
  }
}

function isValidAvailability(availability) {
  if (!availability || typeof availability !== "object" || Array.isArray(availability) ||
    !availability.weekdays || typeof availability.weekdays !== "object" || !Array.isArray(availability.exceptions) ||
    availability.exceptions.length > 100) return false;
  const validIntervals = (intervals) => Array.isArray(intervals) && intervals.length <= 4 &&
    intervals.every((interval) => {
      if (!interval || typeof interval.start !== "string" || typeof interval.end !== "string") return false;
      const start = interval.start.match(/^(\d{2}):(\d{2})$/);
      const end = interval.end.match(/^(\d{2}):(\d{2})$/);
      if (!start || !end || Number(start[1]) > 23 || Number(start[2]) > 59 ||
        Number(end[1]) > 23 || Number(end[2]) > 59) return false;
      return Number(start[1]) * 60 + Number(start[2]) < Number(end[1]) * 60 + Number(end[2]);
    }) && intervals.every((interval, index) => {
      const start = Number(interval.start.slice(0, 2)) * 60 + Number(interval.start.slice(3));
      const end = Number(interval.end.slice(0, 2)) * 60 + Number(interval.end.slice(3));
      return intervals.every((other, otherIndex) => {
        if (otherIndex <= index) return true;
        const otherStart = Number(other.start.slice(0, 2)) * 60 + Number(other.start.slice(3));
        const otherEnd = Number(other.end.slice(0, 2)) * 60 + Number(other.end.slice(3));
        return end <= otherStart || otherEnd <= start;
      });
    });
  const dayKeys = Object.keys(availability.weekdays);
  if (dayKeys.some((day) => !/^[0-6]$/.test(day) || !validIntervals(availability.weekdays[day]))) return false;
  const dates = new Set();
  return availability.exceptions.every((exception) => {
    if (!exception || typeof exception.date !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(exception.date) || dates.has(exception.date) ||
      !validIntervals(exception.intervals)) return false;
    const [year, month, day] = exception.date.split("-").map(Number);
    if (new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) !== exception.date) return false;
    dates.add(exception.date);
    return true;
  });
}

function getAppointmentAvailabilityError(appointment, schedule, appointments, ignoredId) {
  if (!schedule || !isValidAvailability(schedule)) {
    return "No availability is set for this staff member. Add weekly hours in Users & Profile first.";
  }
  if (typeof appointment.date !== "string" || typeof appointment.time !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(appointment.date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(appointment.time)) {
    return "Choose a valid appointment date and available start time.";
  }
  if (getAppointmentStartTime(appointment) === null) return "That local time does not exist in the selected time zone.";
  const duration = Number(appointment.duration || 50);
  if (!Number.isInteger(duration) || duration < 15 || duration > 240) return "Choose a valid appointment duration.";
  const [year, month, day] = appointment.date.split("-").map(Number);
  if (new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10) !== appointment.date) {
    return "Choose a valid appointment date.";
  }
  const exception = schedule.exceptions.find((item) => item.date === appointment.date);
  const intervals = exception ? exception.intervals : schedule.weekdays[String(new Date(Date.UTC(year, month - 1, day)).getUTCDay())] || [];
  const start = Number(appointment.time.slice(0, 2)) * 60 + Number(appointment.time.slice(3));
  const end = start + duration;
  if (end >= 24 * 60) return "The appointment must end before midnight in the selected time zone.";
  const endTime = `${String(Math.floor(end / 60)).padStart(2, "0")}:${String(end % 60).padStart(2, "0")}`;
  if (getAppointmentStartTime({ ...appointment, time: endTime }) === null) {
    return "The appointment would end at a local time that does not exist in the selected time zone.";
  }
  if (!intervals.some((interval) =>
    Number(interval.start.slice(0, 2)) * 60 + Number(interval.start.slice(3)) <= start &&
    Number(interval.end.slice(0, 2)) * 60 + Number(interval.end.slice(3)) >= end
  )) return "That time is outside the selected staff member's availability.";
  const conflict = appointments.some((item) => {
    if (item.id === ignoredId || item.hostUserId !== appointment.hostUserId || item.date !== appointment.date ||
      ["Completed", "Reschedule Requested"].includes(item.status) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(item.time || "")) return false;
    const otherStart = Number(item.time.slice(0, 2)) * 60 + Number(item.time.slice(3));
    const otherEnd = otherStart + Number(item.duration || 50);
    return start < otherEnd && otherStart < end;
  });
  return conflict ? "That time overlaps another appointment for this staff member." : "";
}

function isAppointmentReminderConfigured(appointment, users) {
  return isValidEmail(appointment.clientEmail) &&
    users.some((user) => user.id === appointment.hostUserId && user.active && isValidEmail(user.email)) &&
    getAppointmentStartTime(appointment) !== null;
}

function mergeAppointmentReminderState(existing, updated) {
  if (!existing) return updated;
  const sameAppointmentTime = existing.date === updated.date &&
    existing.time === updated.time &&
    (existing.timeZone || APPOINTMENT_TIME_ZONE) === (updated.timeZone || APPOINTMENT_TIME_ZONE);
  const sameReminderSetting = (existing.reminderEnabled !== false) === (updated.reminderEnabled !== false);
  if (!sameAppointmentTime || !sameReminderSetting || updated.reminderEnabled === false) {
    delete updated.reminderState;
    delete updated.reminderClaim;
    return updated;
  }

  const state = { ...(existing.reminderState || {}) };
  if (existing.clientEmail !== updated.clientEmail) delete state.client;
  if (existing.hostUserId !== updated.hostUserId) delete state.staff;
  if (Object.keys(state).length > 0) updated.reminderState = state;
  else delete updated.reminderState;

  if (existing.clientEmail === updated.clientEmail && existing.hostUserId === updated.hostUserId) {
    if (existing.reminderClaim) updated.reminderClaim = existing.reminderClaim;
    else delete updated.reminderClaim;
  } else {
    delete updated.reminderClaim;
  }
  return updated;
}

function publicPortalUser(user) {
  const mfaMethod = getPortalMfaMethod(user);
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email || "",
    role: user.role,
    mfaMethod,
    mfaEnabled: mfaMethod !== "none",
    active: user.active,
    createdAt: user.createdAt,
  };
}

function getSessionToken(request) {
  const cookies = request.headers.get("Cookie") || "";
  const cookie = cookies.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${AUTH_SESSION_COOKIE}=`));
  return cookie ? cookie.slice(AUTH_SESSION_COOKIE.length + 1) : "";
}

function getClientSessionToken(request) {
  const cookies = request.headers.get("Cookie") || "";
  const cookie = cookies.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${CLIENT_SESSION_COOKIE}=`));
  return cookie ? cookie.slice(CLIENT_SESSION_COOKIE.length + 1) : "";
}

async function isAuthorized(request, env) {
  const sessionToken = getSessionToken(request);
  if (!sessionToken) return null;
  const stub = getAdminStoreStub(env);
  const response = await stub.fetch(new Request("https://internal/internal/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionToken }),
  }));
  if (!response.ok) return null;
  const { user } = await response.json();
  return user && ["admin", "staff"].includes(user.role) ? user : null;
}

async function isClientAuthorized(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const cookie = cookies.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${CLIENT_SESSION_COOKIE}=`));
  const sessionToken = cookie ? cookie.slice(CLIENT_SESSION_COOKIE.length + 1) : "";
  if (!sessionToken) return null;
  const stub = getAdminStoreStub(env);
  const response = await stub.fetch(new Request("https://internal/internal/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sessionToken }),
  }));
  if (!response.ok) return null;
  const { user } = await response.json();
  return user?.role === "client" ? user : null;
}

function getAdminStoreStub(env) {
  const adminStoreId = env.CHAT_ROOM.idFromName("__LINDA_ADMIN_PORTAL_STORE__");
  return env.CHAT_ROOM.get(adminStoreId);
}

async function processAppointmentReminders(env) {
  if (!env.EMAIL || !env.SENDER_EMAIL) {
    console.error("Appointment reminders are enabled but the EMAIL binding or SENDER_EMAIL is unavailable.");
    return;
  }

  const stub = getAdminStoreStub(env);
  const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };
  const claimResponse = await stub.fetch(new Request("https://internal/internal/reminders/claim", {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ now: Date.now() }),
  }));
  if (!claimResponse.ok) throw new Error(`Could not claim appointment reminders (${claimResponse.status}).`);
  const { claims } = await claimResponse.json();

  for (const claim of claims) {
    try {
      for (const target of claim.targets) {
        let sendError = null;
        const isStaff = target.key === "staff";
        const body = isStaff
          ? `Reminder: ${claim.clientName}'s appointment begins in 30 minutes.\nDate: ${claim.date}\nTime: ${claim.time} Eastern Time\nRoom: ${claim.roomCode}`
          : `This is a reminder that your appointment with Linda Milewski, LCSW begins in 30 minutes.\nDate: ${claim.date}\nTime: ${claim.time} Eastern Time`;
        try {
          await env.EMAIL.send({
            from: env.SENDER_EMAIL,
            to: target.email,
            subject: "Appointment reminder: starts in 30 minutes",
            text: body,
          });
        } catch (error) {
          sendError = error;
          console.error(`Appointment reminder delivery failed for ${target.key}:`, error);
        }

        const completionResponse = await stub.fetch(new Request("https://internal/internal/reminders/complete", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({
            id: claim.id,
            claimToken: claim.claimToken,
            recipient: target.key,
            sent: sendError === null,
          }),
        }));
        if (!completionResponse.ok) {
          console.error(`Could not record appointment reminder result (${completionResponse.status}).`);
          continue;
        }

        if (!sendError) {
          const logResponse = await stub.fetch(new Request("https://internal/internal/emails", {
            method: "POST",
            headers: jsonHeaders,
            body: JSON.stringify({
              email: {
                id: crypto.randomUUID(),
                direction: "outbound",
                timestamp: new Date().toISOString(),
                from: env.SENDER_EMAIL,
                to: target.email,
                subject: "Appointment reminder: starts in 30 minutes",
                body,
                deliveryStatus: "Delivered via Cloudflare Email Service",
                category: "appointment-reminder",
              },
            }),
          }));
          if (!logResponse.ok) {
            console.error(`Could not add appointment reminder to the portal mail log (${logResponse.status}).`);
          }
        }
      }
    } finally {
      const releaseResponse = await stub.fetch(new Request("https://internal/internal/reminders/release", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ id: claim.id, claimToken: claim.claimToken }),
      }));
      if (!releaseResponse.ok) {
        console.error(`Could not release appointment reminder claim (${releaseResponse.status}).`);
      }
    }
  }
}

function decodeQuotedPrintable(text) {
  const unfolded = text.replace(/=\r?\n/g, "");
  return unfolded.replace(/((?:=[\da-f]{2})+)/gi, (encodedBytes) => {
    const bytes = new Uint8Array(encodedBytes.length / 3);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(encodedBytes.slice(i * 3 + 1, i * 3 + 3), 16);
    }
    return new TextDecoder("utf-8").decode(bytes);
  });
}

function cleanEmailReplyText(text) {
  return text
    .replace(/=\s+/g, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\b[A-Za-z][\w-]*\s*\{[^}]*\}/g, " ")
    .replace(/\s*(?:_{5,}|-{5,}\s*Original Message|From:\s*[\s\S]*?(?:\bSent:|\bDate:))[\s\S]*$/i, "")
    .replace(/(?:\r?\n)?On .{1,160}wrote:\s*[\s\S]*$/i, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 1500);
}

// Helper: Extract plain text from raw MIME email without external dependencies
function extractPlainTextFromMime(rawEmailText) {
  if (!rawEmailText) return "";
  // Split headers and body
  const parts = rawEmailText.split(/\r?\n\r?\n/);
  if (parts.length < 2) return rawEmailText.slice(0, 1000);
  const bodyContent = decodeQuotedPrintable(parts.slice(1).join("\n\n"));
  // Strip HTML tags and MIME boundary noise for a clean preview
  return cleanEmailReplyText(
    bodyContent.replace(/--[^\r\n]+/g, "").replace(/Content-[^\r\n]+/gi, ""),
  );
}

export default {
  // ===========================================================================
  // HTTP FETCH HANDLER (Website, Portal APIs, Outbound Email, & WebRTC)
  // ===========================================================================
  async fetch(request, env) {
    const url = new URL(request.url);
    const jsonHeaders = { "Content-Type": "application/json", "Cache-Control": "no-store" };

    if (url.pathname.startsWith("/api/") && !["GET", "HEAD", "OPTIONS"].includes(request.method)) {
      const origin = request.headers.get("Origin");
      if (origin && origin !== url.origin) {
        return new Response(JSON.stringify({ error: "Cross-origin request rejected." }), {
          status: 403,
          headers: jsonHeaders,
        });
      }
    }

    // 1. Clinician Authentication and Staff Accounts
    if (url.pathname === "/api/login" && request.method === "POST") {
      let credentials;
      try {
        credentials = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid JSON in sign-in request." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }

      if (!credentials || typeof credentials !== "object" ||
        typeof credentials.username !== "string" || typeof credentials.password !== "string") {
        return new Response(JSON.stringify({ error: "Enter both username and password." }), {
          status: 400,
          headers: jsonHeaders,
        });
      }

      try {
        const stub = getAdminStoreStub(env);
        const loginRes = await stub.fetch(new Request("https://internal/internal/auth/login", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({
            username: credentials.username,
            password: credentials.password,
            expectedRole: "portal",
            email: credentials.email,
            bootstrapEmail: env.ADMIN_BOOTSTRAP_EMAIL,
            bootstrapUsername: env.ADMIN_BOOTSTRAP_USERNAME,
            bootstrapPassword: env.ADMIN_BOOTSTRAP_PASSWORD,
            clientIp: request.headers.get("CF-Connecting-IP") || "unknown",
          }),
        }));
        let result;
        try {
          result = await loginRes.json();
        } catch {
          console.error("Portal login Durable Object returned a non-JSON response:", loginRes.status);
          return new Response(JSON.stringify({ error: "Sign-in service error. Check the Worker logs." }), {
            status: 503,
            headers: jsonHeaders,
          });
        }
        if (!loginRes.ok) {
          return new Response(JSON.stringify({ error: result.error || "Invalid username or password." }), {
            status: loginRes.status,
            headers: { ...jsonHeaders, "Cache-Control": "no-store" },
          });
        }
        if (result.sessionToken) {
          return new Response(JSON.stringify({ ok: true, user: result.user }), {
            headers: {
              ...jsonHeaders,
              "Cache-Control": "no-store",
              "Set-Cookie": `${AUTH_SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_SESSION_TTL_MS / 1000)}${url.protocol === "https:" ? "; Secure" : ""}`,
            },
          });
        }
        if (result.method === "email") {
          if (!env.EMAIL || !env.SENDER_EMAIL || !result.email || !result.challengeCode) {
            await stub.fetch(new Request("https://internal/internal/auth/cancel-mfa", {
              method: "POST",
              headers: jsonHeaders,
              body: JSON.stringify({ challengeId: result.challengeId }),
            }));
            return new Response(JSON.stringify({ error: "Email verification is not configured. Set the Cloudflare EMAIL binding and SENDER_EMAIL." }), {
              status: 503,
              headers: { ...jsonHeaders, "Cache-Control": "no-store" },
            });
          }
          try {
            await env.EMAIL.send({
              from: env.SENDER_EMAIL,
              to: result.email,
              subject: "Your Clinician Portal sign-in code",
              text: `Your Clinician Portal verification code is ${result.challengeCode}.\n\nIt expires in 10 minutes. If you did not request this code, you can ignore this email.`,
            });
          } catch (error) {
            await stub.fetch(new Request("https://internal/internal/auth/cancel-mfa", {
              method: "POST",
              headers: jsonHeaders,
              body: JSON.stringify({ challengeId: result.challengeId }),
            }));
            console.error("Portal MFA email delivery failed:", error);
            return new Response(JSON.stringify({ error: "Could not send the sign-in code. Check the Cloudflare Email binding and try again." }), {
              status: 503,
              headers: { ...jsonHeaders, "Cache-Control": "no-store" },
            });
          }
        }
        return new Response(JSON.stringify({
          ok: true,
          challengeId: result.challengeId,
          method: result.method,
          maskedEmail: result.maskedEmail,
        }), {
          headers: { ...jsonHeaders, "Cache-Control": "no-store" },
        });
      } catch (error) {
        console.error("Portal login request failed:", error);
        return new Response(
          JSON.stringify({ error: "Sign-in service error. Check the Worker logs." }),
          { status: 503, headers: { ...jsonHeaders, "Cache-Control": "no-store" } },
        );
      }
    }

    if (url.pathname === "/api/client-signup/request" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid signup request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid signup request." }), { status: 400, headers: jsonHeaders });
      }
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        return new Response(JSON.stringify({ error: "Account verification email is not configured. Contact the practice." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const stub = getAdminStoreStub(env);
      const start = await stub.fetch(new Request("https://internal/internal/client-signup/request", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, clientIp: request.headers.get("CF-Connecting-IP") || "unknown" }),
      }));
      const result = await start.json();
      if (!start.ok) {
        return new Response(JSON.stringify({ error: result.error || "Could not start account signup." }), {
          status: start.status,
          headers: jsonHeaders,
        });
      }
      try {
        await env.EMAIL.send({
          from: env.SENDER_EMAIL,
          to: result.email,
          subject: "Verify your appointment account",
          text: `Your appointment account verification code is ${result.code}.\n\nThe code expires in 10 minutes. If you did not request an account, you can ignore this email.`,
        });
      } catch (error) {
        console.error("Appointment account verification email failed:", error);
        return new Response(JSON.stringify({ error: "Could not send the verification code. Check the email address and try again." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/api/client-signup/verify" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid signup verification request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid signup verification request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      const verify = await stub.fetch(new Request("https://internal/internal/client-signup/verify", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(body),
      }));
      const result = await verify.json();
      if (!verify.ok) {
        return new Response(JSON.stringify({ error: result.error || "Could not verify account." }), {
          status: verify.status,
          headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify({ ok: true, user: result.user }), {
        headers: {
          ...jsonHeaders,
          "Set-Cookie": `${CLIENT_SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_SESSION_TTL_MS / 1000)}${url.protocol === "https:" ? "; Secure" : ""}`,
        },
      });
    }

    if (url.pathname === "/api/client/login" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid sign-in request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body) ||
        typeof body.username !== "string" || typeof body.password !== "string") {
        return new Response(JSON.stringify({ error: "Enter your username or email and password." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      const login = await stub.fetch(new Request("https://internal/internal/auth/login", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          username: body.username,
          password: body.password,
          expectedRole: "client",
          clientIp: request.headers.get("CF-Connecting-IP") || "unknown",
        }),
      }));
      const result = await login.json();
      if (!login.ok) {
        return new Response(JSON.stringify({ error: result.error || "Invalid email or password." }), {
          status: login.status,
          headers: jsonHeaders,
        });
      }
      if (!result.sessionToken) {
        return new Response(JSON.stringify({ error: "Client sign-in could not be completed." }), { status: 503, headers: jsonHeaders });
      }
      return new Response(JSON.stringify({ ok: true, user: result.user }), {
        headers: {
          ...jsonHeaders,
          "Set-Cookie": `${CLIENT_SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_SESSION_TTL_MS / 1000)}${url.protocol === "https:" ? "; Secure" : ""}`,
        },
      });
    }

    if (url.pathname === "/api/client/session" && request.method === "GET") {
      const user = await isClientAuthorized(request, env);
      return new Response(JSON.stringify(user ? { user } : { error: "Unauthorized" }), {
        status: user ? 200 : 401,
        headers: jsonHeaders,
      });
    }

    if (url.pathname === "/api/client/logout" && request.method === "POST") {
      const cookies = request.headers.get("Cookie") || "";
      const cookie = cookies.split(";").map((part) => part.trim())
        .find((part) => part.startsWith(`${CLIENT_SESSION_COOKIE}=`));
      const sessionToken = cookie ? cookie.slice(CLIENT_SESSION_COOKIE.length + 1) : "";
      const stub = getAdminStoreStub(env);
      await stub.fetch(new Request("https://internal/internal/auth/logout", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ sessionToken }),
      }));
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          ...jsonHeaders,
          "Set-Cookie": `${CLIENT_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${url.protocol === "https:" ? "; Secure" : ""}`,
        },
      });
    }

    if (url.pathname === "/api/client/availability" && request.method === "GET") {
      if (!(await isClientAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Client account sign-in required." }), { status: 401, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      const target = new URL("https://internal/internal/client-availability");
      target.search = url.search;
      return stub.fetch(new Request(target, { headers: jsonHeaders }));
    }

    if (url.pathname === "/api/client/appointments" && ["GET", "POST"].includes(request.method)) {
      const client = await isClientAuthorized(request, env);
      if (!client) return new Response(JSON.stringify({ error: "Client account sign-in required." }), { status: 401, headers: jsonHeaders });
      const stub = getAdminStoreStub(env);
      if (request.method === "GET") {
        return stub.fetch(new Request("https://internal/internal/client/appointments", {
          method: "GET",
          headers: { "X-Client-Session": getClientSessionToken(request) },
        }));
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid appointment request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid appointment request." }), { status: 400, headers: jsonHeaders });
      }
      const booking = await stub.fetch(new Request("https://internal/internal/client/appointments", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, sessionToken: getClientSessionToken(request) }),
      }));
      const result = await booking.json();
      if (!booking.ok) {
        return new Response(JSON.stringify({ error: result.error || "Could not request the appointment." }), {
          status: booking.status,
          headers: jsonHeaders,
        });
      }
      let notificationError = "";
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        notificationError = "The request was saved, but email notifications are not configured.";
      } else {
        const messages = [
          {
            to: client.email,
            subject: "Appointment request received",
            text: `Hello ${client.displayName},\n\nYour appointment request has been received and is awaiting confirmation from the practice.\n\nRequested appointment: ${result.appointment.date} at ${result.appointment.time} Eastern Time\nService: ${result.appointment.service}\n\nThe practice will follow up after reviewing your request.`,
          },
          {
            to: result.host.email,
            subject: "New appointment request",
            text: `A client has requested an appointment.\n\nClient: ${client.displayName}\nRequested appointment: ${result.appointment.date} at ${result.appointment.time} Eastern Time\nService: ${result.appointment.service}\n\nSign in to the Clinician Portal to review and confirm the request.`,
          },
        ];
        const failures = [];
        for (const message of messages) {
          try {
            await env.EMAIL.send({ from: env.SENDER_EMAIL, ...message });
          } catch (error) {
            console.error(`Appointment request email to ${message.to} failed:`, error);
            failures.push(message.to);
          }
        }
        if (failures.length) notificationError = "The request was saved, but one or more email notifications could not be sent.";
      }
      return new Response(JSON.stringify({
        ok: true,
        appointment: result.appointment,
        ...(notificationError ? { notificationError } : {}),
      }), { status: booking.status, headers: jsonHeaders });
    }

    if (url.pathname === "/api/verify-mfa" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid verification request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid verification request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      const verifyRes = await stub.fetch(new Request("https://internal/internal/auth/verify-mfa", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(body),
      }));
      const result = await verifyRes.json();
      if (!verifyRes.ok) {
        return new Response(JSON.stringify({ error: result.error || "Could not verify the code." }), {
          status: verifyRes.status,
          headers: { ...jsonHeaders, "Cache-Control": "no-store" },
        });
      }
      return new Response(JSON.stringify({ ok: true, user: result.user }), {
        headers: {
          ...jsonHeaders,
          "Cache-Control": "no-store",
          "Set-Cookie": `${AUTH_SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_SESSION_TTL_MS / 1000)}${url.protocol === "https:" ? "; Secure" : ""}`,
        },
      });
    }

    if (url.pathname === "/api/mfa/setup" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/mfa/setup", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ sessionToken: getSessionToken(request) }),
      }));
    }

    if (url.pathname === "/api/mfa/verify-setup" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      const body = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid authenticator verification request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/mfa/verify-setup", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
      }));
    }

    if (url.pathname === "/api/mfa/email/start" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        return new Response(JSON.stringify({ error: "Email verification is not configured. Set the Cloudflare EMAIL binding and SENDER_EMAIL." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid email MFA request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid email MFA request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      const response = await stub.fetch(new Request("https://internal/internal/auth/mfa/email/start", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
      }));
      const result = await response.json();
      if (!response.ok) {
        return new Response(JSON.stringify({ error: result.error || "Could not start email MFA." }), {
          status: response.status,
          headers: jsonHeaders,
        });
      }
      try {
        await env.EMAIL.send({
          from: env.SENDER_EMAIL,
          to: result.email,
          subject: "Verify your Clinician Portal email",
          text: `Your Clinician Portal verification code is ${result.code}.\n\nIt expires in 10 minutes. If you did not request this code, you can ignore this email.`,
        });
      } catch (error) {
        await stub.fetch(new Request("https://internal/internal/auth/mfa/email/cancel", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ sessionToken: getSessionToken(request) }),
        }));
        console.error("Portal email MFA enrollment delivery failed:", error);
        return new Response(JSON.stringify({ error: "Could not send the verification code. Check email configuration and try again." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify({ ok: true, maskedEmail: result.maskedEmail }), {
        headers: { ...jsonHeaders, "Cache-Control": "no-store" },
      });
    }

    if (url.pathname === "/api/mfa/email/verify" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid email MFA verification request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid email MFA verification request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/mfa/email/verify", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
      }));
    }

    if (url.pathname === "/api/mfa/disable" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid MFA settings request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid MFA settings request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/mfa/disable", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
      }));
    }

    if (url.pathname === "/api/session" && request.method === "GET") {
      const user = await isAuthorized(request, env);
      return new Response(JSON.stringify(user ? { user } : { error: "Unauthorized" }), {
        status: user ? 200 : 401,
        headers: { ...jsonHeaders, "Cache-Control": "no-store" },
      });
    }

    if (url.pathname === "/api/change-password" && request.method === "POST") {
      const user = await isAuthorized(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      try {
        const body = await request.json();
        const stub = getAdminStoreStub(env);
        const resultRes = await stub.fetch(new Request("https://internal/internal/auth/change-password", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
        }));
        const result = await resultRes.json();
        if (!resultRes.ok) {
          return new Response(JSON.stringify({ error: result.error || "Could not change password." }), {
            status: resultRes.status,
            headers: { ...jsonHeaders, "Cache-Control": "no-store" },
          });
        }
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            ...jsonHeaders,
            "Cache-Control": "no-store",
            "Set-Cookie": `${AUTH_SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_SESSION_TTL_MS / 1000)}${url.protocol === "https:" ? "; Secure" : ""}`,
          },
        });
      } catch {
        return new Response(JSON.stringify({ error: "Invalid request payload." }), {
          status: 400,
          headers: { ...jsonHeaders, "Cache-Control": "no-store" },
        });
      }
    }

    if (url.pathname === "/api/logout" && request.method === "POST") {
      const sessionToken = getSessionToken(request);
      const stub = getAdminStoreStub(env);
      await stub.fetch(new Request("https://internal/internal/auth/logout", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ sessionToken }),
      }));
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          ...jsonHeaders,
          "Cache-Control": "no-store",
          "Set-Cookie": `${AUTH_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${url.protocol === "https:" ? "; Secure" : ""}`,
        },
      });
    }

    if (["/api/account/email", "/api/account/email-for-user"].includes(url.pathname) && request.method === "POST") {
      const actor = await isAuthorized(request, env);
      if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid email update request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid email update request." }), { status: 400, headers: jsonHeaders });
      }
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        return new Response(JSON.stringify({ error: "Email confirmation is not configured. Set the Cloudflare EMAIL binding and SENDER_EMAIL." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const stub = getAdminStoreStub(env);
      const changeResponse = await stub.fetch(new Request("https://internal/internal/auth/account-email", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          ...body,
          userId: url.pathname === "/api/account/email" ? actor.id : body.userId,
          sessionToken: getSessionToken(request),
        }),
      }));
      const change = await changeResponse.json();
      if (!changeResponse.ok) {
        return new Response(JSON.stringify({ error: change.error || "Could not start the email update." }), {
          status: changeResponse.status,
          headers: jsonHeaders,
        });
      }
      if (change.unchanged) return new Response(JSON.stringify({ ok: true, unchanged: true }), { headers: jsonHeaders });
      const verifyUrl = new URL("/verify-email.html", url.origin);
      verifyUrl.searchParams.set("token", change.token);
      try {
        await env.EMAIL.send({
          from: env.SENDER_EMAIL,
          to: change.verificationEmail,
          subject: "Confirm a Clinician Portal email change",
          text: `Hello ${change.displayName},\n\nA request was made to change the email address on your Clinician Portal account. To confirm the change, open this single-use link within 30 minutes:\n${verifyUrl.href}\n\nIf you did not request this change, do not use the link. Your account email remains unchanged.`,
        });
      } catch (error) {
        await stub.fetch(new Request("https://internal/internal/auth/account-email/cancel", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ token: change.token }),
        }));
        console.error("Portal email change confirmation delivery failed:", error);
        return new Response(JSON.stringify({ error: "Could not send the email confirmation. Check the Cloudflare Email binding and try again." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify({ ok: true, confirmationRequired: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/api/directory" && request.method === "GET") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/directory", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ sessionToken: getSessionToken(request) }),
      }));
    }

    if (url.pathname === "/api/account/email/confirm" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid email confirmation request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid email confirmation request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/account-email/complete", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(body),
      }));
    }

    if (url.pathname === "/api/availability") {
      const actor = await isAuthorized(request, env);
      if (!actor) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      const stub = getAdminStoreStub(env);
      if (request.method === "GET") {
        return stub.fetch(new Request("https://internal/internal/availability", {
          method: "GET",
          headers: jsonHeaders,
        }));
      }
      if (request.method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch {
          return new Response(JSON.stringify({ error: "Invalid availability request." }), { status: 400, headers: jsonHeaders });
        }
        return stub.fetch(new Request("https://internal/internal/availability", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ ...body, sessionToken: getSessionToken(request) }),
        }));
      }
      return new Response(JSON.stringify({ error: "Method not allowed." }), { status: 405, headers: jsonHeaders });
    }

    if (url.pathname === "/api/password-reset/request" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid password reset request." }), { status: 400, headers: jsonHeaders });
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return new Response(JSON.stringify({ error: "Invalid password reset request." }), { status: 400, headers: jsonHeaders });
      }
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        return new Response(JSON.stringify({ error: "Password reset email is not configured. Set the Cloudflare EMAIL binding and SENDER_EMAIL." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const actor = await isAuthorized(request, env);
      const stub = getAdminStoreStub(env);
      const createRes = await stub.fetch(new Request("https://internal/internal/auth/password-reset/create", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          email: body.email,
          userId: body.userId,
          sessionToken: actor ? getSessionToken(request) : undefined,
          clientIp: request.headers.get("CF-Connecting-IP") || "unknown",
        }),
      }));
      const reset = await createRes.json();
      if (!createRes.ok) {
        if (actor || createRes.status === 429) {
          return new Response(JSON.stringify({ error: reset.error || "Could not create the password reset link." }), {
            status: createRes.status,
            headers: jsonHeaders,
          });
        }
        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      }
      if (!reset.token) return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      const resetUrl = new URL("/reset-password.html", url.origin);
      resetUrl.searchParams.set("token", reset.token);
      try {
        await env.EMAIL.send({
          from: env.SENDER_EMAIL,
          to: reset.email,
          subject: "Reset your Clinician Portal password",
          text: `Hello ${reset.displayName},\n\nUse this link to set a new Clinician Portal password. It expires in 30 minutes and can only be used once:\n${resetUrl.href}\n\nIf you did not request this change, you can ignore this email.`,
        });
      } catch (error) {
        await stub.fetch(new Request("https://internal/internal/auth/password-reset/cancel", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ token: reset.token }),
        }));
        console.error("Portal password reset email delivery failed:", error);
        return new Response(JSON.stringify({ error: "Could not send the reset link. Check the Cloudflare Email binding and try again." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/api/password-reset/complete" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ error: "Invalid password reset request." }), { status: 400, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/auth/password-reset/complete", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(body),
      }));
    }

    if (url.pathname === "/api/users/reset-password" && request.method === "POST") {
      const actor = await isAuthorized(request, env);
      if (!actor) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      if (!env.EMAIL || !env.SENDER_EMAIL) {
        return new Response(JSON.stringify({ error: "Password reset email is not configured. Set the Cloudflare EMAIL binding and SENDER_EMAIL." }), {
          status: 503,
          headers: jsonHeaders,
        });
      }
      const stub = getAdminStoreStub(env);
      const createRes = await stub.fetch(new Request("https://internal/internal/auth/password-reset/create", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          userId: new URL(request.url).searchParams.get("id"),
          sessionToken: getSessionToken(request),
          clientIp: request.headers.get("CF-Connecting-IP") || "unknown",
        }),
      }));
      const reset = await createRes.json();
      if (!createRes.ok) {
        return new Response(JSON.stringify({ error: reset.error || "Could not create the password reset link." }), {
          status: createRes.status,
          headers: jsonHeaders,
        });
      }
      if (reset.token) {
        const resetUrl = new URL("/reset-password.html", url.origin);
        resetUrl.searchParams.set("token", reset.token);
        try {
          await env.EMAIL.send({
            from: env.SENDER_EMAIL,
            to: reset.email,
            subject: "Reset your Clinician Portal password",
            text: `Hello ${reset.displayName},\n\nUse this link to set a new Clinician Portal password. It expires in 30 minutes and can only be used once:\n${resetUrl.href}\n\nIf you did not request this change, you can ignore this email.`,
          });
        } catch (error) {
          await stub.fetch(new Request("https://internal/internal/auth/password-reset/cancel", {
            method: "POST",
            headers: jsonHeaders,
            body: JSON.stringify({ token: reset.token }),
          }));
          console.error("Portal account password reset email delivery failed:", error);
          return new Response(JSON.stringify({ error: "Could not send the reset link. Check the Cloudflare Email binding and try again." }), {
            status: 503,
            headers: jsonHeaders,
          });
        }
      }
      return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
    }

    if (url.pathname === "/api/users") {
      const user = await isAuthorized(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      if (!["admin", "staff"].includes(user.role)) {
        return new Response(JSON.stringify({ error: "Clinician account access required." }), {
          status: 403,
          headers: jsonHeaders,
        });
      }
      if (!["GET", "POST", "PATCH", "DELETE"].includes(request.method)) {
        return new Response(JSON.stringify({ error: "Method not allowed." }), {
          status: 405,
          headers: jsonHeaders,
        });
      }
      const stub = getAdminStoreStub(env);
      const internalUrl = new URL("/internal/auth/users" + url.search, request.url);
      let body;
      if (request.method === "POST" || request.method === "PATCH") {
        body = await request.json();
        body.sessionToken = getSessionToken(request);
      } else if (request.method === "DELETE") {
        body = { sessionToken: getSessionToken(request) };
      } else {
        return stub.fetch(new Request(internalUrl, {
          method: "GET",
          headers: { "X-Portal-Session": getSessionToken(request) },
        }));
      }
      return stub.fetch(new Request(internalUrl, {
        method: request.method,
        headers: jsonHeaders,
        body: request.method === "GET" ? undefined : JSON.stringify(body),
      }));
    }

    if (url.pathname === "/api/reminder-recipients" && request.method === "GET") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: jsonHeaders });
      }
      const stub = getAdminStoreStub(env);
      return stub.fetch(new Request("https://internal/internal/reminder-recipients", {
        method: "GET",
        headers: jsonHeaders,
      }));
    }

    // 2. One-Click Client Appointment Confirmation Link (GET /api/confirm-appointment)
    if (url.pathname === "/api/confirm-appointment" && request.method === "GET") {
      const appointmentId = url.searchParams.get("id") || "";
      const roomCode = url.searchParams.get("room") || "";
      const action = url.searchParams.get("action") || "confirm";
      const status = action === "reschedule" ? "Reschedule Requested" : "Confirmed";

      const stub = getAdminStoreStub(env);
      const confirmRes = await stub.fetch(
        new Request("https://internal/internal/process-confirmation", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({
            appointmentId,
            roomCode,
            status,
            method: "1-Click Email Link",
          }),
        }),
      );
      const result = await confirmRes.json();
      const appt = result.appointment;

      const htmlPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Appointment ${status} | Linda Milewski, LCSW</title>
  <link rel="stylesheet" href="/tailwind.css">
</head>
<body class="bg-[#f8f5ef] text-[#2c352d] min-h-screen flex items-center justify-center p-4 font-sans">
  <div class="max-w-md w-full bg-white rounded-3xl p-8 border border-[#e4d9c5] shadow-xl text-center space-y-4">
    <div class="w-14 h-14 rounded-2xl ${status === "Confirmed" ? "bg-[#416244]" : "bg-amber-600"} text-white flex items-center justify-center mx-auto text-2xl font-bold">
      ${status === "Confirmed" ? "✓" : "!"}
    </div>
    <h1 class="text-2xl font-serif font-semibold text-[#253527]">
      ${status === "Confirmed" ? "Appointment Confirmed!" : "Reschedule Request Received"}
    </h1>
    <p class="text-sm text-[#354f37] leading-relaxed">
      ${
        appt
          ? `Thank you, <strong>${appt.clientName}</strong>. Your session on <strong>${appt.date} at ${appt.time}</strong> (Room Code: <code>${appt.roomCode}</code>) has been marked as <strong>${status}</strong>.`
          : `Your response (<strong>${status}</strong>) has been recorded for Linda Milewski, LCSW.`
      }
    </p>
    <div class="pt-4 flex flex-col gap-2">
      ${
        appt && status === "Confirmed"
          ? `<a href="/index.html?room=${encodeURIComponent(appt.roomCode)}#telehealth" class="bg-[#416244] hover:bg-[#354f37] text-white font-semibold py-3 px-5 rounded-xl text-sm transition">Open Virtual Waiting Room (${appt.roomCode})</a>`
          : ""
      }
      <a href="/index.html" class="text-xs text-[#557c58] hover:underline pt-1">Return to Website</a>
    </div>
  </div>
</body>
</html>`;

      return new Response(htmlPage, {
        headers: { "Content-Type": "text/html;charset=utf-8" },
      });
    }

    // 3. Public Contact Form Submission -> Sends Email & Logs to Portal Inbox
    if (url.pathname === "/api/public-contact" && request.method === "POST") {
      try {
        const body = await request.json();
        const { name, email, phone, preferred_reply_method, service_interest, referral_source, message } = body;
        const stub = getAdminStoreStub(env);

        const subject = `Website Inquiry: ${service_interest || "Consultation"} - ${name}`;
        const textBody = `New Website Contact Inquiry:\nName: ${name}\nEmail: ${email}\nPhone:${phone || "Not provided"}\nPreferred Reply: ${preferred_reply_method}\nService:${service_interest}\nReferral: ${referral_source}\n\nMessage:\n${message}`;

        // Save to Linda's Portal Inbox
        await stub.fetch(
          new Request("https://internal/internal/emails", {
            method: "POST",
            headers: jsonHeaders,
            body: JSON.stringify({
              email: {
                id: crypto.randomUUID(),
                direction: "inbound",
                timestamp: new Date().toISOString(),
                from: `${name} <${email}>`,
                to: env.SENDER_EMAIL || "Practice Inbox",
                subject,
                body: textBody,
              },
            }),
          }),
        );

        // If Cloudflare Email Service is configured & FORWARD_TO_EMAIL is set, send notification email
        if (env.EMAIL && env.SENDER_EMAIL && env.FORWARD_TO_EMAIL) {
          try {
            await env.EMAIL.send({
              from: env.SENDER_EMAIL,
              to: env.FORWARD_TO_EMAIL,
              replyTo: email,
              subject,
              text: textBody,
            });
          } catch (e) {
            console.warn("Cloudflare EMAIL notification warning:", e);
          }
        }

        return new Response(JSON.stringify({ ok: true }), { headers: jsonHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ ok: false, error: String(err) }), {
          status: 500,
          headers: jsonHeaders,
        });
      }
    }

    // 4. Protected Outbound Email Endpoint (Appointment Confirmation Emails & Custom Emails)
    if (url.pathname === "/api/send-email" && request.method === "POST") {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }

      try {
        const payload = await request.json();
        const { to, subject, text, html, appointment } = payload;

        const senderAddress = env.SENDER_EMAIL || `confirm@${url.hostname}`;
        let finalSubject = subject;
        let finalHtml = html;
        let finalText = text;

        // If sending an Appointment Confirmation request, build rich confirmation email with 1-click + reply support
        if (appointment) {
          const confirmUrl = `${url.origin}/api/confirm-appointment?id=${encodeURIComponent(appointment.id)}&room=${encodeURIComponent(appointment.roomCode)}&action=confirm`;
          const rescheduleUrl = `${url.origin}/api/confirm-appointment?id=${encodeURIComponent(appointment.id)}&room=${encodeURIComponent(appointment.roomCode)}&action=reschedule`;
          const waitingRoomUrl = `${url.origin}/index.html?room=${encodeURIComponent(appointment.roomCode)}#telehealth`;

          finalSubject =
            subject ||
            `Appointment Confirmation [${appointment.roomCode}]: ${appointment.date} at ${appointment.time} with Linda Milewski, LCSW`;

          finalText =
            text ||
            `Hi ${appointment.clientName},\n\n` +
              `You have an upcoming appointment scheduled with Linda Milewski, LCSW:\n\n` +
              `• Date: ${appointment.date}\n` +
              `• Time: ${appointment.time} (${appointment.duration} mins)\n` +
              `• Service: ${appointment.service}\n` +
              `• Telehealth Room Code: ${appointment.roomCode}\n` +
              `• Video Waiting Room: ${waitingRoomUrl}\n\n` +
              `PLEASE CONFIRM YOUR APPOINTMENT:\n` +
              `1. Click here to confirm immediately: ${confirmUrl}\n` +
              `2. Or simply REPLY to this email with the word "CONFIRM".\n\n` +
              `Need to reschedule? Click here: ${rescheduleUrl} or reply to this email.\n\n` +
              `Warmly,\nLinda Milewski, LCSW`;

          finalHtml = `
            <div style="font-family: 'Inter', Helvetica, Arial, sans-serif; max-width: 580px; margin: 0 auto; background: #fdfcfa; border: 1px solid #e4d9c5; border-radius: 16px; padding: 32px; color: #2c352d;">
              <h2 style="font-family: Georgia, serif; color: #253527; margin-top: 0;">Appointment Confirmation Request</h2>
              <p>Hi <strong>${appointment.clientName}</strong>,</p>
              <p>You have an upcoming session scheduled with <strong>Linda Milewski, LCSW</strong>:</p>
              <div style="background: #f4f7f4; border: 1px solid #c9d8c9; border-radius: 12px; padding: 16px; margin: 20px 0;">
                <p style="margin: 4px 0;"><strong>Date:</strong> ${appointment.date}</p>
                <p style="margin: 4px 0;"><strong>Time:</strong> ${appointment.time} (${appointment.duration} mins)</p>
                <p style="margin: 4px 0;"><strong>Service:</strong> ${appointment.service}</p>
                <p style="margin: 4px 0;"><strong>Telehealth Room Code:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 4px;">${appointment.roomCode}</code></p>
              </div>
              <p style="margin-bottom: 16px;"><strong>Please confirm your attendance using either option below:</strong></p>
              <div style="margin: 24px 0;">
                <a href="${confirmUrl}" style="background: #416244; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 10px; font-weight: 600; display: inline-block; margin-right: 10px;">
                  ✓ Confirm Appointment
                </a>
                <a href="${rescheduleUrl}" style="background: #f8f5ef; color: #354f37; border: 1px solid #d3c1a3; text-decoration: none; padding: 12px 18px; border-radius: 10px; font-weight: 500; display: inline-block;">
                  Request Reschedule
                </a>
              </div>
              <p style="font-size: 13px; color: #557c58;">
                <em>Tip: You can also confirm simply by <strong>replying "CONFIRM"</strong> directly to this email.</em>
              </p>
              <hr style="border: none; border-top: 1px solid #e4d9c5; margin: 24px 0;">
              <p style="font-size: 13px; color: #354f37;">
                At the time of your session, join the video waiting room here:<br>
                <a href="${waitingRoomUrl}" style="color: #416244;">${waitingRoomUrl}</a>
              </p>
            </div>
          `;
        }

        let deliveryStatus = "Logged to Portal (Configure SENDER_EMAIL / Cloudflare Email Service for live SMTP)";
        let sentViaCloudflare = false;

        if (env.EMAIL) {
          try {
            await env.EMAIL.send({
              to,
              from: senderAddress,
              replyTo: senderAddress,
              subject: finalSubject,
              text: finalText,
              html: finalHtml || `<p>${(finalText || "").replace(/\n/g, "<br>")}</p>`,
            });
            deliveryStatus = "Delivered via Cloudflare Email Service";
            sentViaCloudflare = true;
          } catch (sendErr) {
            console.error("Cloudflare env.EMAIL.send error:", sendErr);
            deliveryStatus = `Saved in Portal (Email binding notice: ${sendErr.message || sendErr})`;
          }
        }

        // Save outbound email in Durable Object Email Log & update appointment status if applicable
        const stub = getAdminStoreStub(env);
        await stub.fetch(
          new Request("https://internal/internal/emails", {
            method: "POST",
            headers: jsonHeaders,
            body: JSON.stringify({
              email: {
                id: crypto.randomUUID(),
                direction: "outbound",
                timestamp: new Date().toISOString(),
                from: senderAddress,
                to,
                subject: finalSubject,
                body: finalText,
                deliveryStatus,
              },
            }),
          }),
        );

        return new Response(
          JSON.stringify({
            ok: true,
            sentViaCloudflare,
            deliveryStatus,
          }),
          { headers: jsonHeaders },
        );
      } catch (err) {
        return new Response(
          JSON.stringify({ ok: false, error: String(err) }),
          { status: 500, headers: jsonHeaders },
        );
      }
    }

    // 5. Protected Clinician Portal Storage Endpoints (Appointments, Hours, Emails)
    if (
      url.pathname === "/api/appointments" ||
      url.pathname === "/api/hours" ||
      url.pathname === "/api/emails"
    ) {
      if (!(await isAuthorized(request, env))) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const stub = getAdminStoreStub(env);
      const targetPath = url.pathname.replace("/api/", "/internal/");
      const internalUrl = new URL(targetPath + url.search, request.url);
      return stub.fetch(new Request(internalUrl, request));
    }

    // 6. STUN + Cloudflare TURN Credentials Endpoint
    if (url.pathname === "/turn/credentials" || url.pathname === "/ice-servers") {
      const defaultIceServers = [
        { urls: "stun:stun.cloudflare.com:3478" },
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
      ];

      if (env.TURN_KEY_ID && env.TURN_API_TOKEN) {
        try {
          const cfRes = await fetch(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`,
            {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.TURN_API_TOKEN}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ ttl: 86400 }),
            },
          );
          if (cfRes.ok) {
            const data = await cfRes.json();
            return new Response(JSON.stringify(data), { headers: jsonHeaders });
          }
        } catch (err) {
          console.error("Failed to fetch Cloudflare TURN credentials:", err);
        }
      }

      return new Response(JSON.stringify({ iceServers: defaultIceServers }), {
        headers: jsonHeaders,
      });
    }

    // 7. WebSocket Signaling Endpoint
    if (url.pathname === "/ws" && request.headers.get("Upgrade") === "websocket") {
      const roomId = url.searchParams.get("room") || "default";
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 8. Static Assets Fallback
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(processAppointmentReminders(env).catch((error) => {
      console.error("Scheduled appointment reminder check failed:", error);
    }));
  },

  // ===========================================================================
  // INBOUND EMAIL HANDLER (Cloudflare Email Routing -> Appointment Confirmation)
  // ===========================================================================
  async email(message, env, ctx) {
    try {
      const fromEmail = message.from || "";
      const subject = message.headers.get("subject") || "(No Subject)";
      const rawMime = await new Response(message.raw).text();
      const plainText = extractPlainTextFromMime(rawMime);

      // Look for a Room Code like LINDA-123 in the subject or body
      const roomMatch =
        subject.match(/LINDA-\d+/i) || plainText.match(/LINDA-\d+/i);
      const roomCode = roomMatch ? roomMatch[0].toUpperCase() : "";

      // Determine whether the client is confirming or asking to reschedule/cancel
      const lowerContent = `${subject}${plainText}`.toLowerCase();
      let newStatus = "Confirmed";
      if (
        lowerContent.includes("cancel") ||
        lowerContent.includes("reschedule") ||
        lowerContent.includes("cannot make") ||
        lowerContent.includes("can't make")
      ) {
        newStatus = "Reschedule Requested";
      }

      // Update appointment & log incoming email in Durable Object
      const stub = getAdminStoreStub(env);
      await stub.fetch(
        new Request("https://internal/internal/process-confirmation", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            roomCode,
            fromEmail,
            status: newStatus,
            rawSubject: subject,
            rawText: plainText,
            method: "Inbound Email Reply",
          }),
        }),
      );

      // Optional: Forward a copy to Linda's personal email if configured
      if (env.FORWARD_TO_EMAIL) {
        await message.forward(env.FORWARD_TO_EMAIL);
      }
    } catch (err) {
      console.error("Error processing inbound email:", err);
    }
  },
};