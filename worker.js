import { DurableObject } from "cloudflare:workers";

const ADMIN_USER = "lmilewski";
const ADMIN_PASS = "chrysalis63";

export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
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

  async handleInternalStorage(request, url) {
    const jsonHeaders = { "Content-Type": "application/json" };

    // Appointments CRUD
    if (url.pathname === "/internal/appointments") {
      const appointments = (await this.ctx.storage.get("appointments")) || [];
      if (request.method === "GET") {
        return new Response(JSON.stringify({ appointments }), { headers: jsonHeaders });
      }
      if (request.method === "POST") {
        const body = await request.json();
        if (Array.isArray(body.appointments)) {
          await this.ctx.storage.put("appointments", body.appointments);
          return new Response(JSON.stringify({ appointments: body.appointments }), { headers: jsonHeaders });
        }
        const item = body.appointment;
        const idx = appointments.findIndex((a) => a.id === item.id);
        if (idx >= 0) {
          appointments[idx] = item;
        } else {
          appointments.push(item);
        }
        await this.ctx.storage.put("appointments", appointments);
        return new Response(JSON.stringify({ appointments }), { headers: jsonHeaders });
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
        const filtered = appointments.filter((a) => a.id !== id);
        await this.ctx.storage.put("appointments", filtered);
        return new Response(JSON.stringify({ appointments: filtered }), { headers: jsonHeaders });
      }
    }

    // Clinical Hours Tracker CRUD
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

function isAuthorized(request) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "").trim();
  const expectedToken = btoa(`${ADMIN_USER}:${ADMIN_PASS}`);
  return token === expectedToken;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const jsonHeaders = { "Content-Type": "application/json" };

    // 1. Clinician Login Endpoint
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const { username, password } = await request.json();
        if (
          typeof username === "string" &&
          username.trim().toLowerCase() === ADMIN_USER &&
          password === ADMIN_PASS
        ) {
          const token = btoa(`${ADMIN_USER}:${ADMIN_PASS}`);
          return new Response(
            JSON.stringify({
              ok: true,
              token,
              user: { username: ADMIN_USER, displayName: "Linda Milewski, LCSW" },
            }),
            { headers: jsonHeaders },
          );
        }
        return new Response(
          JSON.stringify({ ok: false, error: "Invalid username or password." }),
          { status: 401, headers: jsonHeaders },
        );
      } catch {
        return new Response(
          JSON.stringify({ ok: false, error: "Invalid request payload." }),
          { status: 400, headers: jsonHeaders },
        );
      }
    }

    // 2. Protected Clinician Portal Storage Endpoints (Appointments & Hours)
    if (url.pathname === "/api/appointments" || url.pathname === "/api/hours") {
      if (!isAuthorized(request)) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: jsonHeaders,
        });
      }
      const adminStoreId = env.CHAT_ROOM.idFromName("__LINDA_ADMIN_PORTAL_STORE__");
      const stub = env.CHAT_ROOM.get(adminStoreId);
      const targetPath = url.pathname.replace("/api/", "/internal/");
      const internalUrl = new URL(targetPath + url.search, request.url);
      return stub.fetch(new Request(internalUrl, request));
    }

    // 3. STUN + Cloudflare TURN Credentials Endpoint
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

    // 4. WebSocket Signaling Endpoint
    if (url.pathname === "/ws" && request.headers.get("Upgrade") === "websocket") {
      const roomId = url.searchParams.get("room") || "default";
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 5. Static Assets Fallback
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};