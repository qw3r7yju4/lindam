import { DurableObject } from "cloudflare:workers";

export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong"),
    );
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const url = new URL(request.url);
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Endpoint to provide STUN + Cloudflare TURN credentials to the browser
    if (url.pathname === "/turn/credentials") {
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
            return new Response(JSON.stringify(data), {
              headers: { "Content-Type": "application/json" },
            });
          }
        } catch (err) {
          console.error("Failed to fetch Cloudflare TURN credentials:", err);
        }
      }

      return new Response(
        JSON.stringify({ iceServers: defaultIceServers }),
        { headers: { "Content-Type": "application/json" } },
      );
    }

    // 2. WebSocket Signaling Endpoint
    if (url.pathname === "/ws" && request.headers.get("Upgrade") === "websocket") {
      const roomId = url.searchParams.get("room") || "default";
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 3. Static Assets Fallback (if using Workers Assets)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};