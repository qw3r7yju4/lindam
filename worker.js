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
    server.serializeAttachment({ clientId, clientName });

    this.ctx.acceptWebSocket(server);

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

    // If the message is targeted to a specific peer (offer, answer, ice-candidate), send only to that peer
    if (data.targetPeerId) {
      for (const recipient of otherSockets) {
        const attachment = recipient.deserializeAttachment();
        if (attachment?.clientId === data.targetPeerId) {
          recipient.send(outgoingPayload);
          break;
        }
      }
    } else {
      // Otherwise broadcast to all other peers in the room (e.g., chat messages)
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

    if (url.pathname === "/ws" && request.headers.get("Upgrade") === "websocket") {
      const roomId = url.searchParams.get("room") || "default";
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // Serve static files if Cloudflare Workers Assets binding is present
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};