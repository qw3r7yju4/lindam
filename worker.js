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

    // 1. Appointments CRUD
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
        emails.unshift(emailEntry);
        // Keep latest 200 emails
        const trimmed = emails.slice(0, 200);
        await this.ctx.storage.put("emails", trimmed);
        return new Response(JSON.stringify({ emails: trimmed }), { headers: jsonHeaders });
      }
      if (request.method === "DELETE") {
        const id = url.searchParams.get("id");
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
        subject: rawSubject || `Appointment ${status \vert{}\vert{} "Confirmed"} (${matchedAppt ? matchedAppt.roomCode : "Link"})`,
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

function isAuthorized(request) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "").trim();
  const expectedToken = btoa(`${ADMIN_USER}:${ADMIN_PASS}`);
  return token === expectedToken;
}

function getAdminStoreStub(env) {
  const adminStoreId = env.CHAT_ROOM.idFromName("__LINDA_ADMIN_PORTAL_STORE__");
  return env.CHAT_ROOM.get(adminStoreId);
}

// Helper: Extract plain text from raw MIME email without external dependencies
function extractPlainTextFromMime(rawEmailText) {
  if (!rawEmailText) return "";
  // Split headers and body
  const parts = rawEmailText.split(/\r?\n\r?\n/);
  if (parts.length < 2) return rawEmailText.slice(0, 1000);
  const bodyContent = parts.slice(1).join("\n\n");
  // Strip HTML tags and MIME boundary noise for a clean preview
  return bodyContent
    .replace(/--[^\r\n]+/g, "")
    .replace(/Content-[^\r\n]+/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 1500);
}

export default {
  // ===========================================================================
  // HTTP FETCH HANDLER (Website, Portal APIs, Outbound Email, & WebRTC)
  // ===========================================================================
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
  <script src="https://cdn.tailwindcss.com"></script>
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

        const subject = `Website Inquiry: ${service_interest \vert{}\vert{} "Consultation"} - ${name}`;
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
      if (!isAuthorized(request)) {
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
            `Appointment Confirmation [${appointment.roomCode}]: ${appointment.date} at${appointment.time} with Linda Milewski, LCSW`;

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
      if (!isAuthorized(request)) {
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