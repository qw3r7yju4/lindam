import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

// Integration tests that exercise the Worker exactly as a browser would, through fetch().
// They were written against the original worker.js and must keep passing after refactors.

const ORIGIN = "https://lindam.klutchplay.com";
const ADMIN = { username: "testadmin", password: "test-admin-password-123" };
const SQUARE_KEY = "test-square-signature-key";
const SQUARE_URL = "https://lindam.klutchplay.com/api/square/webhook";

type CallInit = RequestInit & { cookie?: string; json?: unknown };

async function call(path: string, init: CallInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.cookie) headers.set("Cookie", init.cookie);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  return (exports as any).default.fetch(new Request(ORIGIN + path, { ...init, headers, body }));
}

function sessionCookie(res: Response): string {
  const header = res.headers.get("Set-Cookie") || "";
  return header.split(";")[0];
}

function easternDate(offsetDays: number): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/New_York",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(Date.now() + offsetDays * 24 * 60 * 60 * 1000));
}

async function adminLogin(): Promise<{ cookie: string; user: any }> {
  const res = await call("/api/login", { method: "POST", json: ADMIN });
  expect(res.status).toBe(200);
  const body: any = await res.json();
  return { cookie: sessionCookie(res), user: body.user };
}

const fullWeek = Object.fromEntries(
  ["0", "1", "2", "3", "4", "5", "6"].map((day) => [day, [{ start: "09:00", end: "17:00" }]]),
);

async function setAvailability(cookie: string) {
  const res = await call("/api/availability", {
    method: "POST",
    cookie,
    json: { availability: { weekdays: fullWeek, exceptions: [] } },
  });
  expect(res.status).toBe(200);
}

// Durable Object storage is shared by every test in this file, so each appointment gets its own day.
let nextAppointmentDay = 10;

async function createAppointment(cookie: string, hostUserId: string, overrides: Record<string, unknown> = {}) {
  const appointment = {
    id: crypto.randomUUID(),
    clientName: "Test Client",
    clientEmail: "client@example.com",
    hostUserId,
    date: easternDate(nextAppointmentDay++),
    time: "10:00",
    timeZone: "America/New_York",
    duration: 50,
    service: "Individual Psychotherapy",
    roomCode: `LINDA-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    status: "Awaiting Confirmation",
    reminderEnabled: false,
    ...overrides,
  };
  const res = await call("/api/appointments", { method: "POST", cookie, json: { appointment } });
  expect(res.status).toBe(200);
  return appointment;
}

async function squareSignature(body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SQUARE_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(SQUARE_URL + body));
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

describe("static site", () => {
  it("serves the public pages", async () => {
    const res = await call("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    await res.arrayBuffer();
  });
});

describe("portal authentication", () => {
  it("bootstraps the first administrator and issues a hardened session cookie", async () => {
    const res = await call("/api/login", { method: "POST", json: ADMIN });
    expect(res.status).toBe(200);
    const body: any = await res.json();
    expect(body.user).toMatchObject({ username: "testadmin", role: "admin", email: "admin@example.com" });
    const setCookie = res.headers.get("Set-Cookie") || "";
    expect(setCookie).toMatch(/^linda_portal_session=[a-f0-9]{64};/);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).toContain("Secure");

    const session = await call("/api/session", { cookie: sessionCookie(res) });
    expect(session.status).toBe(200);
    expect(((await session.json()) as any).user.username).toBe("testadmin");
  });

  it("rejects bad passwords", async () => {
    await adminLogin();
    const res = await call("/api/login", { method: "POST", json: { ...ADMIN, password: "wrong-password-xyz" } });
    expect(res.status).toBe(401);
  });

  it("rejects cross-origin state-changing requests", async () => {
    const res = await call("/api/login", { method: "POST", json: ADMIN, headers: { Origin: "https://evil.example" } });
    expect(res.status).toBe(403);
  });

  it("requires a session for protected endpoints", async () => {
    for (const path of ["/api/appointments", "/api/hours", "/api/emails", "/api/users", "/api/availability"]) {
      const res = await call(path);
      expect(res.status, path).toBe(401);
      await res.arrayBuffer();
    }
  });

  it("logs out and invalidates the session", async () => {
    const { cookie } = await adminLogin();
    const out = await call("/api/logout", { method: "POST", cookie });
    expect(out.status).toBe(200);
    expect(out.headers.get("Set-Cookie")).toContain("Max-Age=0");
    const session = await call("/api/session", { cookie });
    expect(session.status).toBe(401);
  });

  it("changes the password and rotates the session", async () => {
    const { cookie } = await adminLogin();
    const res = await call("/api/change-password", {
      method: "POST",
      cookie,
      json: { currentPassword: ADMIN.password, newPassword: "a-brand-new-password-456" },
    });
    expect(res.status).toBe(200);
    const newCookie = sessionCookie(res);
    expect(newCookie).not.toBe(cookie);
    expect((await call("/api/session", { cookie })).status).toBe(401);
    expect((await call("/api/session", { cookie: newCookie })).status).toBe(200);
    const relogin = await call("/api/login", {
      method: "POST",
      json: { username: ADMIN.username, password: "a-brand-new-password-456" },
    });
    expect(relogin.status).toBe(200);
    // Restore the original password for the remaining tests (storage is shared).
    const restore = await call("/api/change-password", {
      method: "POST",
      cookie: sessionCookie(relogin),
      json: { currentPassword: "a-brand-new-password-456", newPassword: ADMIN.password },
    });
    expect(restore.status).toBe(200);
  });
});

describe("portal data", () => {
  it("stores and lists appointments", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const appointment = await createAppointment(cookie, user.id);
    const res = await call("/api/appointments", { cookie });
    expect(res.status).toBe(200);
    const body: any = await res.json();
    expect(body.appointments.map((item: any) => item.id)).toContain(appointment.id);
  });

  it("rejects overlapping appointments for the same clinician", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const existing = await createAppointment(cookie, user.id, { time: "11:00" });
    const res = await call("/api/appointments", {
      method: "POST",
      cookie,
      json: {
        appointment: {
          id: crypto.randomUUID(),
          clientEmail: "other@example.com",
          hostUserId: user.id,
          date: existing.date,
          time: "11:30",
          duration: 50,
          roomCode: "LINDA-OVERLAP1",
        },
      },
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toContain("overlaps");
  });

  it("supports bulk appointment saves while preserving order", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const a = await createAppointment(cookie, user.id, { time: "09:00" });
    const b = await createAppointment(cookie, user.id, { time: "13:00" });
    const list: any = await (await call("/api/appointments", { cookie })).json();
    const reordered = [...list.appointments].reverse().map((item: any) =>
      item.id === a.id ? { ...item, notes: "updated" } : item
    );
    const res = await call("/api/appointments", { method: "POST", cookie, json: { appointments: reordered } });
    expect(res.status).toBe(200);
    const after: any = await (await call("/api/appointments", { cookie })).json();
    expect(after.appointments.map((item: any) => item.id)).toEqual(reordered.map((item: any) => item.id));
    const ids = after.appointments.map((item: any) => item.id);
    expect(ids.indexOf(b.id)).toBeLessThan(ids.indexOf(a.id));
    expect(after.appointments.find((item: any) => item.id === a.id).notes).toBe("updated");
  });

  it("marks appointments completed instead of deleting them", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const appointment = await createAppointment(cookie, user.id);
    const res = await call(`/api/appointments?id=${appointment.id}`, { method: "DELETE", cookie });
    expect(res.status).toBe(200);
    const body: any = await res.json();
    expect(body.appointments.find((item: any) => item.id === appointment.id).status).toBe("Completed");
  });

  it("tracks clinical hours", async () => {
    const { cookie } = await adminLogin();
    const first = { id: "h1", date: "2026-01-01", hours: 2 };
    const second = { id: "h2", date: "2026-01-02", hours: 3 };
    await call("/api/hours", { method: "POST", cookie, json: { entry: first } });
    const res = await call("/api/hours", { method: "POST", cookie, json: { entry: second } });
    expect(((await res.json()) as any).hours.map((h: any) => h.id)).toEqual(["h2", "h1"]);
    const updated = await call("/api/hours", { method: "POST", cookie, json: { entry: { ...first, hours: 5 } } });
    expect(((await updated.json()) as any).hours).toEqual([second, { ...first, hours: 5 }]);
    const deleted = await call("/api/hours?id=h2", { method: "DELETE", cookie });
    expect(((await deleted.json()) as any).hours.map((h: any) => h.id)).toEqual(["h1"]);
  });

  it("logs public contact messages to the portal inbox", async () => {
    const { cookie } = await adminLogin();
    const res = await call("/api/public-contact", {
      method: "POST",
      json: { name: "Pat", email: "pat@example.com", message: "Hello there", service_interest: "Consultation" },
    });
    expect(res.status).toBe(200);
    const inbox: any = await (await call("/api/emails", { cookie })).json();
    expect(inbox.emails[0]).toMatchObject({ direction: "inbound", from: "Pat <pat@example.com>" });
    const id = inbox.emails[0].id;
    const deleted: any = await (await call(`/api/emails?id=${id}`, { method: "DELETE", cookie })).json();
    expect(deleted.emails.find((item: any) => item.id === id)).toBeUndefined();
  });

  it("confirms appointments through the one-click email link", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const appointment = await createAppointment(cookie, user.id);
    const res = await call(`/api/confirm-appointment?id=${appointment.id}&action=confirm`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Appointment Confirmed!");
    const list: any = await (await call("/api/appointments", { cookie })).json();
    expect(list.appointments.find((item: any) => item.id === appointment.id).status).toBe("Confirmed");
  });
});

describe("client accounts", () => {
  it("lets a client sign in, see availability, and book a free consultation", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const created = await call("/api/users", {
      method: "POST",
      cookie,
      json: {
        username: "client1",
        displayName: "Client One",
        email: "client1@example.com",
        password: "client-password-123",
        role: "client",
      },
    });
    expect(created.status).toBe(201);

    const login = await call("/api/client/login", {
      method: "POST",
      json: { username: "client1@example.com", password: "client-password-123" },
    });
    expect(login.status).toBe(200);
    const clientCookie = sessionCookie(login);
    expect(clientCookie).toMatch(/^linda_client_session=/);

    // A client session must not unlock the clinician portal.
    expect((await call("/api/session", { cookie: clientCookie })).status).toBe(401);

    const date = easternDate(5);
    const service = "Free 15-Minute Consultation";
    const availability = await call(
      `/api/client/availability?date=${date}&service=${encodeURIComponent(service)}`,
      { cookie: clientCookie },
    );
    expect(availability.status).toBe(200);
    const slots: any = await availability.json();
    expect(slots.clinicians[0].id).toBe(user.id);
    expect(slots.clinicians[0].slots).toContain("09:00");

    const booking = await call("/api/client/appointments", {
      method: "POST",
      cookie: clientCookie,
      json: { service, hostUserId: user.id, date, time: "09:00" },
    });
    expect(booking.status).toBe(201);
    const booked: any = await booking.json();
    expect(booked.appointment).toMatchObject({ date, time: "09:00", status: "Awaiting Confirmation" });

    const mine: any = await (await call("/api/client/appointments", { cookie: clientCookie })).json();
    expect(mine.appointments).toHaveLength(1);
    expect(mine.appointments[0].roomCode).toMatch(/^LINDA-[0-9A-F]{16}$/);

    const slotsAfter: any = await (await call(
      `/api/client/availability?date=${date}&service=${encodeURIComponent(service)}`,
      { cookie: clientCookie },
    )).json();
    expect(slotsAfter.clinicians[0].slots).not.toContain("09:00");
  });
});

describe("video sessions", () => {
  it("only opens signaling sockets for active appointment room codes", async () => {
    const { cookie, user } = await adminLogin();
    await setAvailability(cookie);
    const appointment = await createAppointment(cookie, user.id);

    const denied = await call("/ws?room=LINDA-NOPE&name=x", { headers: { Upgrade: "websocket" } });
    expect(denied.status).toBe(403);
    await denied.arrayBuffer();

    const res = await call(`/ws?room=${appointment.roomCode}&name=Tester`, { headers: { Upgrade: "websocket" } });
    expect(res.status).toBe(101);
    const socket = res.webSocket!;
    const firstMessage = new Promise<any>((resolve) => {
      socket.addEventListener("message", (event) => resolve(JSON.parse(event.data as string)));
    });
    socket.accept();
    expect(await firstMessage).toMatchObject({ type: "connected", peerCount: 0 });
    socket.close();
  });
});

describe("square payments", () => {
  it("rejects webhooks with an invalid signature", async () => {
    const res = await call("/api/square/webhook", {
      method: "POST",
      body: JSON.stringify({ event_id: "evt1", type: "payment.updated" }),
      headers: { "x-square-hmacsha256-signature": "bogus" },
    });
    expect(res.status).toBe(401);
  });

  it("accepts signed webhooks and deduplicates events", async () => {
    const body = JSON.stringify({ event_id: "evt-123", type: "payment.updated", data: { object: { payment: { id: "p1", order_id: "o1", status: "COMPLETED" } } } });
    const signature = await squareSignature(body);
    const first = await call("/api/square/webhook", { method: "POST", body, headers: { "x-square-hmacsha256-signature": signature } });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ ok: true, matched: false });
    const again = await call("/api/square/webhook", { method: "POST", body, headers: { "x-square-hmacsha256-signature": signature } });
    expect(await again.json()).toMatchObject({ ok: true, duplicate: true });
  });
});

