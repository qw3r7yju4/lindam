import type { Appointment, Env, SquarePaymentLinkResult } from "./types";

export const SQUARE_API_BASE_URL = "https://connect.squareup.com";
export const SQUARE_API_VERSION = "2025-10-16";

export const APPOINTMENT_PRICES: Readonly<Record<string, number>> = Object.freeze({
  "Free 15-Minute Consultation": 0,
  "Individual Psychotherapy": 15450,
  "Anxiety & Burnout Recovery": 15450,
  "Life Transitions & Relationships": 19055,
});

export function getAppointmentPrice(service: string): number | null {
  return Object.hasOwn(APPOINTMENT_PRICES, service) ? APPOINTMENT_PRICES[service] : null;
}

export function formatUsdAmount(amountCents: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(amountCents / 100);
}

export async function getSquareIdempotencyKey(scope: string, value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${scope}:${value}`));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${scope}-${hash.slice(0, 32)}`;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aBuffer = new TextEncoder().encode(a);
  const bBuffer = new TextEncoder().encode(b);
  if (aBuffer.byteLength !== bBuffer.byteLength) return false;
  let mismatch = 0;
  for (let i = 0; i < aBuffer.byteLength; i += 1) {
    mismatch |= aBuffer[i] ^ bBuffer[i];
  }
  return mismatch === 0;
}

export async function createSquarePaymentLink(
  env: Env,
  appointment: Appointment
): Promise<SquarePaymentLinkResult> {
  if (!env.SQUARE_ACCESS_TOKEN || !env.SQUARE_LOCATION_ID) {
    throw new Error("Square production payments are not configured. Set SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID.");
  }
  const price = getAppointmentPrice(appointment.service);
  if (!Number.isInteger(price) || price === null || price <= 0) {
    throw new Error("This appointment does not have a payable service price.");
  }
  const origin = env.PUBLIC_SITE_URL || "https://lindam.klutchplay.com";
  const response = await fetch(`${SQUARE_API_BASE_URL}/v2/online-checkout/payment-links`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.SQUARE_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
      "Square-Version": SQUARE_API_VERSION,
    },
    body: JSON.stringify({
      idempotency_key: await getSquareIdempotencyKey("appt", appointment.id),
      order: {
        location_id: env.SQUARE_LOCATION_ID,
        line_items: [
          {
            name: "Appointment payment",
            quantity: "1",
            base_price_money: { amount: price, currency: "USD" },
          },
        ],
      },
      checkout_options: {
        redirect_url: `${origin}/appointments.html?payment=return`,
      },
      ...(appointment.clientEmail ? { pre_populated_data: { buyer_email: appointment.clientEmail } } : {}),
    }),
    signal: AbortSignal.timeout(10000),
  });

  const result: any = await response.json();
  if (!response.ok || !result.payment_link?.url || !result.payment_link?.order_id) {
    console.error("Square payment link creation failed:", JSON.stringify(result.errors || result));
    throw new Error("Square could not create the payment link. Check the payment setup and try again.");
  }

  return {
    paymentLinkId: result.payment_link.id,
    paymentUrl: result.payment_link.url,
    orderId: result.payment_link.order_id,
    amount: price,
    currency: "USD",
  };
}

export async function verifySquareWebhookSignature(
  request: Request,
  env: Env,
  rawBody: string
): Promise<boolean> {
  const signature = request.headers.get("x-square-hmacsha256-signature") || "";
  const notificationUrl = env.SQUARE_WEBHOOK_NOTIFICATION_URL || "";
  if (!env.SQUARE_WEBHOOK_SIGNATURE_KEY || !notificationUrl || !signature) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SQUARE_WEBHOOK_SIGNATURE_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const digest = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(notificationUrl + rawBody)
  );
  const expected = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return constantTimeEqual(expected, signature);
}
