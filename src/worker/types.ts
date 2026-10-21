import type { DurableObjectNamespace, Fetcher, SendEmail } from "@cloudflare/workers-types";

export interface Env {
  ASSETS?: Fetcher;
  CHAT_ROOM: DurableObjectNamespace;
  EMAIL?: SendEmail;
  ADMIN_BOOTSTRAP_USERNAME?: string;
  ADMIN_BOOTSTRAP_PASSWORD?: string;
  ADMIN_BOOTSTRAP_EMAIL?: string;
  SQUARE_ACCESS_TOKEN?: string;
  SQUARE_LOCATION_ID?: string;
  SQUARE_WEBHOOK_SIGNATURE_KEY?: string;
  SQUARE_WEBHOOK_NOTIFICATION_URL?: string;
  FORWARD_TO_EMAIL?: string;
  SENDER_EMAIL?: string;
  PUBLIC_SITE_URL?: string;
}

export type UserRole = "admin" | "staff" | "client";

export interface User {
  id: string;
  username: string;
  email: string;
  displayName: string;
  role: UserRole;
  active: boolean;
  passwordHash?: string;
  passwordSalt?: string;
  mfaEnabled?: boolean;
  createdAt?: number;
  updatedAt?: number;
}

export type AppointmentStatus =
  | "Awaiting Confirmation"
  | "Confirmed"
  | "Completed"
  | "Cancelled"
  | "Reschedule Requested";

export type PaymentStatus = "Pending" | "Paid" | "Refunded" | "None";

export interface Appointment {
  id: string;
  clientName: string;
  clientEmail: string;
  clientPhone?: string;
  hostUserId: string;
  date: string; // YYYY-MM-DD
  time: string; // HH:MM
  timeZone: string;
  duration: number; // minutes
  service: string;
  roomCode: string;
  status: AppointmentStatus;
  reminderEnabled: boolean;
  notes?: string;
  paymentStatus?: PaymentStatus;
  paymentAmount?: number; // cents
  paymentLinkId?: string;
  paymentUrl?: string;
  orderId?: string;
  squarePaymentId?: string;
  createdAt?: number;
  updatedAt?: number;
}

export interface AvailabilitySlot {
  start: string;
  end: string;
}

export interface ClinicianAvailability {
  weekdays: Record<string, AvailabilitySlot[]>; // "0" through "6"
  exceptions: Array<{ date: string; slots: AvailabilitySlot[] }>;
}

export interface SessionData {
  userId: string;
  role: UserRole;
  expiresAt: number;
  createdAt: number;
}

export interface SquarePaymentLinkResult {
  paymentLinkId: string;
  paymentUrl: string;
  orderId: string;
  amount: number;
  currency: string;
}
