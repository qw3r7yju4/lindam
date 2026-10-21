import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      // Never reach out to real Cloudflare resources (e.g. the remote EMAIL binding) from tests.
      remoteBindings: false,
      miniflare: {
        bindings: {
          ADMIN_BOOTSTRAP_USERNAME: "testadmin",
          ADMIN_BOOTSTRAP_PASSWORD: "test-admin-password-123",
          ADMIN_BOOTSTRAP_EMAIL: "admin@example.com",
          SQUARE_WEBHOOK_SIGNATURE_KEY: "test-square-signature-key",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});

