# Square production payments setup

The appointment portal creates Square-hosted USD checkout links for paid services. The free 15-minute consultation remains free. Client requests remain awaiting practice confirmation after payment. Admin and staff can see payment status, receipts, and history. To process a cancellation, set the appointment status to **Canceled** in the Clinician Portal; a full-refund control is then available only if the appointment is at least 24 hours away.

## Configure Square and Cloudflare

1. In the Square Developer Dashboard, select the production application and copy its production access token. Also find the Square location ID for the practice.
2. In the Cloudflare dashboard, open the `lindam` Worker and add `SQUARE_LOCATION_ID` as a Worker variable. Set it to the practice's Square location ID.
3. From the repository directory, add the production access token as a Worker secret:

   ```powershell
   npx wrangler secret put SQUARE_ACCESS_TOKEN
   ```

   Paste the token only into the Wrangler prompt. Do not put it in source code, `wrangler.jsonc`, or chat.
4. In the Square Developer Dashboard, add a production webhook subscription with this exact notification URL:

   `https://lindam.klutchplay.com/api/square/webhook`

   Subscribe to `payment.created`, `payment.updated`, `refund.created`, and `refund.updated`. Copy the webhook signature key and add it as a Worker secret:

   ```powershell
   npx wrangler secret put SQUARE_WEBHOOK_SIGNATURE_KEY
   ```

   `SQUARE_WEBHOOK_NOTIFICATION_URL` is already set in `wrangler.jsonc`; it must exactly match the URL configured in Square.
5. Build and deploy after both secrets and the location variable are configured:

   ```powershell
   npm run build
   npx wrangler deploy
   ```

   Paid client booking requests are blocked (the free consultation remains available) until the access token and location variable exist. Payment-link and refund requests also fail explicitly if configuration is missing. Do not accept live payments until Square's webhook is configured and the Worker has been deployed with all three values.

## Verify safely

1. Confirm the Square webhook subscription is enabled and that Square's webhook test reaches the deployed URL successfully.
2. Check the Worker logs for webhook signature or Square API errors.
3. Verify the listed prices in the appointment page: Individual Psychotherapy $154.50, Anxiety & Burnout Recovery $154.50, and Life Transitions & Relationships $190.55. The price increase is included in each displayed price; no separate card surcharge is added.
4. The deployed integration targets Square production and can charge real money. Do not use an ordinary client appointment as a test. Validate with a deliberately created internal appointment and an authorized production transaction, or add Sandbox environment support before running sandbox tests.
5. After a payment, confirm its status, Square receipt, and history appear in both the client appointment list and Clinician Portal. Confirm the refund control rejects appointments less than 24 hours away.
