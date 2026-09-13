# My Business Starter — FINAL Online Launch

This is the clean final deployment package.

## Deploy
Use Render or Railway with the included Dockerfile.

Set these environment variables on the hosting provider:
- SESSION_SECRET
- STRIPE_SECRET_KEY
- STRIPE_PRO_PRICE_ID
- STRIPE_WEBHOOK_SECRET

Do not put real secrets into the project files.

## Stripe
Create a Business Pro recurring price at £9.99/month in Stripe Test Mode first.

Webhook endpoint:
`https://YOUR-DOMAIN/api/billing/webhook`

Events:
- checkout.session.completed
- customer.subscription.updated
- customer.subscription.deleted
- invoice.payment_failed

## Final customer journey
Visitor → Create account → Business workspace → Pricing → Stripe Checkout → Pro subscription → Billing portal

Before taking real payments, switch from Stripe test mode to live mode and complete the required legal/privacy, backup, database and production-security setup.
