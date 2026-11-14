# Meridian Expenses - CA2

Node.js / Express expense portal. This is the remediated CA1 build, extended for CA2 with a
claim-approval workflow and made importable so the security tests can drive it in-process.

## Run locally (127.0.0.1 only)

```
npm install
export JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(24).toString('hex'))")"
npm run seed      # creates expenses.db and sample receipts
npm start         # http://127.0.0.1:3000
```

Sample accounts (weak on purpose): jdoe/password1 (staff), rsmith/letmein (staff),
achen/Summer2026 (finance), admin/admin (admin).

## Tests

```
npm run test:security
```

The app is exported (`module.exports = app`) and only calls `listen` when run directly, so
supertest imports it without a port clash. Tests read the database path from `APP_DB`.

## Security pipeline

See `.github/workflows/security.yml` (added in the next step) for the CI pipeline: secret
scanning, SAST, SCA and the custom security tests.
