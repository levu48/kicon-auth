// DEV ONLY. Seeds the demo account and pre-fills the login page. Never prod.
export const DEV_PASSWORD = 'demo-pass-123';
export const DEV_LOGIN_HINT = { email: 'lan@example.com', password: DEV_PASSWORD };

// DEV ONLY. A fixed TOTP secret so the seeded user is MFA-enrolled and the
// headless verifier / dev login can compute valid codes.
export const DEV_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
