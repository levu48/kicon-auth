import { Router, urlencoded, type Request, type Response, type NextFunction } from 'express';
import { AccountsService } from '../accounts/accounts.service';
import { AuditService } from '../audit/audit.service';
import { MfaService, mfaRequired } from '../mfa/mfa.service';
import { LoginThrottleService } from '../security/login-throttle.service';
import { BreachedPasswordService } from '../security/breached-password.service';
import { ACR_PWD, ACR_MFA, AMR_PWD, AMR_MFA } from '../mfa/acr';
import { generateToken } from '../mfa/totp';
import { tenantOf } from '../identity/tenants';
import { redis } from '../oidc/redis/redis-client';
import { DEV_LOGIN_HINT, DEV_TOTP_SECRET } from '../accounts/dev-credentials';

const MFA_PENDING_TTL = 300; // seconds a password-verified session waits for MFA
const MIN_PASSWORD = 8; // minimum password length at registration

/**
 * The login interaction UI. oidc-provider redirects here (see interactions.url in
 * oidc.config.ts) whenever an authorization request needs the user to authenticate.
 *
 * Flow:
 *   GET  /interaction/:uid        -> render the login form (prompt: 'login')
 *   POST /interaction/:uid/login  -> verify Argon2id password, finish interaction
 *
 * Consent is handled OUT of band by loadExistingGrant (first-party auto-grant),
 * so we never see a 'consent' prompt here.
 *
 * These routes must be mounted BEFORE provider.callback() so they win over the
 * oidc catch-all. The provider gives us interactionDetails/interactionFinished.
 */
export function buildInteractionsRouter(
  provider: any,
  accounts: AccountsService,
  audit: AuditService,
  mfa: MfaService,
  throttle: LoginThrottleService,
  breached: BreachedPasswordService,
): Router {
  const router = Router();
  const form = urlencoded({ extended: false });
  const mfaPendingKey = (uid: string) => `mfa:pending:${uid}`;

  router.get('/interaction/:uid', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      const { prompt, params, uid } = details;

      if (prompt.name === 'login') {
        res
          .set('cache-control', 'no-store')
          .type('html')
          .send(loginPage({ uid, clientId: params.client_id, scope: params.scope }));
        return;
      }

      if (prompt.name === 'consent') {
        // First-party auto-approval — no consent SCREEN is rendered. We simply
        // extend the grant with whatever this request still needs and finish.
        // A consent prompt reaches us only when the client sends prompt=consent
        // (required by spec to obtain offline_access / a refresh token).
        const grantId = await approveGrant(provider, details);
        await provider.interactionFinished(
          req,
          res,
          { consent: { grantId } },
          { mergeWithLastSubmission: true },
        );
        return;
      }

      // Any other prompt is unexpected in this first-party setup.
      res
        .status(500)
        .type('html')
        .send(errorPage(`Unexpected interaction prompt: "${prompt.name}".`));
    } catch (err) {
      next(err);
    }
  });

  router.post(
    '/interaction/:uid/login',
    form,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { email, password } = (req.body ?? {}) as { email?: string; password?: string };

        // Rate limit + account lockout gate (before touching the password).
        const decision = await throttle.check(req.ip, email);
        if (!decision.allowed) {
          audit.emit('login.blocked', {
            outcome: 'failure',
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: decision.reason, retry_after: decision.retryAfter },
          });
          const details = await provider.interactionDetails(req, res);
          res
            .status(429)
            .set('cache-control', 'no-store')
            .type('html')
            .send(
              loginPage({
                uid: details.uid,
                clientId: details.params.client_id,
                scope: details.params.scope,
                error: `Too many attempts. Try again in ${decision.retryAfter ?? 60}s.`,
              }),
            );
          return;
        }
        await throttle.onAttempt(req.ip);

        const user = email ? await accounts.findByEmail(email) : null;
        const ok = user ? await accounts.verifyPassword(user, password ?? '') : false;

        if (!ok) {
          const failures = await throttle.onFailure(email);
          audit.emit('login.failure', {
            outcome: 'failure',
            actor_sub: user?.id ?? null,
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: user ? 'bad_password' : 'unknown_email', failures },
          });
          // Re-render with a generic error (don't reveal which field was wrong).
          const details = await provider.interactionDetails(req, res);
          res
            .status(401)
            .set('cache-control', 'no-store')
            .type('html')
            .send(
              loginPage({
                uid: details.uid,
                clientId: details.params.client_id,
                scope: details.params.scope,
                error: 'Invalid email or password.',
              }),
            );
          return;
        }

        // Password OK — clear the failure counter / lock.
        await throttle.onSuccess(email);

        // Advisory breached-password check (k-anonymity, fail-open, non-blocking).
        // A real deployment would run this at password-set time and force a reset.
        void breached.pwnedCount(password ?? '').then((n) => {
          if (n > 0) {
            audit.emit('password.breached', {
              outcome: 'success',
              actor_sub: user!.id,
              ip: req.ip ?? null,
              detail: { pwned_count: n },
            });
          }
        });

        // Does this tenant — or the request's requested acr — need a second factor?
        const details = await provider.interactionDetails(req, res);
        const tenant = tenantOf(details.params.client_id);
        const enrolled = await mfa.isEnrolled(user!.id);
        // Both the client id and the requested acr matter — vote-admin is
        // mandatory-MFA by client, civic is by enrollment. See mfaRequired().
        const clientId = details.params.client_id as string | undefined;
        const acrValues = details.params.acr_values as string | undefined;

        if (mfaRequired(tenant, enrolled, { clientId, acrValues })) {
          if (!enrolled) {
            // Mandatory (trader / an admin surface) but not enrolled — a real UX
            // would force enrollment here.
            audit.emit('login.failure', {
              outcome: 'failure',
              actor_sub: user!.id,
              ip: req.ip ?? null,
              user_agent: req.get('user-agent') ?? null,
              detail: { reason: 'mfa_required_not_enrolled', tenant },
            });
            res
              .status(403)
              .type('html')
              .send(errorPage('This application requires two-factor authentication, which is not set up on your account.'));
            return;
          }
          // Remember the password step; ask for the code (interaction not finished yet).
          await redis().set(mfaPendingKey(details.uid), user!.id, 'EX', MFA_PENDING_TTL);
          audit.emit('login.password_ok', {
            outcome: 'success',
            actor_sub: user!.id,
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { tenant, awaiting: 'mfa' },
          });
          res
            .status(200)
            .set('cache-control', 'no-store')
            .type('html')
            .send(mfaPage({ uid: details.uid, clientId: details.params.client_id }));
          return;
        }

        // No second factor needed — finish with a single-factor result.
        audit.emit('login.success', {
          outcome: 'success',
          actor_sub: user!.id,
          ip: req.ip ?? null,
          user_agent: req.get('user-agent') ?? null,
          detail: { amr: AMR_PWD },
        });
        await provider.interactionFinished(
          req,
          res,
          { login: { accountId: user!.id, amr: AMR_PWD, acr: ACR_PWD } },
          { mergeWithLastSubmission: false },
        );
      } catch (err) {
        next(err);
      }
    },
  );

  // Second-factor verification. Reached only after a successful password step
  // that set the mfa:pending marker (see above).
  router.post(
    '/interaction/:uid/mfa',
    form,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const details = await provider.interactionDetails(req, res);
        const accountId = await redis().get(mfaPendingKey(details.uid));
        if (!accountId) {
          res
            .status(400)
            .type('html')
            .send(errorPage('Your second-factor step expired. Please start signing in again.'));
          return;
        }

        const code = ((req.body ?? {}) as { code?: string }).code ?? '';
        const ok = await mfa.verify(accountId, code);
        if (!ok) {
          audit.emit('mfa.failure', {
            outcome: 'failure',
            actor_sub: accountId,
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
          });
          res
            .status(401)
            .set('cache-control', 'no-store')
            .type('html')
            .send(mfaPage({ uid: details.uid, clientId: details.params.client_id, error: 'Invalid code.' }));
          return;
        }

        await redis().del(mfaPendingKey(details.uid));
        audit.emit('mfa.success', {
          outcome: 'success',
          actor_sub: accountId,
          ip: req.ip ?? null,
          user_agent: req.get('user-agent') ?? null,
        });
        audit.emit('login.success', {
          outcome: 'success',
          actor_sub: accountId,
          ip: req.ip ?? null,
          user_agent: req.get('user-agent') ?? null,
          detail: { amr: AMR_MFA },
        });
        await provider.interactionFinished(
          req,
          res,
          { login: { accountId, amr: AMR_MFA, acr: ACR_MFA } },
          { mergeWithLastSubmission: false },
        );
      } catch (err) {
        next(err);
      }
    },
  );

  // ── Registration ─────────────────────────────────────────────────────────
  // Reached from the "Create account" link on the login page, so it lives inside
  // the same OIDC interaction: on success we finish the interaction (log the new
  // user in) and the flow continues back to the client — the hosted-IdP pattern.
  // The auth origin is the only place a password may be collected (CLAUDE.md).

  router.get('/interaction/:uid/register', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      if (details.prompt.name !== 'login') {
        res.status(400).type('html').send(errorPage('Registration is only available while signing in.'));
        return;
      }
      res
        .set('cache-control', 'no-store')
        .type('html')
        .send(registerPage({ uid: details.uid, clientId: details.params.client_id }));
    } catch (err) {
      next(err);
    }
  });

  router.post(
    '/interaction/:uid/register',
    form,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const details = await provider.interactionDetails(req, res);
        const clientId = details.params.client_id;
        const body = (req.body ?? {}) as {
          email?: string;
          name?: string;
          password?: string;
          confirm?: string;
        };
        const email = (body.email ?? '').trim().toLowerCase();
        const name = (body.name ?? '').trim();

        const reRender = (error: string, status = 400) =>
          res
            .status(status)
            .set('cache-control', 'no-store')
            .type('html')
            .send(registerPage({ uid: details.uid, clientId, email, name, error }));

        // Per-IP rate limit (reuses the login throttle's IP bucket; no email lock).
        const decision = await throttle.check(req.ip);
        if (!decision.allowed) {
          audit.emit('register.blocked', {
            outcome: 'failure',
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: decision.reason, retry_after: decision.retryAfter },
          });
          reRender(`Too many attempts. Try again in ${decision.retryAfter ?? 60}s.`, 429);
          return;
        }
        await throttle.onAttempt(req.ip);

        // Field validation.
        if (!email || !/.+@.+\..+/.test(email)) return void reRender('Enter a valid email address.');
        if (!name) return void reRender('Enter your name.');
        if ((body.password ?? '').length < MIN_PASSWORD) {
          return void reRender(`Password must be at least ${MIN_PASSWORD} characters.`);
        }
        if (body.password !== body.confirm) return void reRender('Passwords do not match.');

        // Email must be unique (friendly pre-check; unique constraint is the race guard).
        if (await accounts.findByEmail(email)) {
          audit.emit('register.failure', {
            outcome: 'failure',
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: 'email_taken' },
          });
          return void reRender('An account with that email already exists.');
        }

        // Breached-password check is BLOCKING at set-time (unlike the advisory check
        // at login). k-anonymity + fail-open, so an HIBP outage never blocks signup.
        if (await breached.isBreached(body.password ?? '')) {
          audit.emit('register.failure', {
            outcome: 'failure',
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: 'breached_password' },
          });
          return void reRender('That password has appeared in a known data breach. Please choose a different one.');
        }

        // Create the account.
        let user: Awaited<ReturnType<typeof accounts.create>>;
        try {
          user = await accounts.create({ email, name, password: body.password ?? '' });
        } catch (e) {
          // Unique-violation race (two signups, same email) or DB error.
          audit.emit('register.failure', {
            outcome: 'failure',
            ip: req.ip ?? null,
            user_agent: req.get('user-agent') ?? null,
            detail: { email, reason: 'create_failed' },
          });
          return void reRender('An account with that email already exists.');
        }

        audit.emit('register.success', {
          outcome: 'success',
          actor_sub: user.id,
          ip: req.ip ?? null,
          user_agent: req.get('user-agent') ?? null,
          detail: { email, client_id: clientId },
        });

        // A brand-new account is never MFA-enrolled. If this surface makes MFA
        // mandatory (trader, or an admin origin), we can't complete the sign-in
        // here yet — the account exists, but enrollment (not built) is required
        // first. Note `enrolled: false` means the voluntary acr clause in
        // mfaRequired() cannot fire, so only the mandatory rules apply.
        const tenant = tenantOf(clientId);
        if (
          mfaRequired(tenant, false, {
            clientId,
            acrValues: details.params.acr_values as string | undefined,
          })
        ) {
          res
            .status(403)
            .type('html')
            .send(
              errorPage(
                'Your account was created, but this application requires two-factor authentication, ' +
                  'which is not yet set up. Enrollment is coming soon.',
              ),
            );
          return;
        }

        // Otherwise sign the new user in and continue the OIDC flow.
        audit.emit('login.success', {
          outcome: 'success',
          actor_sub: user.id,
          ip: req.ip ?? null,
          user_agent: req.get('user-agent') ?? null,
          detail: { amr: AMR_PWD, via: 'register' },
        });
        await provider.interactionFinished(
          req,
          res,
          { login: { accountId: user.id, amr: AMR_PWD, acr: ACR_PWD } },
          { mergeWithLastSubmission: false },
        );
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}

/**
 * Auto-approve consent for a first-party client: find or create the Grant, add
 * exactly the scopes/claims/resource-scopes still missing, save, return grantId.
 * This is the canonical oidc-provider consent-confirm logic, minus the UI.
 */
async function approveGrant(provider: any, details: any): Promise<string> {
  const { session, params, grantId, prompt } = details;

  const grant = grantId
    ? await provider.Grant.find(grantId)
    : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });

  const missing = prompt.details ?? {};
  if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
  if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
  if (missing.missingResourceScopes) {
    for (const [indicator, scopes] of Object.entries<string[]>(missing.missingResourceScopes)) {
      grant.addResourceScope(indicator, scopes.join(' '));
    }
  }
  return grant.save();
}

// ── views ────────────────────────────────────────────────────────────────────

function loginPage(opts: {
  uid: string;
  clientId: string;
  scope: string;
  error?: string;
}): string {
  const scopes = (opts.scope ?? '')
    .split(' ')
    .filter(Boolean)
    .map((s) => `<code>${escapeHtml(s)}</code>`)
    .join(' ');

  return page(`
    <h1>auth.kicon.com</h1>
    <p class="sub"><strong>${escapeHtml(opts.clientId)}</strong> wants you to sign in.</p>
    ${opts.error ? `<p class="err">${escapeHtml(opts.error)}</p>` : ''}
    <form method="post" action="/interaction/${encodeURIComponent(opts.uid)}/login" autocomplete="off">
      <label>Email
        <input name="email" type="email" required autofocus value="${escapeHtml(DEV_LOGIN_HINT.email)}" />
      </label>
      <label>Password
        <input name="password" type="password" required value="${escapeHtml(DEV_LOGIN_HINT.password)}" />
      </label>
      <button type="submit">Sign in</button>
    </form>
    <p class="alt">No account?
      <a href="/interaction/${encodeURIComponent(opts.uid)}/register">Create one</a>
    </p>
    <p class="scopes">Requested scopes: ${scopes || '<em>none</em>'}</p>
    <p class="hint">Dev credentials are pre-filled. This page is served by the IdP itself —
      the crown-jewel origin. Real login adds MFA + rate limiting (Phase 4).</p>
  `);
}

function registerPage(opts: {
  uid: string;
  clientId: string;
  email?: string;
  name?: string;
  error?: string;
}): string {
  return page(`
    <h1>Create your account</h1>
    <p class="sub">One kicon account signs you in to <strong>${escapeHtml(opts.clientId)}</strong>
      and every kicon app.</p>
    ${opts.error ? `<p class="err">${escapeHtml(opts.error)}</p>` : ''}
    <form method="post" action="/interaction/${encodeURIComponent(opts.uid)}/register" autocomplete="off">
      <label>Name
        <input name="name" type="text" required autofocus value="${escapeHtml(opts.name ?? '')}" />
      </label>
      <label>Email
        <input name="email" type="email" required value="${escapeHtml(opts.email ?? '')}" />
      </label>
      <label>Password
        <input name="password" type="password" required minlength="8"
               autocomplete="new-password" />
      </label>
      <label>Confirm password
        <input name="confirm" type="password" required minlength="8"
               autocomplete="new-password" />
      </label>
      <button type="submit">Create account</button>
    </form>
    <p class="alt">Already have an account?
      <a href="/interaction/${encodeURIComponent(opts.uid)}">Sign in</a>
    </p>
    <p class="hint">At least 8 characters. Passwords found in known data breaches are rejected.</p>
  `);
}

function mfaPage(opts: { uid: string; clientId: string; error?: string }): string {
  // DEV convenience: show the current valid code so the browser flow is usable
  // without an authenticator app. Never do this in production.
  const devHint =
    process.env.NODE_ENV !== 'production'
      ? `<p class="hint">Dev code (this 30s window): <code>${generateToken(DEV_TOTP_SECRET)}</code></p>`
      : '';
  return page(`
    <h1>Two-factor authentication</h1>
    <p class="sub"><strong>${escapeHtml(opts.clientId)}</strong> requires a second factor.</p>
    ${opts.error ? `<p class="err">${escapeHtml(opts.error)}</p>` : ''}
    <form method="post" action="/interaction/${encodeURIComponent(opts.uid)}/mfa" autocomplete="off">
      <label>6-digit code
        <input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" required autofocus
               placeholder="123456" />
      </label>
      <button type="submit">Verify</button>
    </form>
    ${devHint}
    <p class="hint">From your authenticator app (TOTP). Required for the trader tenant,
      and for civic once enrolled (Phase 4 policy).</p>
  `);
}

function errorPage(message: string): string {
  return page(`<h1>Something went wrong</h1><p class="err">${escapeHtml(message)}</p>`);
}

function page(body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>auth.kicon.com</title>
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      body { font: 15px/1.5 system-ui, sans-serif; margin: 0; min-height: 100vh;
        display: grid; place-items: center; background: #0f1115; color: #e7e9ee; }
      .card { width: min(92vw, 380px); background: #171a21; border: 1px solid #262b36;
        border-radius: 14px; padding: 28px; box-shadow: 0 10px 40px rgba(0,0,0,.4); }
      h1 { font-size: 1.15rem; margin: 0 0 4px; }
      .sub { margin: 0 0 18px; color: #aab1c0; }
      label { display: block; font-size: .82rem; color: #aab1c0; margin: 14px 0 4px; }
      input { width: 100%; padding: 10px 12px; border-radius: 9px; border: 1px solid #2c3240;
        background: #0f1115; color: #e7e9ee; font-size: .95rem; }
      button { width: 100%; margin-top: 20px; padding: 11px; border: 0; border-radius: 9px;
        background: #4f7cff; color: #fff; font-weight: 600; font-size: .95rem; cursor: pointer; }
      button:hover { background: #6b90ff; }
      .err { background: #3a1d22; border: 1px solid #6b2d38; color: #ffb3bd;
        padding: 8px 11px; border-radius: 8px; font-size: .85rem; }
      .alt { margin-top: 16px; font-size: .82rem; color: #aab1c0; }
      a { color: #6b90ff; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .scopes { margin-top: 18px; font-size: .8rem; color: #aab1c0; }
      code { background: #0f1115; border: 1px solid #2c3240; border-radius: 5px;
        padding: 1px 6px; font-size: .78rem; }
      .hint { margin-top: 14px; font-size: .74rem; color: #6b7280; }
    </style></head><body><div class="card">${body}</div></body></html>`;
}

function escapeHtml(s: string): string {
  return String(s ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}
