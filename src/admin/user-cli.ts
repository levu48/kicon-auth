/**
 * Admin CLI to create / list IdP accounts — Ring-1 `users` rows + Argon2id
 * credentials. Mirrors the signing-key CLI (src/oidc/keys/cli.ts) and reuses the
 * standalone DataSource the migration CLI uses (src/database/data-source.ts).
 *
 * This is deliberately NOT wired into the HTTP surface: auth.kicon.com stays
 * login-only (CLAUDE.md — the auth origin keeps a tiny, tightly controlled
 * surface). Account creation is an operator action, run inside the app container:
 *
 *   docker compose -f docker-compose.prod.yml run --rm \
 *     --entrypoint "node dist/admin/user-cli.js create --email a@b.com --name 'A B'" app1
 *   docker compose -f docker-compose.prod.yml run --rm \
 *     --entrypoint "node dist/admin/user-cli.js list" app1
 *
 * `mfa-enroll` enrols a second factor out of band — self-service enrollment is
 * not built, and vote-admin makes MFA mandatory, so an operator must do this
 * before the admin surface is usable. It is interactive (confirms a code), so
 * run it WITHOUT --rm's default detach and with -it:
 *
 *   docker compose -f docker-compose.prod.yml run --rm -it \
 *     --entrypoint "node dist/admin/user-cli.js mfa-enroll --email a@b.com" app1
 *
 * Password is read from, in order: USER_PASSWORD env, piped stdin, or a hidden
 * TTY prompt. Argon2id hashing matches AccountsService.hash so login verification
 * (argon2.verify) stays consistent.
 */
import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import AppDataSource from '../database/data-source';
import { User, UserMfa } from '../database/entities';
import { generateSecret, keyuri, verifyToken } from '../mfa/totp';

type Args = Record<string, string | true>;

function parseArgs(argv: string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }
  return out;
}

const genId = (): string => 'u_' + randomBytes(8).toString('hex');
const normEmail = (e: string): string => e.trim().toLowerCase();

/** Read a password without echoing it, or from USER_PASSWORD / piped stdin. */
async function readPassword(args: Args): Promise<string> {
  if (process.env.USER_PASSWORD) return process.env.USER_PASSWORD;
  if (typeof args.password === 'string') return args.password; // least preferred (shell history)
  if (!process.stdin.isTTY) {
    // piped: read one line
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return chunks.length ? Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '') : '';
  }
  // interactive hidden prompt
  return await new Promise<string>((resolve) => {
    const stdin = process.stdin;
    process.stdout.write('Password: ');
    stdin.setRawMode?.(true);
    stdin.resume();
    let buf = '';
    const onData = (d: Buffer) => {
      const ch = d.toString('utf8');
      if (ch === '\n' || ch === '\r' || ch === '') {
        stdin.setRawMode?.(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(buf);
      } else if (ch === '' || ch === '\b') {
        buf = buf.slice(0, -1);
      } else if (ch === '') {
        process.stdout.write('\n');
        process.exit(130); // Ctrl-C
      } else {
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function create(args: Args): Promise<void> {
  const email = typeof args.email === 'string' ? normEmail(args.email) : '';
  const name = typeof args.name === 'string' ? args.name.trim() : '';
  if (!email || !/.+@.+\..+/.test(email)) throw new Error('valid --email is required');
  if (!name) throw new Error('--name is required');

  const users = AppDataSource.getRepository(User);
  if (await users.findOne({ where: { primary_email: email } })) {
    throw new Error(`an account with email ${email} already exists`);
  }

  const password = await readPassword(args);
  if (!password || password.length < 8) throw new Error('password must be at least 8 characters');

  const user = users.create({
    id: typeof args.id === 'string' ? args.id : genId(),
    primary_email: email,
    name,
    default_locale: typeof args.locale === 'string' ? args.locale : null,
    default_zoneinfo: typeof args.zoneinfo === 'string' ? args.zoneinfo : null,
    password_hash: await argon2.hash(password, { type: argon2.argon2id }),
  });
  await users.save(user);
  console.log(`created account: ${user.id}  <${user.primary_email}>  "${user.name}"`);
}

/** Read one line of visible input (a 6-digit code is not a secret to hide). */
async function readLine(prompt: string): Promise<string> {
  process.stdout.write(prompt);
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) {
    chunks.push(c as Buffer);
    if (Buffer.concat(chunks).includes(0x0a)) break; // stop at first newline
  }
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n.*$/s, '').trim();
}

/**
 * Out-of-band TOTP enrollment for one account.
 *
 * Self-service enrollment is not built, and `vote-admin` makes a second factor
 * MANDATORY (src/mfa/mfa.service.ts), so an un-enrolled admin is refused at
 * login with no way forward. This is how an operator enrolls one, matching what
 * MfaService.enroll does but from the standalone CLI DataSource.
 *
 * The secret is confirmed with a live code BEFORE `enabled_at` is set, unless
 * --force. That guard matters here specifically: enabling a secret the admin's
 * authenticator did not actually capture would lock them out of a surface whose
 * whole point is that it cannot fall back to a password. `enabled_at` is what
 * MfaService.isEnrolled checks, so a row without it is inert.
 */
async function mfaEnroll(args: Args): Promise<void> {
  const email = typeof args.email === 'string' ? normEmail(args.email) : '';
  const byId = typeof args.id === 'string' ? args.id : '';
  if (!email && !byId) throw new Error('--email or --id is required');

  const users = AppDataSource.getRepository(User);
  const user = await users.findOne({
    where: email ? { primary_email: email } : { id: byId },
  });
  if (!user) throw new Error(`no account for ${email || byId}`);

  const mfa = AppDataSource.getRepository(UserMfa);
  const existing = await mfa.findOne({ where: { user_id: user.id } });
  if (existing?.enabled_at && !args.force) {
    throw new Error(
      `${user.primary_email} is already enrolled (since ${existing.enabled_at.toISOString()}). ` +
        `Re-enroll with --force to replace the secret.`,
    );
  }

  const secret = generateSecret();
  const otpauth = keyuri(secret, user.primary_email, 'auth.kicon.com');

  console.log(`\nEnrolling ${user.id}  <${user.primary_email}>\n`);
  console.log('Add this to an authenticator app (scan the otpauth URI as a QR,');
  console.log('or type the secret in manually):\n');
  console.log(`  otpauth:  ${otpauth}`);
  console.log(`  secret:   ${secret}   (SHA1, 6 digits, 30s)\n`);

  // enabled_at is set only after a code round-trips, so a mis-scanned secret
  // fails HERE (a re-runnable error) instead of at the admin's next login.
  let enabledAt: Date;
  if (args.force && !process.stdin.isTTY) {
    // Non-interactive --force: enable without a code round-trip. Only for
    // scripted/seed use where no human is present to read a code.
    enabledAt = new Date();
    console.log('--force with no TTY: enabling without code confirmation.\n');
  } else {
    const code = await readLine('Enter the current 6-digit code to confirm: ');
    if (!verifyToken(secret, code)) {
      throw new Error('code did not verify — nothing saved. Re-run to try again.');
    }
    enabledAt = new Date();
  }

  await mfa.save(
    mfa.create({ user_id: user.id, type: 'totp', secret, enabled_at: enabledAt }),
  );
  console.log(`\nenrolled: ${user.primary_email} (loa2 available from ${enabledAt.toISOString()})`);
}

async function list(): Promise<void> {
  const users = AppDataSource.getRepository(User);
  const rows = await users.find({ order: { created_at: 'ASC' } });
  if (!rows.length) return console.log('no accounts yet');
  console.table(
    rows.map((u) => ({
      id: u.id,
      email: u.primary_email,
      name: u.name,
      credentials: u.password_hash ? 'set' : 'MISSING',
      created_at: u.created_at?.toISOString?.() ?? String(u.created_at),
    })),
  );
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  await AppDataSource.initialize();
  try {
    if (cmd === 'create') await create(args);
    else if (cmd === 'list') await list();
    else if (cmd === 'mfa-enroll') await mfaEnroll(args);
    else {
      console.error(
        'usage: user-cli.js <\n' +
          "  create --email <e> --name <n> [--locale <l>] [--zoneinfo <z>] [--id <id>]\n" +
          '  list\n' +
          '  mfa-enroll (--email <e> | --id <id>) [--force]\n' +
          '>',
      );
      process.exitCode = 1;
    }
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
