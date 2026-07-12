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
 * Password is read from, in order: USER_PASSWORD env, piped stdin, or a hidden
 * TTY prompt. Argon2id hashing matches AccountsService.hash so login verification
 * (argon2.verify) stays consistent.
 */
import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import AppDataSource from '../database/data-source';
import { User } from '../database/entities';

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
    else {
      console.error('usage: user-cli.js <create --email <e> --name <n> [--locale <l>] [--zoneinfo <z>] [--id <id>] | list>');
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
