/**
 * Signing-key rotation CLI. Run via the npm scripts:
 *   npm run keys:init     — create a keystore with one key if none exists
 *   npm run keys:list     — show kids (first = active signer)
 *   npm run keys:rotate   — prepend a new active key, prune to JWKS_KEEP (default 3)
 *
 * After rotating, restart the provider (or rolling-restart instances) so it
 * reloads the keystore and signs with the new key. Old keys stay published until
 * pruned, so tokens signed just before rotation still verify. See keystore.ts.
 */
import { readKeystore, writeKeystore, generateSigningKey, keystorePath, type Keystore } from './keystore';

function publicView(ks: Keystore) {
  return ks.keys.map((k, i) => ({
    kid: k.kid,
    role: i === 0 ? 'ACTIVE (signs new tokens)' : 'published for verification',
  }));
}

async function main() {
  const cmd = process.argv[2] ?? 'list';
  const keep = Number(process.env.JWKS_KEEP ?? 3);

  if (cmd === 'init') {
    if (readKeystore()) {
      console.log(`keystore already exists at ${keystorePath()}`);
    } else {
      writeKeystore({ keys: [await generateSigningKey()] });
      console.log(`created keystore at ${keystorePath()}`);
    }
  } else if (cmd === 'rotate') {
    const ks = readKeystore() ?? { keys: [] };
    const key = await generateSigningKey();
    ks.keys.unshift(key); // new key becomes the active signer
    const pruned = ks.keys.length - keep;
    if (pruned > 0) ks.keys = ks.keys.slice(0, keep);
    writeKeystore(ks);
    console.log(`rotated: new active kid=${key.kid}; ${ks.keys.length} key(s) kept${pruned > 0 ? ` (pruned ${pruned})` : ''}`);
    console.log('restart the provider so it signs with the new key.');
  } else if (cmd === 'list') {
    const ks = readKeystore();
    if (!ks) return console.log(`no keystore at ${keystorePath()} — run: npm run keys:init`);
    console.table(publicView(ks));
  } else {
    console.error(`unknown command "${cmd}" (use: init | list | rotate)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
