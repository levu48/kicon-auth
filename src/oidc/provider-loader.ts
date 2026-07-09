/**
 * oidc-provider v8+ is ESM-only. This app compiles to CommonJS (NestJS default),
 * where TypeScript would downlevel a plain `import()` into `require()` — which
 * throws on an ESM-only package. Hiding the dynamic import behind `Function`
 * keeps it a real runtime `import()` that tsc won't rewrite.
 *
 * If you later run the whole app as ESM (or oidc-provider ships CJS again),
 * this indirection can go away. Verify against your INSTALLED version.
 */
const dynamicImport = new Function('specifier', 'return import(specifier)') as (
  specifier: string,
) => Promise<any>;

export async function loadProviderCtor(): Promise<any> {
  const mod = await dynamicImport('oidc-provider');
  return mod.default ?? mod;
}

/** Load the Provider constructor plus the interactionPolicy helpers together. */
export async function loadOidc(): Promise<{ Provider: any; interactionPolicy: any }> {
  const mod = await dynamicImport('oidc-provider');
  return { Provider: mod.default ?? mod, interactionPolicy: mod.interactionPolicy };
}
