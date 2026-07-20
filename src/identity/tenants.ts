/**
 * Client → tenant mapping. Tenant is a property of WHO is asking, never stored
 * on the user. Authoritative and static, alongside the client registrations.
 * (Phase 3 keeps it here; a later phase may move it onto the client metadata.)
 */
const TENANT_OF: Record<string, string> = {
  banmua: 'food',
  vietcouncil: 'civic',
  xbottrader: 'trader',
  // kicon app platform (docs/app-platform-domains.md). Its own tenant so app
  // users never receive food/civic/trader claims and vice-versa.
  //
  // All three surfaces of the platform share the 'apps' tenant: they are
  // different origins and different clients, but the same tenant — a vote admin
  // is the same person seeing the same identity projection as a vote consumer.
  // (vote-admin was missing here originally, so it resolved to 'unknown' and the
  // admin surface silently received a different claim projection than intended.)
  vote: 'apps',
  'vote-admin': 'apps',
  'vote-bridge': 'apps',
};

export function tenantOf(clientId: string | undefined): string {
  return TENANT_OF[clientId ?? ''] ?? 'unknown';
}
