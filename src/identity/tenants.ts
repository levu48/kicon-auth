/**
 * Client → tenant mapping. Tenant is a property of WHO is asking, never stored
 * on the user. Authoritative and static, alongside the client registrations.
 * (Phase 3 keeps it here; a later phase may move it onto the client metadata.)
 */
const TENANT_OF: Record<string, string> = {
  banmua: 'food',
  vietcouncil: 'civic',
  xbottrader: 'trader',
};

export function tenantOf(clientId: string | undefined): string {
  return TENANT_OF[clientId ?? ''] ?? 'unknown';
}
