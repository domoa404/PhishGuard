import type { UserRole } from '../types/phishguard.ts';

let currentActor = 'Tariq Haddad';
let currentRole: UserRole = 'Security Analyst';

export function setApiActor(actor: string, role: UserRole) {
  currentActor = actor;
  currentRole = role;
}

export function getApiActor() {
  return { actor: currentActor, role: currentRole };
}

export async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json');
  }
  headers.set('x-phishguard-actor', currentActor);
  headers.set('x-phishguard-role', currentRole);

  const res = await fetch(url, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `Request failed (${res.status})`);
  }
  return data as T;
}
