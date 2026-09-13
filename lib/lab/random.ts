export function rng(seed: number) { let s = seed >>> 0; return () => { s += 0x6D2B79F5; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
export function pick<T>(r: () => number, a: readonly T[]): T { return a[Math.floor(r() * a.length)]; }
export function int(r: () => number, min: number, max: number) { return Math.floor(r() * (max - min + 1)) + min; }
export function fauxHash(seed: number, length = 64) { const r = rng(seed); return Array.from({ length }, () => Math.floor(r() * 16).toString(16)).join(''); }
export const EPOCH = Date.parse('2026-09-09T12:00:00Z');
export const iso = (ms: number) => new Date(ms).toISOString();
export function externalIP(i: number) { return ['192.0.2', '198.51.100', '203.0.113'][Math.floor(i / 254) % 3] + '.' + (i % 254 + 1); }
