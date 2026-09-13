import { env } from 'cloudflare:workers';
export function database(): D1Database { if (!env.DB)
    throw new Error('The lab database is unavailable. Please retry shortly.'); return env.DB; }
export async function all<T = any>(sql: string, args: unknown[] = []): Promise<T[]> { return (await database().prepare(sql).bind(...args).all<T>()).results; }
export async function one<T = any>(sql: string, args: unknown[] = []): Promise<T | null> { return database().prepare(sql).bind(...args).first<T>(); }
export async function run(sql: string, args: unknown[] = []) { return database().prepare(sql).bind(...args).run(); }
