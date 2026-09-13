'use client';
import React, { createContext, useContext, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Pagination, PaginationContent, PaginationItem, PaginationNext, PaginationPrevious } from '@/components/ui/pagination';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
export { Button, Input, toast };
export type Nav = (view: string, params?: Record<string, string>) => void;
export const LabContext = createContext<any>(null);
export const useLab = () => useContext(LabContext);
export async function request(params: Record<string, any>) { const r = await fetch('/api/lab?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => [k, String(v)])), { cache: 'no-store' }); const d: any = await r.json(); if (!r.ok)
    throw Error(d.error || 'Request failed'); return d; }
export async function mutate(b: any) { const r = await fetch('/api/lab', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); const d: any = await r.json(); if (!r.ok)
    throw Object.assign(Error(d.error || 'Save failed'), {status:r.status}); return d; }
export function useApi(params: Record<string, any>) { const key = JSON.stringify(params), { revision } = useLab(); const [data, setData] = useState<any>(null), [error, setError] = useState(''); useEffect(() => { let current = true; setData(null); setError(''); request(JSON.parse(key)).then(d => { if (current)
    setData(d); }).catch(e => { if (current)
    setError(e.message); }); return () => { current = false; }; }, [key, revision]); return { data, error }; }
export function Loading({ error = '' }: {
    error?: string;
}) { return error ? <div className="empty" role="alert">{error}<p>Adjust the query or use Refresh to retry.</p></div> : <div className="space-y-3" aria-label="Loading records"><Skeleton className="h-16 w-full"/><Skeleton className="h-60 w-full"/></div>; }
export function Heading({ eyebrow, title, description, children }: any) { return <div className="heading"><div><div className="eyebrow">{eyebrow || 'NORTHSTAR / SECURITY OPERATIONS'}</div><h1>{title}</h1>{description && <p>{description}</p>}</div><div className="flex gap-2 flex-wrap">{children}</div></div>; }
export function Panel({ title, detail, children, className = '' }: any) { return <section className={'panel ' + className}>{title && <div className="panel-head"><h2>{title}</h2><span className="muted">{detail}</span></div>}<div className="panel-body">{children}</div></section>; }
export function Badge({ children }: any) { return <span className={'badge ' + String(children).toLowerCase().replaceAll(' ', '-')}>{children}</span>; }
export function Stat({ label, value, detail, onClick }: any) { return <button className="stat" onClick={onClick}><span>{label}</span><strong>{value}</strong><small>{detail}</small></button>; }
export function Pick({ label, value, onChange, options, className = '' }: {
    label: string;
    value: string;
    onChange: (value: string) => void;
    options: readonly any[];
    className?: string;
}) { return <label className={'field ' + className}><span>{label}</span><Select value={value || '__empty'} onValueChange={v => onChange(v === '__empty' ? '' : v)}><SelectTrigger aria-label={label}><SelectValue /></SelectTrigger><SelectContent>{options.map((o: any) => { const v = typeof o === 'string' ? o : o.value; return <SelectItem key={v || '__empty'} value={v || '__empty'}>{typeof o === 'string' ? o : o.label}</SelectItem>; })}</SelectContent></Select></label>; }
export function GridTable({ columns, rows, empty = 'No matching records.' }: any) { return <Table><TableHeader><TableRow>{columns.map((c: any) => <TableHead key={c.key}>{c.label}</TableHead>)}</TableRow></TableHeader><TableBody>{rows.map((r: any, i: number) => <TableRow key={r.id || r.value || i}>{columns.map((c: any) => <TableCell key={c.key}>{c.render ? c.render(r) : String(r[c.key] ?? '—')}</TableCell>)}</TableRow>)}{!rows.length && <TableRow><TableCell colSpan={columns.length}><div className="empty">{empty}</div></TableCell></TableRow>}</TableBody></Table>; }
export function Pager({ page, total, size = 25, onChange }: any) { const max = Math.max(1, Math.ceil(total / size)); return <div className="pager"><span>{total.toLocaleString()} records · Page {page} of {max}</span><Pagination className="m-0 w-auto"><PaginationContent><PaginationItem><PaginationPrevious aria-disabled={page <= 1} className={page <= 1 ? 'disabled' : ''} onClick={() => page > 1 && onChange(page - 1)}/></PaginationItem><PaginationItem><PaginationNext aria-disabled={page >= max} className={page >= max ? 'disabled' : ''} onClick={() => page < max && onChange(page + 1)}/></PaginationItem></PaginationContent></Pagination></div>; }
export function Pivot({ view, id, children }: any) { const { nav } = useLab(); return <button className="link" onClick={() => nav(view, view === 'ioc' ? { q: id } : view === 'siem' ? { q: id } : { id })}>{children || id || '—'}</button>; }
export function When({ value }: any) { const { workspace } = useLab(); if (!value)
    return <>—</>; return <span className="mono nowrap" title={value}>{new Date(value).toLocaleString('en-GB', { timeZone: workspace?.settings?.timezone || 'UTC', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}</span>; }
export function KeyValues({ data }: any) { return <dl className="keyvalues">{Object.entries(data || {}).map(([k, v]) => <React.Fragment key={k}><dt>{k.replace(/([A-Z])/g, ' $1').replaceAll('_', ' ')}</dt><dd>{typeof v === 'object' ? <pre>{JSON.stringify(v, null, 2)}</pre> : String(v ?? '—')}</dd></React.Fragment>)}</dl>; }
export function download(name: string, data: any, csv = false) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv ? String(data) : JSON.stringify(data, null, 2)], { type: csv ? 'text/csv' : 'application/json' })); a.download = name; a.click(); URL.revokeObjectURL(a.href); }
export async function copy(value: string) { try {
    await navigator.clipboard.writeText(value);
    toast.success('Copied to clipboard');
}
catch {
    toast.error('Clipboard is unavailable in this browser. Use Export instead.');
} }
export function AlertRows({ alerts, pageSize = 25 }: any) { const { workspace, nav } = useLab(), [page, setPage] = useState(1); useEffect(() => setPage(1), [alerts]); const inv = new Map(workspace.investigations.map((i: any) => [i.alert_id, i])); return <><GridTable rows={alerts.slice((page - 1) * pageSize, page * pageSize)} columns={[{ key: 'name', label: 'Detection', render: (a: any) => <div className="detection"><button className="link" onClick={() => nav('alert', { id: a.id })}>{a.name}</button><small>{a.id} · {a.family}</small></div> }, { key: 'severity', label: 'Severity', render: (a: any) => <Badge>{a.severity}</Badge> }, { key: 'host', label: 'Endpoint', render: (a: any) => <Pivot view="host" id={a.host}/> }, { key: 'user', label: 'User', render: (a: any) => <Pivot view="user" id={a.user}/> }, { key: 'status', label: 'Status', render: (a: any) => <Badge>{(inv.get(a.id) as any)?.status || a.status}</Badge> }, { key: 'time', label: 'Detected', render: (a: any) => <When value={a.time}/> }]} empty="No alerts match these filters."/>{alerts.length > pageSize && <Pager page={page} total={alerts.length} size={pageSize} onChange={setPage}/>}</>; }
export function Events({ rows }: any) { const { inspect } = useLab(); return <GridTable rows={rows} columns={[{ key: 'timestamp', label: 'Time', render: (e: any) => <When value={e.timestamp}/> }, { key: 'kind', label: 'Source / ID', render: (e: any) => <div className="detection"><Badge>{e.kind}</Badge><small>{e.source}{e.event_id ? ' · ' + e.event_id : ''}</small></div> }, { key: 'message', label: 'Observation', render: (e: any) => <button className="link" onClick={() => inspect(e)}>{e.message}</button> }, { key: 'host', label: 'Endpoint', render: (e: any) => <Pivot view="host" id={e.host}/> }, { key: 'user', label: 'User', render: (e: any) => <Pivot view="user" id={e.user}/> }, { key: 'destination_ip', label: 'Destination / indicator', render: (e: any) => <div><Pivot view="ioc" id={e.domain || e.destination_ip}/></div> }]}/>; }

export function downloadText(name:string,content:string){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([content],{type:'text/markdown;charset=utf-8'}));a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
