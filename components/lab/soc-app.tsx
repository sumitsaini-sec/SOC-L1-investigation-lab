'use client';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ShieldCheck, LayoutDashboard, Bell, Layers, Search, Monitor, Server, Users, Network, Mail, ScanSearch, Globe, Briefcase, NotebookPen, SlidersHorizontal, GitBranch, FileChartColumn, History, ChartNoAxesCombined, Wrench, Settings as SettingsIcon, Plus, RefreshCw, Bookmark, Shield } from 'lucide-react';
import { SidebarProvider, Sidebar, SidebarHeader, SidebarContent, SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuItem, SidebarMenuButton, SidebarFooter, SidebarInset, SidebarTrigger, useSidebar } from '@/components/ui/sidebar';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Toaster } from '@/components/ui/sonner';
import { LabContext, request, mutate, Button, Input, Pick, KeyValues, When, Pivot, Badge, copy, toast } from './common';
import { Overview, AlertsPage, Incidents, Telemetry, Inventory, EntityDetail, IOCPage, Intelligence, RulesPage, CasePage, ProgressPage, Settings } from './workspace-pages';
import { Investigation } from './investigation';
import { ToolsPage } from './tools-page';
const groups = [{ title: 'OPERATIONS', items: [['overview', 'Overview', LayoutDashboard], ['alerts', 'Alert queue', Bell], ['incidents', 'Incidents', Layers], ['siem', 'SIEM search', Search]] }, { title: 'INVESTIGATE', items: [['edr', 'Endpoint response', Monitor], ['hosts', 'Endpoints', Server], ['users', 'Identities', Users], ['network', 'Network & DNS', Network], ['email', 'Email security', Mail], ['ioc', 'IOC investigation', ScanSearch], ['intelligence', 'Threat intelligence', Globe]] }, { title: 'ANALYST WORKSPACE', items: [['cases', 'Case management', Briefcase], ['notes', 'Analyst notebook', NotebookPen], ['rules', 'Detection rules', SlidersHorizontal], ['mitre', 'MITRE ATT&CK', GitBranch], ['reports', 'Reports', FileChartColumn], ['history', 'Investigation history', History], ['performance', 'Performance', ChartNoAxesCombined], ['tools', 'Analyst tools', Wrench], ['settings', 'Settings', SettingsIcon]] }];
function Navigation({ view, nav, workspace }: any) { const { setOpenMobile } = useSidebar(); return <Sidebar><SidebarHeader><button className="brand" onClick={() => nav('overview')}><ShieldCheck /><span>SENTINEL DESK<small>SECURITY OPERATIONS LAB</small></span></button></SidebarHeader><SidebarContent>{groups.map(g => <SidebarGroup key={g.title}><SidebarGroupLabel className="text-[9px] tracking-[1.4px]">{g.title}</SidebarGroupLabel><SidebarMenu>{g.items.map(([key, title, Icon]: any) => <SidebarMenuItem key={key}><SidebarMenuButton isActive={view === key || view === 'alert' && key === 'alerts' || view === 'host' && key === 'hosts' || view === 'user' && key === 'users'} onClick={() => { setOpenMobile(false); nav(key); }} className="h-8 text-xs"><Icon className="size-[15px]"/><span>{title}</span>{key === 'alerts' && <span className="ml-auto text-[10px] opacity-60">{workspace.alerts.length}</span>}</SidebarMenuButton></SidebarMenuItem>)}</SidebarMenu></SidebarGroup>)}</SidebarContent><SidebarFooter className="sidebar-foot"><span className="flex items-center gap-2 text-[#83c7b5]"><span className="h-1.5 w-1.5 rounded-full bg-[#6bdcc0]"/> Northstar training tenant</span><span className="text-[#6c829c]">Synthetic data · Persistent workspace</span></SidebarFooter></Sidebar>; }
function Route({ view }: any) { switch (view) {
    case 'overview': return <Overview />;
    case 'alerts': return <AlertsPage />;
    case 'alert': return <Investigation />;
    case 'incidents': return <Incidents />;
    case 'siem':
    case 'network':
    case 'email': return <Telemetry mode={view}/>;
    case 'hosts':
    case 'users':
    case 'edr': return <Inventory mode={view}/>;
    case 'host':
    case 'user': return <EntityDetail mode={view}/>;
    case 'ioc': return <IOCPage />;
    case 'intelligence': return <Intelligence />;
    case 'rules': return <RulesPage />;
    case 'mitre': return <RulesPage mitre/>;
    case 'cases': return <CasePage />;
    case 'notes':
    case 'history':
    case 'performance':
    case 'reports': return <ProgressPage mode={view}/>;
    case 'tools': return <ToolsPage />;
    case 'settings': return <Settings />;
    default: return <Overview />;
} }
const parseHash = () => { const [v, qs = ''] = window.location.hash.slice(1).split('?'); return { view: v || 'overview', params: Object.fromEntries(new URLSearchParams(qs)) }; };
export default function SocApp() {
    const [workspace, W] = useState<any>(null), [progress, P] = useState(0), [error, E] = useState(''), [route, RO] = useState<any>({ view: 'overview', params: {} }), [active, AC] = useState(''), [revision, RE] = useState(0), [search, Q] = useState(''), [record, REC] = useState<any>(null), [inject, J] = useState(false), [options, O] = useState<any>({ category: 'DET-001', severity: 'High', difficulty: 'Intermediate', seed: '83491' }), [busy, B] = useState(false);
    const started = useRef(false), flush = useRef<null | (() => Promise<void>)>(null), routeRef = useRef(route);
    routeRef.current = route;
    const refresh = useCallback(async () => { const w = await request({ view: 'workspace' }); W(w); RE(n => n + 1); }, []);
    const registerFlush = useCallback((fn: () => Promise<void>) => { flush.current = fn; return () => { if (flush.current === fn)
        flush.current = null; }; }, []);
    const boot = async () => { E(''); try {
        const meta = await request({ view: 'meta' });
        for (let batch = 0; batch < 24; batch++) {
            if (!meta.batches.includes(meta.seedPrefix + batch))
                await mutate({ op: 'initialize', batch });
            P(batch + 1);
        }
        await refresh();
    }
    catch (e: any) {
        E(e.message);
    } };
    useEffect(() => { const change = () => { Promise.resolve(flush.current?.()).then(() => { const r = parseHash(); RO(r); if (r.view === 'alert')
        AC(r.params.id || '');
    else
        AC(r.params.active || ''); }).catch(e => toast.error(e.message)); }; change(); window.addEventListener('hashchange', change); if (!started.current) {
        started.current = true;
        boot();
    } return () => window.removeEventListener('hashchange', change); }, []);
    const nav = useCallback(async (view: string, params: Record<string, string> = {}) => { try {
        if (flush.current) {
            await flush.current();
            W(await request({ view: 'workspace' }));
        }
        REC(null);
        Q('');
        const previous = routeRef.current, context = view === 'alert' ? params.id : params.active || previous.params.active || (previous.view === 'alert' ? previous.params.id : '');
        const next = { ...params, ...context ? { active: context } : {} };
        window.location.hash = view + (Object.keys(next).length ? '?' + new URLSearchParams(next) : '');
        if (window.location.hash === '#' + view)
            RO({ view, params: next });
    }
    catch (e: any) {
        toast.error('Could not save your draft: ' + e.message);
    } }, []);
    if (!workspace)
        return <div className="boot"><ShieldCheck size={40} color="#6bdcc0"/><div className="eyebrow mt-6">SENTINEL DESK / SOC LAB</div><h1>{error ? 'Workspace needs a retry' : 'Preparing your investigation workspace'}</h1><p>{error || 'Loading correlated alerts, endpoint telemetry and enterprise baselines. Your progress will be preserved.'}</p><progress max={24} value={progress}/><p className="text-xs mt-3">{progress * 25} / 600 baseline alerts ready</p>{error && <Button className="mt-5" onClick={boot}>Retry initialization</Button>}</div>;
    const query = search.toLowerCase().trim(), results = query ? [...workspace.alerts.filter((a: any) => JSON.stringify(a).toLowerCase().includes(query)).slice(0, 8).map((a: any) => ({ view: 'alert', id: a.id, title: a.name, sub: a.id + ' · ' + a.host })), ...workspace.users.filter((u: any) => JSON.stringify(u).toLowerCase().includes(query)).slice(0, 4).map((u: any) => ({ view: 'user', id: u.id, title: u.fullName, sub: u.id + ' · ' + u.department })), ...workspace.hosts.filter((h: any) => JSON.stringify(h).toLowerCase().includes(query)).slice(0, 4).map((h: any) => ({ view: 'host', id: h.id, title: h.id, sub: h.ip })), ...workspace.cases.filter((c: any) => JSON.stringify(c).toLowerCase().includes(query)).slice(0, 4).map((c: any) => ({ view: 'cases', id: c.id, title: c.id, sub: c.status }))] : [];
    const current = workspace.alerts.find((a: any) => a.id === active), inv = workspace.investigations.find((i: any) => i.alert_id === active);
    const value = { workspace, params: route.params, active, revision, nav, refresh, registerFlush, inspect: REC };
    const displayRecord = record ? { ...record.data, ...record.kind === 'email' ? { currentDeliveryState: workspace.actions.some((a: any) => a.action === 'Quarantine Email' && a.target === record.alert_id) ? 'Quarantined' : 'Delivered' } : {} } : {};
    return <LabContext.Provider value={value}><SidebarProvider style={{ '--sidebar-width': '232px' } as React.CSSProperties}><Navigation view={route.view} nav={nav} workspace={workspace}/><SidebarInset><header className="topbar"><SidebarTrigger /><div className="global-search"><div className="relative"><Search className="absolute top-2.5 left-3 size-4 text-[#688099]"/><Input aria-label="Global search" className="pl-9 bg-[#0c141f]" placeholder="Search alerts, users, endpoints, indicators…" value={search} onChange={e => Q(e.target.value)} onKeyDown={e => { if (e.key === 'Escape')
        Q(''); if (e.key === 'Enter' && search)
        nav('siem', { q: search }); }}/></div>{query && <div className="search-results">{results.map((r: any) => <button key={r.view + r.id} onClick={() => nav(r.view, { id: r.id })}><span>{r.title}</span><small className="block muted text-[10px] mt-1">{r.sub}</small></button>)}<button onClick={() => nav('ioc', { q: search })}>Look up “{search}” as an indicator →</button><button onClick={() => nav('siem', { q: search })}>Search all event records →</button></div>}</div><Button size="icon" variant="ghost" aria-label="Refresh workspace" onClick={() => refresh().catch(e => toast.error(e.message))}><RefreshCw size={16}/></Button><span className="analyst-label muted text-xs">{workspace.settings.analyst}</span><div className="avatar">{workspace.settings.analyst.split(' ').map((s: string) => s[0]).slice(0, 2).join('')}</div></header><div className="workspace"><div className="flex justify-between items-center mb-5"><span className="text-[10px] tracking-[1px] text-[#6d849e]">WORKSPACE / {groups.flatMap(g => g.items).find(i => i[0] === route.view)?.[1] as string || 'INVESTIGATION'}</span><Button size="sm" variant="outline" onClick={() => J(true)}><Plus size={14}/> Inject scenario</Button></div>{current && route.view !== 'alert' && <div className="contextbar"><span>Investigating <strong>{current.id}</strong> · {current.name}</span><Button size="sm" variant="ghost" onClick={() => nav('alert', { id: current.id })}>Return to alert →</Button></div>}<Route key={route.view + JSON.stringify(route.params)} view={route.view}/></div></SidebarInset></SidebarProvider><Toaster position="bottom-right" theme="dark" richColors/>
    <Sheet open={!!record} onOpenChange={v => { if (!v)
        REC(null); }}><SheetContent className="record-sheet"><SheetHeader><SheetTitle>{record?.message || 'Evidence inspector'}</SheetTitle><SheetDescription>{record?.id} · {record?.source}</SheetDescription></SheetHeader>{record && <><div className="toolbar mt-5"><Badge>{record.kind}</Badge><When value={record.timestamp}/><Badge>{record.event_id || 'Normalized'}</Badge></div><div className="toolbar"><Button disabled={!active || !!inv?.submitted_at || busy || !current || (!!route.params.attempt && Number(route.params.attempt) !== (inv?.attempt || 1))} onClick={async () => { B(true); try {
        await flush.current?.();
        const r = await mutate({ op:'bookmark',id:active,eventId:record.id,attempt:inv?.attempt||1,selected:!inv?.bookmarks.includes(record.id) });
        await refresh();
        toast.success(r.investigation.bookmarks.includes(record.id) ? 'Evidence bookmarked' : 'Bookmark removed');
    }
    catch (e: any) {
        toast.error(e.message);
    }
    finally {
        B(false);
    } }}><Bookmark size={15}/>{inv?.bookmarks.includes(record.id) ? 'Remove bookmark' : 'Bookmark evidence'}</Button><Button variant="outline" onClick={() => copy(JSON.stringify(record, null, 2))}>Copy raw JSON</Button></div>{!active && <p className="note">Open an alert first to preserve evidence in an investigation.</p>}<div className="chip-list mb-5"><Pivot view="host" id={record.host}/><Pivot view="user" id={record.user}/>{[record.source_ip, record.destination_ip, record.domain, record.hash].filter((x: any, i: number, a: any[]) => x && a.indexOf(x) === i).map(x => <Pivot key={x} view="ioc" id={x}/>)}</div><KeyValues data={displayRecord}/><details className="mt-5"><summary className="link">Full raw event JSON</summary><pre className="raw">{JSON.stringify(record, null, 2)}</pre></details></>}</SheetContent></Sheet>
    <Dialog open={inject} onOpenChange={J}><DialogContent className="max-w-[680px]!"><DialogHeader><DialogTitle>Inject a correlated scenario</DialogTitle><DialogDescription>Generate a new detection with linked identity, endpoint, network and contextual evidence. The verdict is hidden until you submit an assessment.</DialogDescription></DialogHeader><div className="dialog-body space-y-4"><Pick label="Detection category" value={options.category} onChange={v => O({ ...options, category: v, host: '' })} options={workspace.rules.map((r: any) => ({ value: r.id, label: r.name }))}/><div className="form-grid"><Pick label="Scenario severity" value={options.severity} onChange={v => O({ ...options, severity: v })} options={['Critical', 'High', 'Medium', 'Low']}/><Pick label="Scenario difficulty" value={options.difficulty} onChange={v => O({ ...options, difficulty: v })} options={['Beginner', 'Intermediate', 'Advanced']}/><Pick label="Scenario user" value={options.user || ''} onChange={v => O({ ...options, user: v })} options={[{ value: '', label: 'Select automatically' }, ...workspace.users.map((u: any) => ({ value: u.id, label: u.id + ' · ' + u.fullName }))]}/><Pick label="Scenario endpoint" value={options.host || ''} onChange={v => O({ ...options, host: v })} options={[{ value: '', label: 'Select automatically' }, ...workspace.hosts.filter((h:any)=>/sudo/i.test(workspace.rules.find((r:any)=>r.id===options.category)?.name||'')===h.os.startsWith('Ubuntu')).map((h:any)=>h.id)]}/><label className="field"><span>Seed</span><Input aria-label="Scenario seed" type="number" value={options.seed} onChange={e => O({ ...options, seed: e.target.value })}/></label><label className="field"><span>IOC override (optional)</span><Input aria-label="Scenario indicator" value={options.ioc || ''} placeholder="203.0.113.20 or example.test" onChange={e => O({ ...options, ioc: e.target.value })}/></label><label className="field"><span>Detection time (UTC, optional)</span><Input aria-label="Scenario time" type="datetime-local" value={options.localTime || ''} onChange={e => O({ ...options, localTime: e.target.value, timestamp: e.target.value ? new Date(e.target.value + 'Z').toISOString() : '' })}/></label></div><Button disabled={busy} onClick={async () => { B(true); try {
        await flush.current?.();
        const r = await mutate({ op: 'inject', options });
        await refresh();
        J(false);
        nav('alert', { id: r.alert.id });
        toast.success('Scenario and evidence generated');
    }
    catch (e: any) {
        toast.error(e.message);
    }
    finally {
        B(false);
    } }}>{busy ? 'Generating…' : 'Generate scenario'}</Button></div></DialogContent></Dialog></LabContext.Provider>;
}
