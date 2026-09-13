import { database, all, one, run } from '@/db';
import { users, hosts } from './entities';
import { rules } from './catalog';
import { generateScenario, incidentMetadata, type Injection } from './scenario-engine';
import { SEED_PREFIX } from './scenario-quality';
import { emptyWorksheet, type Investigation, type Scenario } from './types';
export const decode = (row: any) => row ? JSON.parse(row.data) : null;
async function insert(table: string, cols: string[], rows: any[][], update = false) { const size = Math.floor(96 / cols.length), stmts = []; for (let i = 0; i < rows.length; i += size) {
    const r = rows.slice(i, i + size);
    stmts.push(database().prepare(`INSERT ${update ? '' : 'OR IGNORE'} INTO ${table} (${cols.join(',')}) VALUES ${r.map(() => `(${cols.map(() => '?').join(',')})`).join(',')}${update ? ' ON CONFLICT(' + cols[0] + ') DO UPDATE SET ' + cols.slice(1).map(c => c + '=excluded.' + c).join(',') : ''}`).bind(...r.flat()));
} for (let i = 0; i < stmts.length; i += 60)
    await database().batch(stmts.slice(i, i + 60)); }
export async function persist(scenarios: Scenario[]) { await insert('alerts', ['id', 'incident_id', 'time', 'severity', 'family', 'user', 'host', 'source_ip', 'domain', 'rule_id', 'data'], scenarios.map(({ alert: a }) => [a.id, a.incident_id, a.time, a.severity, a.family, a.user, a.host, a.source_ip, a.domain, a.rule_id, JSON.stringify(a)])); await insert('events', ['id', 'alert_id', 'incident_id', 'timestamp', 'kind', 'event_id', 'user', 'host', 'source_ip', 'domain', 'hash', 'process_name', 'data'], scenarios.flatMap(s => s.events.map(e => [e.id, e.alert_id, e.incident_id, e.timestamp, e.kind, e.event_id, e.user, e.host, e.source_ip, e.domain, e.hash, e.process_name, JSON.stringify(e)]))); await insert('iocs', ['value', 'type', 'data'], scenarios.flatMap(s => s.iocs.map(i => [i.value, i.type, JSON.stringify(i)])), true); await insert('scenario_truth', ['alert_id', 'data'], scenarios.map(s => [s.alert.id, JSON.stringify(s.truth)])); }
export async function seed(batch: number) { if (!Number.isInteger(batch) || batch < 0 || batch > 23)
    throw Error('Invalid seed batch'); if (await one('SELECT id FROM seed_batches WHERE id=?', [SEED_PREFIX + batch]))
    return; if (batch === 0) {
    await insert('users', ['id', 'data'], users.map(u => [u.id, JSON.stringify(u)]));
    await insert('hosts', ['id', 'user', 'ip', 'data'], hosts.map(h => [h.id, h.user, h.ip, JSON.stringify(h)]), true);
    await insert('detection_rules', ['id', 'data'], rules.map(r => [r.id, JSON.stringify(r)]));
    await insert('incidents', ['id', 'name', 'data'], Array.from({ length: 24 }, (_, i) => incidentMetadata(i * 5 + 1)).map(x => [x.id, x.name, JSON.stringify(x)]));
} await persist(Array.from({ length: 25 }, (_, i) => generateScenario(batch * 25 + i + 1))); await run('INSERT OR IGNORE INTO seed_batches (id,time) VALUES (?,?)', [SEED_PREFIX + batch, new Date().toISOString()]); }
export async function inject(over: Injection) {
    // Stable seed controls evidence; a separate identifier permits repeated exercises.
    const seed = Math.abs(Math.trunc(over.seed ?? 83491)) % 1000000;
    const s = generateScenario(10000 + seed, { ...over, seed });
    const original = s.alert.id, id = 'ALT-CUSTOM-' + crypto.randomUUID().slice(0, 12).toUpperCase();
    s.alert.id = id; delete s.alert.supersedes; delete s.alert.priorExerciseIds;
    for (const e of s.events) {
        e.alert_id = id;
        e.id = e.id.replace(original, id);
    }
    s.truth.requiredEvidence = s.truth.requiredEvidence.map(e => e.replace(original, id));
    for (const f of s.truth.findings || []) { f.eventId = f.eventId.replace(original, id); f.observation = f.observation.replaceAll(original, id); }
    await persist([s]);
    return s.alert;
}
export class Conflict extends Error { status = 409; }
async function bookmarkIds(owner:string,id:string,attempt:number){return (await all<{event_id:string}>('SELECT event_id FROM investigation_bookmarks WHERE owner=? AND alert_id=? AND attempt=? ORDER BY created_at,event_id',[owner,id,attempt])).map(x=>x.event_id);}
async function upgradeBookmarkStore(owner:string,id:string,i:Investigation){
    if((i.bookmarkStoreVersion||0)>=1)return i;
    const now=new Date().toISOString(),existing=i.bookmarks||[];
    if(existing.length)await insert('investigation_bookmarks',['owner','alert_id','attempt','event_id','created_at'],existing.map((eventId,n)=>[owner,id,i.attempt||1,eventId,new Date(Date.parse(now)+n).toISOString()]));
    await run("UPDATE investigations SET data=json_set(data,'$.bookmarkStoreVersion',1) WHERE owner=? AND alert_id=?",[owner,id]);
    return {...i,bookmarkStoreVersion:1};
}
export async function hydrateInvestigations(owner:string,list:Investigation[]){
    if(!list.length)return list;
    const rows=await all<any>('SELECT alert_id,attempt,event_id FROM investigation_bookmarks WHERE owner=? ORDER BY created_at,event_id',[owner]),by=new Map<string,string[]>();
    for(const r of rows){const k=r.alert_id+':'+r.attempt,a=by.get(k)||[];a.push(r.event_id);by.set(k,a);}
    return list.map(i=>(i.bookmarkStoreVersion||0)>=1?{...i,bookmarks:by.get(i.alert_id+':'+(i.attempt||1))||[]}:i);
}
export async function getInvestigation(owner: string, id: string): Promise<Investigation> {
    const old = decode(await one('SELECT data FROM investigations WHERE owner=? AND alert_id=?', [owner,id]));
    if(old){let i:Investigation={attempt:1,worksheetVersion:0,revision:0,hintsUsed:0,bookmarkStoreVersion:0,...old};if((i.bookmarkStoreVersion||0)>=1)i={...i,bookmarks:await bookmarkIds(owner,id,i.attempt||1)};return i;}
    const a:any=await one('SELECT severity FROM alerts WHERE id=?',[id]);
    return {alert_id:id,status:'New',started_at:'',updated_at:'',submitted_at:null,worksheet:{...emptyWorksheet,severity:a?.severity||'Medium'},reviewed:[],bookmarks:[],feedback:null,attempt:1,worksheetVersion:0,revision:0,hintsUsed:0,bookmarkStoreVersion:1};
}
export async function ensureInvestigation(owner:string,id:string){let i=await getInvestigation(owner,id);await run('INSERT OR IGNORE INTO investigations(owner,alert_id,status,started_at,updated_at,submitted_at,data) VALUES(?,?,?,?,?,?,?)',[owner,id,i.status,i.started_at,i.updated_at,i.submitted_at,JSON.stringify(i)]);i=await getInvestigation(owner,id);if((i.bookmarkStoreVersion||0)<1)i=await upgradeBookmarkStore(owner,id,i);return i;}
export function checkAttempt(b:any,i:Investigation){if(Number(b.attempt)!==i.attempt)throw new Conflict('This attempt changed in another tab. Reload to open the current attempt; your draft is preserved.');}
export async function mark(owner:string,id:string,area:string){
    if(!id||!await one('SELECT id FROM alerts WHERE id=?',[id]))return;
    await ensureInvestigation(owner,id);const now=new Date().toISOString();
    await run(`UPDATE investigations SET status=CASE WHEN status='New' THEN 'Investigating' ELSE status END,started_at=CASE WHEN started_at='' THEN ? ELSE started_at END,updated_at=?,data=json_set(data,'$.reviewed',json((SELECT json_group_array(value) FROM (SELECT value FROM json_each(investigations.data,'$.reviewed') UNION SELECT ?))),'$.started_at',CASE WHEN started_at='' THEN ? ELSE started_at END,'$.updated_at',?,'$.status',CASE WHEN status='New' THEN 'Investigating' ELSE status END,'$.revision',COALESCE(json_extract(data,'$.revision'),0)+1) WHERE owner=? AND alert_id=? AND submitted_at IS NULL AND NOT EXISTS(SELECT 1 FROM json_each(data,'$.reviewed') WHERE value=?)`,[now,now,area,now,now,owner,id,area]);
}
export async function bookmark(owner:string,id:string,eventId:string,selected:boolean,attempt:number){
    await ensureInvestigation(owner,id);const now=new Date().toISOString();
    const touch=database().prepare(`UPDATE investigations SET status=CASE WHEN status='New' THEN 'Investigating' ELSE status END,started_at=CASE WHEN started_at='' THEN ? ELSE started_at END,updated_at=?,data=json_set(data,'$.started_at',CASE WHEN started_at='' THEN ? ELSE started_at END,'$.updated_at',?,'$.status',CASE WHEN status='New' THEN 'Investigating' ELSE status END,'$.bookmarkStoreVersion',1,'$.revision',COALESCE(json_extract(data,'$.revision'),0)+1) WHERE owner=? AND alert_id=? AND submitted_at IS NULL AND COALESCE(json_extract(data,'$.attempt'),1)=?`).bind(now,now,now,now,owner,id,attempt);
    const change=selected
        ?database().prepare(`INSERT OR IGNORE INTO investigation_bookmarks(owner,alert_id,attempt,event_id,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM investigations WHERE owner=? AND alert_id=? AND submitted_at IS NULL AND COALESCE(json_extract(data,'$.attempt'),1)=?)`).bind(owner,id,attempt,eventId,now,owner,id,attempt)
        :database().prepare(`DELETE FROM investigation_bookmarks WHERE owner=? AND alert_id=? AND attempt=? AND event_id=? AND EXISTS(SELECT 1 FROM investigations WHERE owner=? AND alert_id=? AND submitted_at IS NULL AND COALESCE(json_extract(data,'$.attempt'),1)=?)`).bind(owner,id,attempt,eventId,owner,id,attempt);
    const result=await database().batch([touch,change]),changed=(result[0] as any).meta?.changes??(result[0] as any).changes;
    if(!changed)throw new Conflict('This attempt was submitted or restarted. Reload before changing evidence.');
    return getInvestigation(owner,id);
}
export async function saveWorksheet(owner:string,i:Investigation,version:number,submitting=false){
    await ensureInvestigation(owner,i.alert_id);
    const row=await one(`UPDATE investigations SET status=?,started_at=?,updated_at=?,submitted_at=?,data=json_set(data,'$.worksheet',json(?),'$.status',?,'$.started_at',?,'$.updated_at',?,'$.submitted_at',?,'$.feedback',json(?),'$.worksheetVersion',?,'$.revision',COALESCE(json_extract(data,'$.revision'),0)+1,'$.bookmarkStoreVersion',1) WHERE owner=? AND alert_id=? AND submitted_at IS NULL AND COALESCE(json_extract(data,'$.attempt'),1)=? AND COALESCE(json_extract(data,'$.worksheetVersion'),0)=?${submitting?" AND COALESCE(json_extract(data,'$.revision'),0)=?":''} RETURNING data`,[i.status,i.started_at,i.updated_at,i.submitted_at,JSON.stringify(i.worksheet),i.status,i.started_at,i.updated_at,i.submitted_at,JSON.stringify(i.feedback),version+1,owner,i.alert_id,i.attempt!,version,...submitting?[i.revision!]:[]]);
    if(!row)throw new Conflict('Another tab saved or changed this investigation. Your local draft is preserved; reload and compare before saving.');return getInvestigation(owner,i.alert_id);
}
export async function retry(owner:string,i:Investigation,snapshot:any){
    if(!i.submitted_at)throw Error('Submit this assessment before starting another attempt.');
    const next:Investigation={...i,attempt:i.attempt!+1,worksheetVersion:0,revision:0,hintsUsed:0,bookmarkStoreVersion:1,status:'New',started_at:'',updated_at:new Date().toISOString(),submitted_at:null,worksheet:{...emptyWorksheet,severity:snapshot.alert.severity},reviewed:[],bookmarks:[],feedback:null},args=[owner,i.alert_id,i.attempt!];
    const result=await database().batch([
        database().prepare(`INSERT INTO attempts(owner,alert_id,attempt,data) SELECT owner,alert_id,?,? FROM investigations WHERE owner=? AND alert_id=? AND submitted_at IS NOT NULL AND COALESCE(json_extract(data,'$.attempt'),1)=? ON CONFLICT(owner,alert_id,attempt) DO NOTHING`).bind(i.attempt!,JSON.stringify(snapshot),...args),
        database().prepare(`UPDATE investigations SET status='New',started_at='',updated_at=?,submitted_at=NULL,data=? WHERE owner=? AND alert_id=? AND submitted_at IS NOT NULL AND COALESCE(json_extract(data,'$.attempt'),1)=?`).bind(next.updated_at,JSON.stringify(next),...args)
    ]);if(!((result[1]as any).meta?.changes??(result[1]as any).changes))throw new Conflict('This attempt has already restarted. Reload to continue.');return next;
}
