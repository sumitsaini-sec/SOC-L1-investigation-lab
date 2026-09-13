import { normalizeIOC } from './scenario-quality';
const columns: Record<string, string> = { alert_id: 'e.alert_id', incident_id: 'e.incident_id', timestamp: 'e.timestamp', kind: 'e.kind', event_id: 'e.event_id', eventid: 'e.event_id', user: 'e.user', username: 'e.user', host: 'e.host', hostname: 'e.host', source_ip: 'e.source_ip', destination_ip: "json_extract(e.data,'$.destination_ip')", domain: 'e.domain', hash: 'e.hash', process_name: 'e.process_name', process: 'e.process_name', source: "json_extract(e.data,'$.source')", severity: "json_extract(e.data,'$.severity')", outcome: "json_extract(e.data,'$.data.outcome')" };
export function parseQuery(input: string) { let q = input.trim(), order = 'DESC', limit = 50; const params: unknown[] = [], clauses: string[] = []; q = q.replace(/^(?:events|securityevent|sysmon|logs)\s*\|\s*where\s+/i, '').replace(/^\|?\s*where\s+/i, ''); q = q.replace(/\|\s*(?:sort|order)\s+by\s+timestamp\s*(asc|desc)?/gi, (_m, d) => { order = (d ?? 'DESC').toUpperCase(); return ''; }); q = q.replace(/\|\s*(?:take|limit)\s+(\d+)/gi, (_m, n) => { limit = Math.min(100, Math.max(1, Number(n))); return ''; }); if (q.includes('|'))
    throw new Error('Supported pipes: | where, | sort by timestamp asc/desc, | take 1–100.'); if (q) {
    if (!/\b\w+\s*(?:==|!=|=|contains\b)/i.test(q)) {
        clauses.push('e.data LIKE ?');
        params.push('%' + q + '%');
    }
    else {
        const re = /\s*(\w+)\s*(==|!=|=|contains)\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))\s*(?:(and|or)\s+)?/giy;
        let at = 0, next = '';
        while (at < q.trim().length) {
            re.lastIndex = at;
            const m = re.exec(q);
            if (!m)
                throw new Error('Use field="value" joined by AND / OR. Quote values containing spaces.');
            const col = columns[m[1].toLowerCase()];
            if (!col)
                throw new Error('Unknown query field: ' + m[1]);
            const field=m[1].toLowerCase(); let value = m[3] ?? m[4] ?? m[5];
            if(field==='domain')value=normalizeIOC(value);
            if(field==='hash')value=value.toLowerCase();
            const nocase = ['domain','hash','process_name','process'].includes(field) ? ' COLLATE NOCASE' : '';
            clauses.push(next + col + nocase + (m[2].toLowerCase() === 'contains' ? ' LIKE ?' : m[2] === '!=' ? ' != ?' : ' = ?'));
            params.push(m[2].toLowerCase() === 'contains' ? '%' + value + '%' : value);
            next = m[6] ? ' ' + m[6].toUpperCase() + ' ' : ' AND ';
            at = re.lastIndex;
            if (at < q.trim().length && !m[6])
                throw new Error('Join conditions with AND or OR.');
            if (at >= q.trim().length && m[6])
                throw new Error('Add a condition after ' + m[6]);
        }
    }
} return { where: clauses.length ? '(' + clauses.join('') + ')' : '1=1', params, order, limit }; }
