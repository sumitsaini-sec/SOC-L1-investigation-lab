'use client';
import React, { useState } from 'react';
import { Textarea } from '@/components/ui/textarea';
import { useLab, Heading, Panel, Button, Pick, Input, copy, toast } from './common';
const toolsList = [['IP reputation', 'Compare simulated provider observations.', 'ioc'], ['WHOIS lookup', 'Registration and ownership context.', 'ioc'], ['DNS lookup', 'Observed DNS records and related addresses.', 'ioc'], ['Domain age', 'Inspect registration age and lookalike signals.', 'ioc'], ['URL analysis', 'Redirects, forms and observed destinations.', 'ioc'], ['Hash analysis', 'File metadata, aliases and provider detections.', 'ioc'], ['Base64 decoder', 'Decode UTF-8 or UTF-16LE text.', 'base64'], ['URL decoder', 'Decode percent-encoded text.', 'url'], ['Email header parser', 'Inspect routing and authentication fields.', 'headers'], ['JWT decoder', 'Inspect claims without verifying the signature.', 'jwt'], ['Timestamp converter', 'Convert Unix seconds, milliseconds or ISO dates.', 'time'], ['Regex tester', 'Find matches with a bounded runtime.', 'regex']];
export function ToolsPage() { const { nav } = useLab(), [selected, S] = useState('Base64 decoder'), [input, I] = useState(''), [pattern, P] = useState(''), [encoding, E] = useState('UTF-8'), [result, R] = useState(''), [busy, B] = useState(false); const tool = toolsList.find(t => t[0] === selected)!; async function run() { B(true); try {
    if (tool[2] === 'ioc') {
        nav('ioc', { q: input.trim() });
        return;
    }
    let out: any = '';
    if (tool[2] === 'base64') {
        const bytes = Uint8Array.from(atob(input.replaceAll(/\s/g, '')), c => c.charCodeAt(0));
        out = new TextDecoder(encoding === 'UTF-16LE' ? 'utf-16le' : 'utf-8', { fatal: true }).decode(bytes);
    }
    if (tool[2] === 'url')
        out = decodeURIComponent(input.replaceAll('+', ' '));
    if (tool[2] === 'time') {
        const n = Number(input), d = new Date(/^\d+$/.test(input.trim()) ? n * (input.trim().length <= 10 ? 1000 : 1) : input);
        if (!Number.isFinite(d.getTime()))
            throw Error('Enter valid Unix time or an ISO timestamp.');
        out = { UTC: d.toISOString(), UnixSeconds: Math.floor(d.getTime() / 1000), UnixMilliseconds: d.getTime(), local: d.toLocaleString() };
    }
    if (tool[2] === 'headers') {
        out = {};
        input.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/).forEach(l => { const pos = l.indexOf(':'); if (pos > 0) {
            const k = l.slice(0, pos).trim();
            out[k] = out[k] ? [...Array.isArray(out[k]) ? out[k] : [out[k]], l.slice(pos + 1).trim()] : l.slice(pos + 1).trim();
        } });
    }
    if (tool[2] === 'jwt') {
        const parts = input.trim().split('.');
        if (parts.length !== 3)
            throw Error('A JWT must have three dot-separated parts.');
        const decode = (s: string) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))));
        out = { header: decode(parts[0]), payload: decode(parts[1]), signature: 'NOT VERIFIED — decoded data can be modified by anyone.' };
    }
    if (tool[2] === 'regex') {
        if (input.length > 20000 || pattern.length > 500)
            throw Error('Use at most 20,000 input characters and a 500-character pattern.');
        out = await new Promise((resolve, reject) => { const url = URL.createObjectURL(new Blob(['onmessage=e=>{try{const re=new RegExp(e.data.pattern,"g");const matches=[];let m;while((m=re.exec(e.data.input))&&matches.length<200){matches.push({match:m[0],index:m.index,groups:m.slice(1)});if(m[0]==="")re.lastIndex++;}postMessage({matches});}catch(e){postMessage({error:e.message});}}'], { type: 'application/javascript' })); const worker = new Worker(url), end = () => { worker.terminate(); URL.revokeObjectURL(url); }, timer = setTimeout(() => { end(); reject(Error('Pattern exceeded 500 ms. Simplify it and retry.')); }, 500); worker.onmessage = e => { clearTimeout(timer); end(); e.data.error ? reject(Error(e.data.error)) : resolve(e.data.matches); }; worker.onerror = () => { clearTimeout(timer); end(); reject(Error('Regex worker failed.')); }; worker.postMessage({ pattern, input }); });
    }
    R(typeof out === 'string' ? out : JSON.stringify(out, null, 2));
}
catch (e: any) {
    R('Error: ' + e.message);
}
finally {
    B(false);
} } return <><Heading title="Analyst utility bench" description="Inspect suspicious artifacts without executing their contents."/><div className="grid3 mb-6">{toolsList.map(t => <button key={t[0]} className="toolcard" onClick={() => { S(t[0]); R(''); }} style={selected === t[0] ? { borderColor: '#6bdcc0' } : {}}><h3>{t[0]}</h3><p>{t[1]}</p></button>)}</div><Panel title={selected}><div className="space-y-4">{tool[2] === 'base64' && <Pick label="Text encoding" value={encoding} onChange={E} options={['UTF-8', 'UTF-16LE']}/>}<label className="field"><span>{tool[2] === 'ioc' ? 'Indicator' : 'Input'}</span><Textarea aria-label="Tool input" className="font-mono" value={input} onChange={e => I(e.target.value)} maxLength={20000}/></label>{tool[2] === 'regex' && <label className="field"><span>Regular expression (global, without slashes)</span><Input aria-label="Regex pattern" value={pattern} onChange={e => P(e.target.value)} maxLength={500}/></label>}<Button disabled={busy || !input} onClick={run}>{tool[2] === 'ioc' ? 'Look up indicator' : 'Run tool'}</Button>{result && <><pre className="raw">{result}</pre><Button variant="outline" onClick={() => copy(result)}>Copy result</Button></>}</div></Panel></>; }
